-module(jamdb_oracle_conn).

%% API
-export([connect/1, connect/2]).
-export([reconnect/1]).
-export([disconnect/1, disconnect/2]).
-export([sql_query/2, sql_query/3]).

-include("TNS.hrl").
-include("jamdb_oracle.hrl").
-include("jamdb_oracle_defaults.hrl").

-define(ENCODER, jamdb_oracle_tns_encoder).
-define(DECODER, jamdb_oracle_tns_decoder).

-record(oraclient, {
    socket = undefined,
    conn_state = disconnected :: disconnected | connected | auth_negotiate,
    packet_size :: non_neg_integer(),
    conn_key,
    server,
    cursors = [],
    params = [],
    env = []
}).

-opaque state() :: #oraclient{}.
-type error_type() :: socket | remote | local.
-type columns() :: list().  %% TODO
-type metainfo() :: list(). %%TODO
-type rows() :: list().  %% TODO
-type return_status() :: non_neg_integer().
-type out_params() :: list().  %% TODO
-type empty_result() :: {ok, state()} | {error, error_type(), binary(), state()}.
-type affected_rows() :: {affected_rows, non_neg_integer()}.
-type result_set() :: {result_set, columns(), metainfo(), rows()}.
-type procedure_result() :: {proc_result, return_status(), out_params()}.
-type result() :: affected_rows() | result_set() | procedure_result().
-type query_result() :: {ok, [result()], state()}.
-type env() :: 
        {host, string()} |
        {port, string()} |
        {user, string()} |
        {password, string()} |
        {app_name, string()} |
        {packet_size, non_neg_integer()}.
-type options() :: [env()].

-export_type([state/0]).
-export_type([options/0]).

%% API
-spec connect([env()], timeout()) -> empty_result().
connect(Opts) ->
    connect(Opts, ?DEF_TIMEOUT).

-spec connect([env()]) -> empty_result().
connect(Opts, Timeout) ->
    Host        = proplists:get_value(host, Opts, ?DEF_HOST), 
    Port        = proplists:get_value(port, Opts, ?DEF_PORT),
    PacketSize  = proplists:get_value(packet_size, Opts, ?DEF_PACKET_SIZE),
    SockOpts = [binary, {active, false}, {packet, raw}, 
            {nodelay, true}, {keepalive, true}],
    case gen_tcp:connect(Host, Port, SockOpts, Timeout) of
        {ok, Socket} ->
            State = #oraclient{
                socket        = Socket, 
                packet_size   = PacketSize,
                env           = Opts
            },
            case login(State, Timeout) of
                {ok, State2 = #oraclient{conn_state = connected}} ->
                    send_req(func, State2, ?ENCODER:encode_record(func, ?TTI_COMON), Timeout);
                Error ->
                    Error
            end;
        {error, Reason} ->
            {error, socket, Reason}
    end.

-spec disconnect(state()) -> {ok, [env()]}.
disconnect(State) ->
    disconnect(State, ?DEF_TIMEOUT).

-spec disconnect(state(), timeout()) -> {ok, [env()]}.
disconnect(#oraclient{conn_state=connected, socket=Socket, env=Env}, 0) ->
    ok = gen_tcp:close(Socket),
    {ok, Env};
disconnect(State = #oraclient{conn_state=connected, socket=Socket, cursors=Cursors, env=Env}, Timeout) ->
    Data = ?ENCODER:encode_record(close, Cursors),
    try send(State, ?TNS_DATA, Data) of
        {ok, State2} -> 
            _ = handle_empty_resp(State2, Timeout),
            _ = send(State2, ?TNS_DATA, <<64>>);
        {error, _Type, _Reason, _State2} ->
            ok
    after
        ok = gen_tcp:close(Socket)
    end,
    {ok, Env};
disconnect(#oraclient{env = Env}, _Timeout) ->
    {ok, Env}.

-spec reconnect(state()) -> {ok, state()}.
reconnect(State) ->
    {ok, InitOpts} = disconnect(State),
    connect(InitOpts).

-spec sql_query(state(), string()) -> query_result().
sql_query(State, Query) ->
    sql_query(State, Query, ?DEF_TIMEOUT).

-spec sql_query(state(), string(), timeout()) -> query_result().
sql_query(State = #oraclient{conn_state=connected, server=Ver}, Query, Timeout) ->
    {ok, State2 = #oraclient{params=RowFormat}} = send_req(query, State, Query),
    handle_resp({Ver, RowFormat}, State2, Timeout).

%% internal
login(State, Timeout) ->
    {ok, State2} = send_req(login, State),
    handle_login_resp(State2#oraclient{conn_state = auth_negotiate}, Timeout).

login(State, Data, Timeout) ->
    case ?DECODER:decode_token(tti, Data) of 
        {?TTI_SESS, Sess, Salt} ->
	    {ok, State2} = send_req(auth, State, Sess, Salt),
	    handle_login_resp(State2, Timeout);
	{?TTI_AUTH, Resp} ->
	    #oraclient{conn_key = KeyConn} = State,
	    case jamdb_oracle_crypt:validate(Resp,KeyConn) of
		ok ->
		    {ok, State2} = send_req(ver, State),
		    handle_login_resp(State2, Timeout);
    		{error, ErrorCode} ->
		    ErrorCode
	    end;
	{?TTI_VERSION, Ver} ->
	    {ok, State#oraclient{conn_state = connected, server = Ver}}
    end.

handle_login_resp(#oraclient{socket=Socket} = State, Timeout) ->
    case recv(Socket, Timeout) of
        {ok, ?TNS_RESEND, <<>>} ->
	    {ok, State2} = send_req(login, State),
	    handle_login_resp(State2, Timeout);
        {ok, ?TNS_ACCEPT, _} ->
	    {ok, State2} = send_req(pro, State),
	    handle_login_resp(State2, Timeout);
        {ok, ?TNS_DATA, <<?TTI_PRO,_PacketBody/bits>>} ->
	    {ok, State2} = send_req(dty, State),
	    handle_login_resp(State2, Timeout);
        {ok, ?TNS_DATA, <<?TTI_DTY,_PacketBody/bits>>} ->
	    {ok, State2} = send_req(sess, State),
	    handle_login_resp(State2, Timeout);
        {ok, ?TNS_DATA, <<?TTI_RPA,PacketBody/bits>>} ->
            login(State, PacketBody, Timeout);
        {ok, ?TNS_DATA, <<?TTI_WRN,ResultData/bits>>} ->
            case ?DECODER:decode_token(wrn, ResultData) of
                <<?TTI_RPA,PacketBody/bits>> -> 
                    login(State, PacketBody, Timeout);
                PacketBody -> 
                    PacketBody
            end;
        {ok, ?TNS_REFUSE, <<_ResultData:32,PacketBody/bits>>} ->
            PacketBody;
        {ok, _Type, _PacketBody} ->
            login_failed;
        {error, _Type, ErrorCode} ->
            ErrorCode
     end.

handle_error(socket, Reason, State) ->
    _ = disconnect(State, 0),
    {error, socket, Reason, State#oraclient{conn_state = disconnected}};
handle_error(Type, Reason, State) ->
    {error, Type, Reason, State}.

send_req(auth, #oraclient{env=Env} = State, Sess, Salt) ->
    {Data,KeyConn} = ?ENCODER:encode_record(auth, Env, Sess, Salt),
    send(State#oraclient{conn_key = KeyConn}, ?TNS_DATA, Data);
send_req(func, State, Data, Timeout) ->
    {ok, State2} = send(State, ?TNS_DATA, Data),
    handle_empty_resp(State2, Timeout).

send_req(login, #oraclient{env=Env} = State) ->
    Data = ?ENCODER:encode_record(login, Env),
    send(State, ?TNS_CONNECT, Data);
send_req(Request, #oraclient{env=Env} = State) ->
    Data = ?ENCODER:encode_record(Request, Env),
    send(State, ?TNS_DATA, Data).
    
send_req(fetch, State, Request) when is_integer(Request) ->
    Data = ?ENCODER:encode_record(fetch, Request),
    send(State, ?TNS_DATA, Data);
send_req(fetch, #oraclient{server=Ver} = State, Request) when is_tuple(Request) ->
    Data = ?ENCODER:encode_record(fetch, erlang:append_element(Request, Ver)),
    send(State, ?TNS_DATA, Data);
send_req(query, #oraclient{server=Ver} = State, {Query, Bind}) ->
    Data = ?ENCODER:encode_record(fetch, {0, Query, [get_param(data, B) || B <- Bind], Ver}),
    send(State#oraclient{params = [get_param(format, B) || B <- Bind]}, ?TNS_DATA, Data);
send_req(query, #oraclient{server=Ver} = State, Query) ->
    Data = ?ENCODER:encode_record(fetch, {0, Query, [], Ver}),
    send(State, ?TNS_DATA, Data). 

handle_empty_resp(State, Timeout) ->
    case handle_resp([], State, Timeout) of
        {ok, _, State2} ->
            {ok, State2};
        Other ->
            Other
    end.

handle_resp(TokensBufer, State = #oraclient{socket=Socket}, Timeout) ->
    case recv(Socket, Timeout) of
        {ok, ?TNS_DATA, BinaryData} ->
            handle_resp(BinaryData, TokensBufer, State, Timeout);
        {ok, ?TNS_MARKER, _BinaryData} ->
	    {ok, State2} = send(State, ?TNS_MARKER, <<1,0,2>>),
	    handle_resp([], State2, Timeout);
        {error, Type, Reason} ->
            handle_error(Type, Reason, State)
    end.


handle_resp(Data, TokensBufer, State, Timeout) ->
    case ?DECODER:decode_token(Data, TokensBufer) of
	{cursor, Cursor, RowFormat} ->
	    {ok, State2} = send_req(fetch, State, {Cursor, [], []}),
       	    handle_resp({Cursor, RowFormat, []}, State2, Timeout);
	{RetCode, RowNumber, Cursor, RowFormat, Rows} ->
            #oraclient{cursors = Cursors} = State,
	    case get_result(RetCode, RowNumber, RowFormat, Rows) of
		more ->
		    {ok, State2} = send_req(fetch, State, Cursor),
        	    handle_resp({Cursor, RowFormat, Rows}, State2, Timeout);
                Result ->                
                    erlang:append_element(Result, State#oraclient{cursors = get_cursors(Cursor, Cursors)})
	    end;
	{ok, Token} ->
	    {ok, Token, State};
        {error, Message} ->
    	    {error, remote, Message}
    end.

%%lager:log(info,self(),"~p",[Data]),

get_result(0, RowNumber, _RowFormat, []) ->
    {ok, [{affected_rows, RowNumber}]};
get_result(RetCode, _RowNumber, _RowFormat, []) ->
    {error, local, RetCode};
get_result(0, _RowNumber, [], Rows) ->
    {ok, [{proc_result, 0, Rows}]};
get_result(RetCode, _RowNumbers, RowFormat, Rows) ->
    case RetCode of
	1403 -> 
            FieldNames = [get_field_name(Fmt) || Fmt <- RowFormat],
            {ok, [{result_set, FieldNames, [], Rows}]};
%	3113 -> {error, local, RetCode};
%	600 -> {error, local, RetCode};
%	28 -> {error, local, RetCode};
	_ -> more
    end.

get_cursors(Cursor, Cursors) when Cursor > 0 ->
    [Cursor|Cursors];
get_cursors(Cursor, Cursors) when Cursor =:= 0 ->
    Cursors.

get_param(data, {_Param, Data}) ->
    Data;
get_param(data, Data) ->
    Data;    
get_param(format, {Param, Data}) ->
    get_param(Param, Data);
get_param(format, Data) ->
    get_param(in, Data);    
get_param(Param, Data) ->
    {<<>>, Type, Scale, Length, Charset} = 
    ?DECODER:decode_token(oac, ?ENCODER:encode_token(oac, Data)),
    #format{param=Param,
            data_type=Type,
            data_length=Length,
            scale=Scale,
            locale=Charset}.

get_field_name(#format{column_name = ColumnName}) ->
    ColumnName.

send(State, _PacketType, <<>>) ->
    {ok, State};
send(State, PacketType, Data) ->
    #oraclient{socket=Socket} = State,
    Packet = ?ENCODER:encode_packet(PacketType, Data),
    case gen_tcp:send(Socket, Packet) of
        ok ->
            send(State, PacketType, <<>>);
        {error, Reason} ->
            handle_error(socket, Reason, State)
    end.

recv(Socket, Timeout) ->
    recv(Socket, Timeout, <<>>, <<>>).

recv(Socket, Timeout, Buffer, ResultData) ->
    case ?DECODER:decode_packet(Buffer) of
        {ok, Type, PacketBody, _} ->
	    {ok, Type, PacketBody};
        {error, incomplete_packet} ->
            case gen_tcp:recv(Socket, 0, Timeout) of
                {ok, NetworkData} ->
                    NewBuffer = <<Buffer/bits, NetworkData/bits>>,
                    recv(Socket, Timeout, NewBuffer, ResultData);
                {error, Reason} ->
                    {error, socket, Reason}
            end
    end.
