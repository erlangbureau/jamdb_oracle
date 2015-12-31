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
    req_capabilities = [],
    resp_capabilities = [],
    env = []
}).

-opaque state() :: #oraclient{}.
-type error_type() :: socket | remote | local.
-type empty_result() :: {ok, state()} | {error, error_type(), binary(), state()}.
-type affected_rows() :: {affected_rows, non_neg_integer()}.
-type columns() :: list().  %% TODO
-type metainfo() :: list(). %%TODO
-type rows() :: list().  %% TODO
-type result_set() :: {result_set, columns(), metainfo(), rows()}.
-type return_status() :: non_neg_integer().
-type out_params() :: list().  %% TODO
-type procedure_result() :: 
        {proc_result, return_status(), out_params()}.
-type result() :: 
        affected_rows() | 
        result_set() | 
        procedure_result().
-type query_result() :: {ok, [result()], state()}.
-type env() :: 
        {host, string()} |
        {port, string()} |
        {user, string()} |
        {password, string()} |
        {schema, string()} |
        {app_name, string()} |
        {lib_name, string()} |
        {language, string()} |
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
                    system_query(State2, ?ENCODER:encode_record(func, ?TTI_COMON), Timeout);
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
disconnect(State = #oraclient{conn_state=connected, socket=Socket, env=Env}, Timeout) ->
    Data = ?ENCODER:encode_record(func, ?TTI_LOGOFF),
    try send(State, ?TNS_DATA, Data) of
        {ok, State2} -> 
            _ = handle_empty_resp(State2, Timeout);
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
sql_query(State = #oraclient{conn_state = connected}, Query, Timeout) ->
    {ok, State2} = send_query_req(State, Query),    %% TODO handle error
    handle_resp([], State2, Timeout).

%% internal
login(State, Timeout) ->
    {ok, State2} = send_req(login, State),
    handle_login_resp(State2, Timeout).

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
	    case ?DECODER:decode_token(tti, PacketBody) of 
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
            	    State2 = State#oraclient{conn_state = connected, server = Ver},
		    {ok, State2}
	    end;
        {ok, ?TNS_REFUSE, <<_ResultData:32,PacketBody/bits>>} ->
            PacketBody;
        {ok, _Type, _PacketBody} ->
	    login_failed;
        {error, _Type, ErrorCode} ->
	    ErrorCode
    end.


send_req(auth, #oraclient{env=Env} = State, Sess, Salt) ->
    {Data,KeyConn} = ?ENCODER:encode_record(auth, Env, Sess, Salt),
    State2 = State#oraclient{conn_key = KeyConn},
    send(State2, ?TNS_DATA, Data).

send_req(login, #oraclient{env=Env} = State) ->
    Data = ?ENCODER:encode_record(login, Env),
    send(State, ?TNS_CONNECT, Data);
send_req(Request, #oraclient{env=Env} = State) when is_atom(Request) ->
    Data = ?ENCODER:encode_record(Request, Env),
    send(State, ?TNS_DATA, Data);
send_req(Request, State) when is_integer(Request) ->
    Data = ?ENCODER:encode_record(fetch, Request),
    send(State, ?TNS_DATA, Data).

system_query(State, Data, Timeout) ->
    {ok, State2} = send(State, ?TNS_DATA, Data),  %% TODO handle error
    handle_empty_resp(State2, Timeout).

send_query_req(State, {Query, Bind}) ->
    Data = ?ENCODER:encode_query(Query, Bind),
    send(State, ?TNS_DATA, Data);
send_query_req(State, Query) ->
    Data = ?ENCODER:encode_query(Query,[]),
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
        {error, _Type, _ErrorCode} = Error ->
            _ = disconnect(State),
            State2 = State#oraclient{conn_state = disconnected},
            erlang:append_element(Error, State2)
    end.


handle_resp(Data, TokensBufer, State, Timeout) ->
    case ?DECODER:decode_token(Data, TokensBufer) of
	{Status, Cursor, RowFormat, Rows} ->
	    case Status of
		done ->
		    FieldNames = [get_field_name(Fmt) || Fmt <- RowFormat],
	    	    {ok, [{FieldNames, [], Rows}], State};
		more ->
		    {ok, State2} = send_req(Cursor, State),
        	    handle_resp({Cursor, RowFormat, Rows}, State2, Timeout);
		crud ->
	    	    {ok, [{[], [], [Rows]}], State};
		_ ->
    		    {error, remote, Status}
	    end;
	{ok, Message} ->
	    {ok, Message, State};
        {error, Message} ->
    	    {error, remote, Message}
    end.


%%lager:log(info,self(),"~p",[Data]),

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
            State2 = State#oraclient{conn_state = disconnected},
            {error, socket, Reason, State2}
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
