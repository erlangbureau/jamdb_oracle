-module(jamdb_oracle_conn).

%% API
-export([connect/1, connect/2]).
-export([reconnect/1]).
-export([disconnect/1, disconnect/2]).
-export([sql_query/2, sql_query/3]).

-include("TNS.hrl").
-include("jamdb_oracle.hrl").
-include("jamdb_oracle_defaults.hrl").

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
-type procedure_result() :: {proc_result, return_status(), out_params() | metainfo()}.
-type result() :: affected_rows() | result_set() | procedure_result().
-type query_result() :: {ok, [result()], state()}.
-type env() ::
        {host, string()} |
        {port, non_neg_integer()} |
        {user, string()} |
        {password, string()} |
        {sid, string()} |
        {service_name, string()} |
        {app_name, string()}.
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
    SockOpts = [binary, {active, false}, {packet, raw}, %{recbuf, 65535},
            {nodelay, true}, {keepalive, true}],
    case gen_tcp:connect(Host, Port, SockOpts, Timeout) of
        {ok, Socket} ->
            State = #oraclient{socket=Socket, env=Opts, auto=?DEF_AUTOCOMMIT, fetch=?DEF_FETCH},
            {ok, State2} = send_req(login, State),
            handle_login_resp(State2#oraclient{conn_state=auth_negotiate}, Timeout);
        {error, Reason} ->
            {error, socket, Reason}
    end.

-spec disconnect(state()) -> {ok, [env()]}.
disconnect(State = #oraclient{auth=To}) ->
    exit(To, ok),
    disconnect(State, ?DEF_TIMEOUT).

-spec disconnect(state(), timeout()) -> {ok, [env()]}.
disconnect(#oraclient{conn_state=connected, socket=Socket, env=Env}, 0) ->
    ok = gen_tcp:close(Socket),
    {ok, Env};
disconnect(State = #oraclient{conn_state=connected, socket=Socket, env=Env}, Timeout) ->
    _ = send_req(close, State, Timeout),
    ok = gen_tcp:close(Socket),
    {ok, Env};
disconnect(#oraclient{env=Env}, _Timeout) ->
    {ok, Env}.

-spec reconnect(state()) -> {ok, state()}.
reconnect(State) ->
    {ok, InitOpts} = disconnect(State),
    connect(InitOpts).

-spec sql_query(state(), string() | tuple()) -> query_result().
sql_query(State, Query) ->
    sql_query(State, Query, ?DEF_TIMEOUT).

-spec sql_query(state(), string() | tuple(), timeout()) -> query_result().
sql_query(State, Query, Timeout) when is_list(Query) ->
    sql_query(State, {Query, []}, Timeout);
sql_query(State = #oraclient{conn_state=connected}, {Query, Bind}, Timeout) when length(Query) > 10 ->
    {ok, State2 = #oraclient{server=Ver, params=RowFormat}} = send_req(query, State, {Query, Bind}),
    handle_resp({Ver, RowFormat}, State2, Timeout);
sql_query(State = #oraclient{conn_state=connected, auth=To, env=Env}, {Query, Bind}, Timeout) ->
    case lists:nth(1, string:tokens(string:to_upper(Query)," \t;")) of
        "COMMIT" -> send_req(tran, State, ?TTI_COMMIT, Timeout);
        "ROLLBACK" -> send_req(tran, State, ?TTI_ROLLBACK, Timeout);
        "COMON" -> send_req(tran, State#oraclient{auto=1}, ?TTI_COMON, Timeout);
        "COMOFF" -> send_req(tran, State#oraclient{auto=0}, ?TTI_COMOFF, Timeout);
        "CLOSE" -> send_req(close, State, Timeout), {ok, Env, State#oraclient{conn_state=disconnected}};
        "PING" -> send_req(tran, State, ?TTI_PING, Timeout);
        "FETCH" -> {ok, [], State#oraclient{fetch=hd(Bind)}};
        "AUTH" -> To ! {get, self()}, {ok, receive Reply -> Reply end, State};
        _ -> {ok, undefined, State}
    end.

loop(Values) -> 
    receive {get, From} -> From ! Values, loop(Values) end.

%% internal
handle_login_resp(State = #oraclient{socket=Socket}, Timeout) ->
    case recv(Socket, Timeout) of
        {ok, ?TNS_DATA, BinaryData} ->
            case handle_token(BinaryData, State) of
                {ok, State2} -> handle_login_resp(State2, Timeout);
                State2 -> {ok, State2}                  %connected
            end;
        {ok, ?TNS_RESEND, _BinaryData} ->
            {ok, State2} = send_req(login, State),
            handle_login_resp(State2, Timeout);
        {ok, ?TNS_ACCEPT, _BinaryData} ->
            {ok, State2} = send_req(pro, State),
            handle_login_resp(State2, Timeout);
        {ok, ?TNS_MARKER, _BinaryData} ->
	    send_req(marker, State, Timeout);
        {ok, ?TNS_REFUSE, BinaryData} ->
            io:format("~s~n", [BinaryData]),
            handle_error(remote, BinaryData, State);
        {error, Type, Reason} ->
            handle_error(Type, Reason, State)
    end.

handle_token(<<Token, Data/binary>>, State) ->
    case Token of
	?TTI_PRO -> send_req(dty, State);
	?TTI_DTY -> send_req(sess, State);
	?TTI_RPA -> 
            case ?DECODER:decode_token(rpa, Data) of 
                {?TTI_SESS, Sess, Salt} -> send_req(auth, State, Sess, Salt);
                {?TTI_AUTH, Resp, Ver, Values} ->
                    #oraclient{auth = KeyConn} = State,
                    To = spawn(fun() -> loop(Values) end),
                    case jamdb_oracle_crypt:validate(Resp,KeyConn) of
                        ok -> State#oraclient{auth=To, conn_state=connected, server=Ver};
                        error -> handle_error(remote, <<>>, State)
                    end
            end;	
	?TTI_WRN -> handle_token(?DECODER:decode_token(wrn, Data), State);
	_ -> 
    	    {error, remote, undefined}
    end.

handle_error(socket, Reason, State) ->
    _ = disconnect(State, 0),
    {error, socket, Reason, State#oraclient{conn_state=disconnected}};
handle_error(Type, Reason, State) ->
    {error, Type, Reason, State}.

send_req(auth, #oraclient{env=Env} = State, Sess, Salt) ->
    {Data,KeyConn} = ?ENCODER:encode_record(auth, Env, Sess, Salt),
    send(State#oraclient{auth = KeyConn}, ?TNS_DATA, Data);
send_req(tran, State, Request, Timeout) ->
    Data = ?ENCODER:encode_record(tran, Request),
    {ok, State2} = send(State, ?TNS_DATA, Data),
    handle_resp([], State2, Timeout).

send_req(login, #oraclient{env=Env} = State) ->
    Data = ?ENCODER:encode_record(login, Env),
    send(State, ?TNS_CONNECT, Data);
send_req(Request, #oraclient{env=Env} = State) ->
    Data = ?ENCODER:encode_record(Request, Env),
    send(State, ?TNS_DATA, Data).

send_req(close, #oraclient{auto=0} = State, Timeout) ->
    _ = send_req(tran, State, ?TTI_ROLLBACK, Timeout),
    send_req(close, State#oraclient{auto=1}, Timeout);
send_req(close, #oraclient{cursors=Cursors} = State, Timeout) ->
    Data = ?ENCODER:encode_record(close, Cursors),
    {ok, State2} = send(State, ?TNS_DATA, Data),
    _ = handle_resp([], State2, Timeout),
    send(State2, ?TNS_DATA, <<64>>);
send_req(marker, State, Timeout) ->
    {ok, State2} = send(State, ?TNS_MARKER, <<1,0,2>>),
    handle_resp([], State2, Timeout);
send_req(fetch, #oraclient{auto=Auto,server=Ver} = State, {Cursor, Def}) ->
    Data = ?ENCODER:encode_record(fetch, {Cursor, 0, [], [], Def, Auto, 0, Ver}),
    send(State, ?TNS_DATA, Data);
send_req(fetch, #oraclient{fetch=Fetch} = State, Cursor) ->
    Data = ?ENCODER:encode_record(fetch, {Cursor, Fetch}),
    send(State, ?TNS_DATA, Data);
send_req(query, #oraclient{auto=Auto,fetch=Fetch,server=Ver} = State, {Query, Bind}) ->
    {Type, Fetch2} = get_param(type, {Query, Fetch}), 
    Data = ?ENCODER:encode_record(fetch, {0, Type, Query, [get_param(data, B) || B <- Bind], [], Auto, Fetch2, Ver}),
    send(State#oraclient{type=Type,params = [get_param(format, B) || B <- Bind]}, ?TNS_DATA, Data).

handle_resp(TokensBufer, State = #oraclient{socket=Socket}, Timeout) ->
    case recv(Socket, Timeout) of
        {ok, ?TNS_DATA, Data} ->
            handle_resp(Data, TokensBufer, State, Timeout);
        {ok, ?TNS_MARKER, _Data} ->
	    send_req(marker, State, Timeout);
        {error, Type, Reason} ->
            handle_error(Type, Reason, State)
    end.

handle_resp(Data, TokensBufer, #oraclient{type=Type} = State, Timeout) ->
    case ?DECODER:decode_token(Data, TokensBufer) of
	{0, 0, Cursor, RowFormat, []} when Type =/= 0, RowFormat =/= [] ->             %defcols   
	    {ok, State2} = send_req(fetch, State, {Cursor, RowFormat}),
       	    handle_resp({Cursor, RowFormat, []}, State2, Timeout);
	{0, _RowNumber, Cursor, RowFormat, []} when Type =/= 0, RowFormat =/= [] ->    %cursor
	    {ok, State2} = send_req(fetch, State, {Cursor, []}),
       	    handle_resp({Cursor, RowFormat, []}, State2, Timeout);
	{RetCode, RowNumber, Cursor, RowFormat, Rows} ->
            #oraclient{cursors = Cursors} = State,
	    case get_result(Type, RetCode, RowNumber, RowFormat, Rows) of
		more ->
		    {ok, State2} = send_req(fetch, State, Cursor),
        	    handle_resp({Cursor, RowFormat, Rows}, State2, Timeout);
                Result ->
                    erlang:append_element(Result, State#oraclient{cursors=get_result(Cursor,Cursors)})
	    end;
        {ok, Result} ->                                                                %tran
	    {ok, Result, State};
        {error, Reason} ->
    	    {error, remote, Reason}
    end.

get_result(0, 0, RowNumber, _RowFormat, []) ->
    {ok, [{affected_rows, RowNumber}]};
get_result(_Type, 0, _RowNumber, [], Rows) ->
    {ok, [{proc_result, 0, Rows}]};
get_result(_Type, RetCode, _RowNumber, Reason, []) when RetCode =/= 1403 ->
    io:format("~s~n", [Reason]),
    {ok, [{proc_result, RetCode, Reason}]};
get_result(_Type, RetCode, _RowNumber, RowFormat, Rows) ->
    case RetCode of
	1403 -> 
            Column = [get_result(Fmt) || Fmt <- RowFormat],
            {ok, [{result_set, Column, [], Rows}]};
	_ -> more
    end.

get_result(#format{column_name=Column}) ->
    Column.

get_result(Cursor, Cursors) when Cursor > 0 ->
    [Cursor|Cursors];
get_result(Cursor, Cursors) when Cursor =:= 0 ->
    Cursors.

get_param(type, {Query, Fetch}) ->
    case lists:nth(1, string:tokens(string:to_upper(Query)," \t")) of
        "SELECT" -> {1, Fetch};
        "BEGIN" -> {-1, 0};
        _ -> {0, 0}
    end;
get_param(data, {_Param, Data}) ->
    Data;
get_param(data, Data) ->
    Data;
get_param(format, {Param, Data}) ->
    get_param(Param, Data);
get_param(format, Data) ->
    get_param(in, Data);
get_param(Param, Data) ->
    {<<>>, DataType, Length, Charset} = 
    ?DECODER:decode_token(oac, ?ENCODER:encode_token(oac, Data)),
    #format{param=Param,data_type=DataType,data_length=Length,charset=Charset}.

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

recv(Socket, Timeout, Buffer, Data) ->
    case ?DECODER:decode_packet(Buffer) of
        {ok, Type, PacketBody, <<>>} ->
            {ok, Type, <<Data/bits, PacketBody/bits>>};
        {ok, ?TNS_DATA, PacketBody, Rest} ->
            recv(Socket, Timeout, Rest, <<Data/bits, PacketBody/bits>>);
        {error, more} ->
            case gen_tcp:recv(Socket, 0, Timeout) of
                {ok, NetworkData} ->
                    recv(Socket, Timeout, <<Buffer/bits, NetworkData/bits>>, Data);
                {error, Reason} ->
                    {error, socket, Reason}
            end
    end.
