-module(jamdb_oracle_conn).

%% API
-export([connect/1, connect/2]).
-export([reconnect/1]).
-export([disconnect/1, disconnect/2]).
-export([sql_query/2, sql_query/3]).

-include("jamdb_oracle.hrl").

-opaque state() :: #oraclient{}.
-type error_type() :: socket | remote | local.
-type columns() :: list().  %% TODO
-type metainfo() :: list(). %%TODO
-type rows() :: list().  %% TODO
-type return_status() :: non_neg_integer().
-type out_params() :: list().  %% TODO
-type empty_result() :: {ok, state()} | {error, error_type(), binary(), state()}.
-type fetched_rows() :: {fetched_rows, non_neg_integer(), metainfo(), rows()}.
-type affected_rows() :: {affected_rows, non_neg_integer()}.
-type result_set() :: {result_set, columns(), metainfo(), rows()}.
-type procedure_result() :: {proc_result, return_status(), out_params() | metainfo()}.
-type result() :: fetched_rows() | affected_rows() | result_set() | procedure_result().
-type query_result() :: {ok, [result()], state()}.
-type options() :: [env()].

-export_type([state/0]).
-export_type([options/0]).

%% API
-spec connect([env()]) -> empty_result().
connect(Opts) ->
    Tout        = proplists:get_value(timeout, Opts, ?DEF_TIMEOUT),
    connect(Opts, Tout).

-spec connect([env()], timeout()) -> empty_result().
connect(Opts, Tout) ->
    Host        = proplists:get_value(host, Opts, ?DEF_HOST),
    Port        = proplists:get_value(port, Opts, ?DEF_PORT),
    SslOpts     = proplists:get_value(ssl, Opts, []),
    SocketOpts  = proplists:get_value(socket_options, Opts, []),
    Auto        = proplists:get_value(autocommit, Opts, ?DEF_AUTOCOMMIT),
    Fetch       = proplists:get_value(fetch, Opts, ?DEF_FETCH),
    SockOpts = [binary, {active, false}, {packet, raw}, %{recbuf, 65535},
            {nodelay, true}, {keepalive, true}]++SocketOpts,
    case gen_tcp:connect(Host, Port, SockOpts, Tout) of
        {ok, Socket} ->
            {ok, Socket2} = sock_connect(Socket, SslOpts, Tout),
            State = #oraclient{socket=Socket2, env=Opts, auto=Auto, fetch=Fetch, timeout=Tout},
            {ok, State2} = send_req(login, State),
            handle_login(State2#oraclient{conn_state=auth_negotiate}, Tout);
        {error, Reason} ->
            {error, socket, Reason}
    end.

-spec disconnect(state()) -> {ok, [env()]}.
disconnect(#oraclient{timeout=Tout} = State) ->
    disconnect(State, Tout).

-spec disconnect(state(), timeout()) -> {ok, [env()]}.
disconnect(#oraclient{socket=Socket, env=Env}, 0) ->
    sock_close(Socket),
    {ok, Env};
disconnect(#oraclient{conn_state=connected, socket=Socket, env=Env} = State, Tout) ->
    _ = send_req(close, State, Tout),
    sock_close(Socket),
    {ok, Env};
disconnect(#oraclient{env=Env}, _Tout) ->
    {ok, Env}.

-spec reconnect(state()) -> {ok, state()}.
reconnect(State) ->
    {ok, InitOpts} = disconnect(State, 0),
    connect(InitOpts).

-spec sql_query(state(), string() | tuple()) -> query_result().
sql_query(State, Query) when is_list(Query) ->
    sql_query(State, {Query, []});
sql_query(#oraclient{timeout=Tout} = State, Query) ->
    sql_query(State, Query, Tout).

-spec sql_query(state(), string() | tuple(), timeout()) -> query_result().
sql_query(State, {Query, Bind}, Tout) when length(Query) > 10 ->
    sql_query(State, {Query, Bind, [], []}, Tout);
sql_query(State, {batch, Query, [Bind|Batch]}, Tout) ->
    sql_query(State, {Query, Bind, Batch, []}, Tout);
sql_query(State, {fetch, Query, Bind}, Tout) ->
    sql_query(State, {Query, Bind, [], fetch}, Tout);
sql_query(#oraclient{conn_state=connected} = State, {fetch, Cursor, RowFormat, LastRow}, Tout) ->
    {ok, State2} = send_req(fetch, State#oraclient{type=fetch}, Cursor),
    handle_resp({Cursor, RowFormat, [LastRow]}, State2, Tout);
sql_query(#oraclient{conn_state=connected} = State, {Query, Bind, Batch, Fetch}, Tout) ->
    {ok, State2} = send_req(exec, State, {Query, Bind, Batch}),
    #oraclient{server=Ver, defcols=DefCol, params=RowFormat, type=Type} = State2,
    handle_resp(get_param(defcols, {DefCol, Ver, RowFormat, Type}),
    State2#oraclient{type=get_param(type, {Type, Fetch})}, Tout);
sql_query(#oraclient{conn_state=connected} = State, {Query, Bind}, Tout) ->
    case lists:nth(1, string:tokens(string:to_upper(Query)," \t;")) of
        "SESSION" -> sql_query(State, {?ENCODER:encode_helper(sess, []), [], [], []}, Tout);
        "COMMIT" -> handle_req(tran, State, ?TTI_COMMIT, Tout);
        "ROLLBACK" -> handle_req(tran, State, ?TTI_ROLLBACK, Tout);
        "COMON" -> handle_req(tran, State#oraclient{auto=1}, ?TTI_COMON, Tout);
        "COMOFF" -> handle_req(tran, State#oraclient{auto=0}, ?TTI_COMOFF, Tout);
        "PING" -> handle_req(tran, State, ?TTI_PING, Tout);
        "STOP" -> handle_req(stop, State, hd(Bind), Tout);
        "START" -> handle_req(spfp, State, [], Tout), handle_req(start, State, hd(Bind), Tout);
        "CLOSE" -> disconnect(State, Tout), {ok, [], State#oraclient{conn_state=disconnected}};
        "TIMEOUT" -> {ok, [], State#oraclient{timeout=hd(Bind)}};
        "FETCH" -> {ok, [], State#oraclient{fetch=hd(Bind)}};
        _ -> {ok, undefined, State}
    end.

loop(Values) ->
    receive {get, From} -> From ! Values, loop(Values); {set, Values2} -> loop(Values2) end.

%% internal
handle_login(#oraclient{socket=Socket, env=Env} = State, Tout) ->
    case recv(Socket, Tout) of
        {ok, ?TNS_DATA, BinaryData} ->
            case handle_token(BinaryData, State) of
                {ok, State2} -> handle_login(State2, Tout);
                State2 -> {ok, State2}                  %connected
            end;
        {ok, ?TNS_REDIRECT, BinaryData} ->
            {ok, Opts} = ?DECODER:decode_token(net, {BinaryData, Env}),
            reconnect(State#oraclient{env=Opts});
        {ok, ?TNS_RESEND, _BinaryData} ->
            {ok, Socket2} = sock_renegotiate(Socket, Env, Tout),
            {ok, State2} = send_req(login, State#oraclient{socket=Socket2}),
            handle_login(State2, Tout);
        {ok, ?TNS_ACCEPT, _BinaryData} ->
            Task = spawn(fun() -> loop(0) end),
            {ok, State2} = send_req(pro, State#oraclient{seq=Task}),
            handle_login(State2, Tout);
        {ok, ?TNS_MARKER, _BinaryData} ->
            _ = handle_req(marker, State, [], Tout),
            disconnect(State, 0);
        {ok, ?TNS_REFUSE, BinaryData} ->
            _ = handle_error(remote, BinaryData, State),
            disconnect(State, 0);
        {error, Type, Reason} ->
            handle_error(Type, Reason, State)
    end.

handle_token(<<Token, Data/binary>>, State) ->
    case Token of
	?TTI_PRO -> send_req(dty, State);
	?TTI_DTY -> send_req(sess, State);
	?TTI_RPA ->
            case ?DECODER:decode_token(rpa, Data) of
                {?TTI_SESS, SessKey, Salt, DerivedSalt} ->
		    send_req(auth, State#oraclient{auth={SessKey, Salt, DerivedSalt}});
                {?TTI_AUTH, Resp, Ver, SessId} ->
                    #oraclient{auth = KeyConn} = State,
                    Cursors = spawn(fun() -> loop([]) end),
                    case jamdb_oracle_crypt:validate(Resp,KeyConn) of
                        ok -> State#oraclient{conn_state=connected,auth=SessId,server=Ver,cursors=Cursors};
                        error -> handle_error(remote, Resp, State)
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
%    io:format("~s~n", [Reason]),
    {error, Type, Reason, State}.

handle_req(marker, State, Acc, Tout) ->
    {ok, State2} = send(State, ?TNS_MARKER, <<1,0,2>>),
    handle_resp(Acc, State2, Tout);
handle_req(fob, State, Acc, Tout) ->
    {ok, State2} = send(State, ?TNS_DATA, <<?TTI_FOB>>),
    handle_resp(Acc, State2, Tout);
handle_req(Type, #oraclient{seq=Task} = State, Request, Tout) ->
    Data = ?ENCODER:encode_record(Type, #oraclient{req=Request,seq=get_param(Task)}),
    {ok, State2} = send(State, ?TNS_DATA, Data),
    handle_resp([], State2, Tout).
    
send_req(login, #oraclient{env=Env} = State) ->
    Data = ?ENCODER:encode_record(login, #oraclient{env=Env}),
    send(State, ?TNS_CONNECT, Data);
send_req(auth, #oraclient{env=Env,auth={Sess, Salt, DerivedSalt},seq=Task} = State) ->
    {Data,KeyConn} = ?ENCODER:encode_record(auth, #oraclient{env=Env, req={Sess, Salt, DerivedSalt},seq=get_param(Task)}),
    send(State#oraclient{auth=KeyConn}, ?TNS_DATA, Data);
send_req(Type, #oraclient{env=Env,seq=Task} = State) ->
    Data = ?ENCODER:encode_record(Type, #oraclient{env=Env,seq=get_param(Task)}),
    send(State, ?TNS_DATA, Data).

send_req(close, #oraclient{server=0,seq=Task} = State, _Tout) ->
    exit(Task, ok),
    send(State, ?TNS_DATA, <<64>>);
send_req(close, #oraclient{auto=0} = State, Tout) ->
    _ = handle_req(tran, State, ?TTI_ROLLBACK, Tout),
    send_req(close, State#oraclient{auto=1}, Tout);
send_req(close, #oraclient{cursors=Cursors,seq=Task} = State, Tout) ->
    _ = handle_req(close, State, {[get_result(DefCol) || DefCol <- get_result(Cursors)], get_param(Task)}, Tout),
    exit(Cursors, ok),
    send_req(close, State#oraclient{server=0}, Tout);
send_req(fetch, #oraclient{auto=Auto,server=Ver,fetch=Fetch,seq=Task} = State, {Cursor, RowFormat}) ->
    Data = ?ENCODER:encode_record(exec, #oraclient{req={Cursor, [], [], [], RowFormat},
	type=fetch, auth=Auto, fetch=Fetch, server=Ver, seq=get_param(Task)}),
    send(State, ?TNS_DATA, Data);
send_req(fetch, #oraclient{fetch=Fetch,seq=Task} = State, Cursor) ->
    Data = ?ENCODER:encode_record(fetch, #oraclient{fetch=Fetch,req=Cursor,seq=get_param(Task)}),
    send(State, ?TNS_DATA, Data);
send_req(exec, State, {Query, Bind, Batch}) when is_map(Bind) ->
    Data = lists:filtermap(fun(L) -> case string:chr(L, $:) of 0 -> false; I -> {true, lists:nthtail(I, L)} end end,
        string:tokens(Query," \t;,)")),
    send_req(exec, State, {Query, get_param(Data, Bind, []), Batch});
send_req(exec, #oraclient{auto=Auto,fetch=Fetch,server=Ver,cursors=Cursors,seq=Task} = State, {Query, Bind, Batch}) ->
    {Type, Fetch2, DefCol} = get_param(type, {Query, [B || {out, B} <- Bind], Fetch, Cursors}),
    Data = ?ENCODER:encode_record(exec, #oraclient{req={get_result(DefCol), Query,
	[get_param(data, B) || B <- Bind], Batch, []}, type=Type, auth=Auto, fetch=Fetch2, server=Ver, seq=get_param(Task)}),
    send(State#oraclient{type=Type,defcols=DefCol,params=[get_param(format, B) || B <- Bind]}, ?TNS_DATA, Data).
	
handle_resp(Acc, #oraclient{socket=Socket} = State, Tout) ->
    case recv(Socket, Tout) of
        {ok, ?TNS_DATA, Data} ->
            handle_resp(Data, Acc, State, Tout);
        {ok, ?TNS_MARKER, _Data} ->
            handle_req(marker, State, Acc, Tout);
        {error, Type, Reason} ->
            handle_error(Type, Reason, State)
    end.

handle_resp(Data, Acc, #oraclient{type=Type, cursors=Cursors} = State, Tout) ->
    case ?DECODER:decode_token(Data, Acc) of
	{0, RowNumber, Cursor, {Cursor2, RowFormat}, []} when Type =/= change, RowFormat =/= [] ->          %defcols
	    {ok, State2} = send_req(fetch, State, {Cursor, case RowNumber of 0 -> RowFormat; _ -> [] end}),
	    #oraclient{defcols=DefCol} = State2,
       	    handle_resp({Cursor, RowFormat, []},
	    State2#oraclient{defcols=get_result(DefCol, {Cursor2, RowFormat}, Cursors)}, Tout);
	{RetCode, RowNumber, Cursor, {Cursor2, RowFormat}, Rows} ->
	    case get_result(Type, RetCode, RowNumber, RowFormat, Rows) of
		more when Type =:= fetch ->
		    {ok, [{fetched_rows, Cursor, RowFormat, Rows}], State};
		more ->
		    {ok, State2} = send_req(fetch, State, Cursor),
		    handle_resp({Cursor, RowFormat, Rows}, State2, Tout);
		Result ->
		    #oraclient{defcols=DefCol} = State,
		    _ = get_result(DefCol, {Cursor2, RowFormat}, Cursors),
		    erlang:append_element(Result, State)
	    end;
	{ok, Result} -> %tran
	    {ok, Result, State};
	{error, fob} -> %return
	    handle_req(fob, State, Acc, Tout);
	{error, Reason} ->
	    handle_error(remote, Reason, State)
    end.

get_result(change, 0, RowNumber, _RowFormat, []) ->
    {ok, [{affected_rows, RowNumber}]};
get_result(return, 0, _RowNumber, _RowFormat, Rows) ->
    {ok, [{proc_result, 0, Rows}]};
get_result(block, 0, _RowNumber, _RowFormat, Rows) ->
    {ok, [{proc_result, 0, [Rows]}]};
get_result(_Type, 0, _RowNumber, [], Rows) ->
    {ok, [{proc_result, 0, Rows}]};
get_result(_Type, RetCode, _RowNumber, Reason, []) when RetCode =/= 1403 ->
%    io:format("~s~n", [Reason]),
    {ok, [{proc_result, RetCode, Reason}]};
get_result(_Type, RetCode, _RowNumber, RowFormat, Rows) ->
    case RetCode of
	1403 -> 
	    Column = [get_result(Fmt) || Fmt <- RowFormat],
	    {ok, [{result_set, Column, [], Rows}]};
	_ -> more
    end.

get_result(Cursors) when is_pid(Cursors) -> Cursors ! {get, self()}, receive Reply -> Reply end;
get_result({_Sum, {Cursor, _RowFormat}}) -> Cursor;
get_result(#format{column_name=Column}) -> Column.

get_result({Sum, {0, _RowFormat}}, {Cursor, RowFormat}, Cursors) when is_pid(Cursors) ->
    Acc = get_result(Cursors),
    DefCol = {Sum, {Cursor, RowFormat}},
    Cursors ! {set, [DefCol|Acc]},
    DefCol;
get_result(DefCol, {_Cursor, _RowFormat}, _Cursors) -> DefCol.

get_param(Task) when is_pid(Task) ->
    Task ! {get, self()},
    Tseq = receive 127 -> 0; Reply -> Reply end,
    Task ! {set, Tseq + 1}, Tseq + 1.

get_param([], _M, Acc) -> Acc;
get_param([H|L], M, Acc) -> get_param(L, M, Acc++[maps:get(list_to_atom(H), M)]).

get_param(defcols, {Query, Cursors}) ->
    Acc = get_result(Cursors),
    Sum = erlang:crc32(unicode:characters_to_binary(Query)),
    {Cursor, RowFormat} = proplists:get_value(Sum, Acc, {0,[]}),
    {Sum, {Cursor, RowFormat}};
get_param(defcols, {{_Sum, {0, _RowFormat}}, Ver, RowFormat, Type}) ->
    {Ver, RowFormat, Type};
get_param(defcols, {{_Sum, {_Cursor, RowFormat}} , Ver, _RowFormat, Type}) when Type =/= select ->
    {Ver, RowFormat, Type};
get_param(defcols, {{_Sum, {Cursor, RowFormat}} , _Ver, _RowFormat, Type}) ->
    {Cursor, RowFormat, Type};
get_param(type, {Query, Bind, Fetch, Cursors}) ->
    Value = lists:nth(1, string:tokens(string:to_upper(Query)," \t")),
    DefCol = get_param(defcols, {Query, Cursors}),
    erlang:append_element(get_param(type, {Value, Bind, Fetch}), DefCol);
get_param(type, {"BEGIN", _Bind, _Fetch}) -> {block, 0};
get_param(type, {"SELECT", [], Fetch}) -> {select, Fetch};
get_param(type, {_Value, [], _Fetch}) -> {change, 0};
get_param(type, {_Value, _Bind, _Fetch}) -> {return, 0};
get_param(type, {_Type, fetch}) -> fetch;
get_param(type, {Type, []}) -> Type;
get_param(data, {out, Data}) -> ?ENCODER:encode_helper(param, Data);
get_param(data, {in, Data}) -> Data;
get_param(data, Data) -> Data;
get_param(format, {out, Data}) -> get_param(out, ?ENCODER:encode_helper(param, Data));
get_param(format, {in, Data}) -> get_param(in, Data);
get_param(format, Data) -> get_param(in, Data);
get_param(Type, Data) ->
    {<<>>, DataType, Length, Scale, Charset} = ?DECODER:decode_helper(param, Data),
    #format{param=Type,data_type=DataType,data_length=Length,data_scale=Scale,charset=Charset}.

sock_renegotiate(Socket, _Opts, _Tout) when is_port(Socket) -> {ok, Socket};
sock_renegotiate(Socket, Opts, Tout) ->
    SslOpts = proplists:get_value(ssl, Opts, []),
    {ok, Socket2} = ssl:close(Socket, {self(), Tout}),
    ssl:connect(Socket2, SslOpts, Tout).

sock_connect(Socket, [], _Tout) when is_port(Socket) -> {ok, Socket};
sock_connect(Socket, SslOpts, Tout) -> ssl:connect(Socket, SslOpts, Tout).

sock_close(Socket) when is_port(Socket) -> gen_tcp:close(Socket);
sock_close(Socket) -> ssl:close(Socket).

sock_send(Socket, Packet) when is_port(Socket) -> gen_tcp:send(Socket, Packet);
sock_send(Socket, Packet) -> ssl:send(Socket, Packet).

sock_recv(Socket, Length, Tout) when is_port(Socket) -> gen_tcp:recv(Socket, Length, Tout);
sock_recv(Socket, Length, Tout) -> ssl:recv(Socket, Length, Tout).

send(State, _PacketType, <<>>) ->
    {ok, State};
send(#oraclient{socket=Socket} = State, PacketType, Data) ->
    {Packet, Rest} = ?ENCODER:encode_packet(PacketType, Data),
    case sock_send(Socket, Packet) of
        ok ->
            send(State, PacketType, Rest);
        {error, Reason} ->
            handle_error(socket, Reason, State)
    end.

recv(Socket, Tout) ->
    recv(Socket, Tout, <<>>, <<>>).

recv(Socket, Acc, Data) ->
    Tout = 500,
    case sock_recv(Socket, 0, Tout) of
        {ok, NetworkData} ->
            recv(Socket, Tout, <<Acc/bits, NetworkData/bits>>, Data);
        {error, timeout} ->
            {ok, ?TNS_DATA, Data};
        {error, Reason} ->
            {error, socket, Reason}
    end.

recv(Socket, Tout, Acc, Data) ->
    case ?DECODER:decode_packet(Acc) of
        {ok, Type, PacketBody, <<>>} ->
            {ok, Type, <<Data/bits, PacketBody/bits>>};
        {ok, _Type, PacketBody, Rest} ->
            recv(Socket, Tout, Rest, <<Data/bits, PacketBody/bits>>);
        {error, more, PacketBody, <<>>} ->
            recv(Socket, <<>>, <<Data/bits, PacketBody/bits>>);
        {error, more, PacketBody, Rest} ->
            recv(Socket, Tout, Rest, <<Data/bits, PacketBody/bits>>);
        {error, more} ->
            recv(Socket, Acc, Data);
        {error, socket} ->
            case sock_recv(Socket, 0, Tout) of
                {ok, NetworkData} ->
                    recv(Socket, Tout, <<Acc/bits, NetworkData/bits>>, Data);
                {error, Reason} ->
                    {error, socket, Reason}
            end
    end.

