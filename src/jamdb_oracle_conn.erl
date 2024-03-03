-module(jamdb_oracle_conn).

%% API
-export([connect/1, connect/2]).
-export([reconnect/1]).
-export([disconnect/1, disconnect/2]).
-export([sql_query/2, sql_query/3]).

-include("jamdb_oracle.hrl").

-opaque state() :: #oraclient{}.
-type error_type() :: socket | remote | local.
-type columns() :: list().
-type metainfo() :: list().
-type rows() :: list().
-type return_status() :: non_neg_integer().
-type out_params() :: list().
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
    Sdu         = proplists:get_value(sdu, Opts, ?DEF_SDU),
    ReadTout    = proplists:get_value(read_timeout, Opts, ?DEF_READ_TIMEOUT),
    Cset        = proplists:get_value(charset, Opts, utf8),
    Charset     = proplists:get_value(Cset, ?CHARSET, ?UTF8_CHARSET),
    SockOpts = [binary, {active, false}, {packet, raw},
            {nodelay, true}, {keepalive, true}]++SocketOpts,
    Desc        = proplists:get_value(description, Opts, []),
    Pass        = proplists:get_value(password, Opts),
    NewPass     = proplists:get_value(newpassword, Opts, []),
    EnvOpts     = proplists:delete(password, proplists:delete(newpassword, Opts)),
    Passwd = spawn(fun() -> loop({Pass, NewPass}) end),
    case gen_tcp:connect(Host, Port, SockOpts, Tout) of
        {ok, Socket} ->
            {ok, Socket2} = sock_connect(Socket, SslOpts, Tout),
            {ok, [{recbuf, RecBuf}]} = inet:getopts(Socket2, [recbuf]),
            inet:setopts(Socket2, [{buffer, RecBuf}]),
            State = #oraclient{socket=Socket2, env=EnvOpts, passwd=Passwd, auth=Desc,
            auto=Auto, fetch=Fetch, sdu=Sdu, charset=Charset, timeouts={Tout, ReadTout}},
            {ok, State2} = send_req(login, State),
            handle_login(State2#oraclient{conn_state=auth_negotiate});
        {error, Reason} ->
            handle_error(socket, Reason, #oraclient{})
    end.

-spec disconnect(state()) -> {ok, [env()]}.
disconnect(#oraclient{socket=Socket, env=Env, passwd=Passwd}) ->
    sock_close(Socket),
    freeval(Passwd),
    {ok, Env}.

-spec disconnect(state(), timeout()) -> {ok, []}.
disconnect(#oraclient{socket=Socket, passwd=Passwd} = State, _Tout) ->
    send_req(close, State),
    sock_close(Socket),
    freeval(Passwd),
    {ok, []}.

-spec reconnect(state()) -> empty_result().
reconnect(#oraclient{passwd=Passwd} = State) ->
    Passwd ! {get, self()},
    {Pass, NewPass} = receive Reply -> Reply end,
    {ok, EnvOpts} = disconnect(State),
    Pass2 = if NewPass =/= [] -> NewPass; true -> Pass end,
    connect([{password, Pass2}|EnvOpts]).

-spec sql_query(state(), string() | tuple(), timeout()) -> query_result().
sql_query(#oraclient{timeouts={_Tout, ReadTout}} = State, Query, Tout) ->
    sql_query(State#oraclient{timeouts={Tout, ReadTout}}, Query).

-spec sql_query(state(), string() | tuple()) -> query_result().
sql_query(State, Query) when is_list(Query) ->
    sql_query(State, {Query, []});
sql_query(State, {Query, Bind}) when length(Query) > 10 ->
    sql_query(State, {Query, Bind, [], []});
sql_query(State, {batch, Query, [Bind|Batch]}) ->
    sql_query(State, {Query, Bind, Batch, []});
sql_query(State, {fetch, Query, Bind}) ->
    sql_query(State, {Query, Bind, [], fetch});
sql_query(#oraclient{conn_state=connected} = State, {fetch, Cursor, RowFormat, LastRow}) ->
    {ok, State2} = send_req(fetch, State#oraclient{type=fetch}, Cursor),
    handle_resp({Cursor, RowFormat, [LastRow]}, State2);
sql_query(#oraclient{conn_state=connected} = State, {Query, Bind, Batch, Fetch}) ->
    {ok, State2} = send_req(exec, State, {Query, Bind, Batch}),
    #oraclient{defcols=DefCol, params=RowFormat, type=Type} = State2,
    handle_resp(get_param(defcols, {DefCol, RowFormat, Type}),
    State2#oraclient{type=get_param(type, {Type, Fetch})});
sql_query(#oraclient{conn_state=connected, timeouts={_Tout, ReadTout}} = State, {Query, Bind}) ->
    case lists:nth(1, string:tokens(string:to_upper(Query)," \t;")) of
        "SESSION" -> sql_query(State, {?ENCODER:encode_helper(sess, []), [], [], []});
        "COMMIT" -> handle_req(tran, State, ?TTI_COMMIT);
        "ROLLBACK" -> handle_req(tran, State, ?TTI_ROLLBACK);
        "COMON" -> handle_req(tran, State#oraclient{auto=1}, ?TTI_COMON);
        "COMOFF" -> handle_req(tran, State#oraclient{auto=0}, ?TTI_COMOFF);
        "PING" -> handle_req(tran, State, ?TTI_PING);
        "STOP" -> handle_req(stop, State, hd(Bind));
        "START" -> handle_req(spfp, State, []), handle_req(start, State, hd(Bind));
        "CLOSE" -> send_req(close, State), handle_error(local, [], State);
        "CURRESET" -> send_req(reset, State), {ok, [], State};
        "TIMEOUT" -> {ok, [], State#oraclient{timeouts={hd(Bind), ReadTout}}};
        "FETCH" -> {ok, [], State#oraclient{fetch=hd(Bind)}};
        _ -> {ok, undefined, State}
    end.

loop(Values) ->
    receive {get, From} -> From ! Values, loop(Values); {set, Values2} -> loop(Values2) end.

%% internal
handle_login(#oraclient{socket=Socket, env=Env, sdu=Length, timeouts=Touts} = State) ->
    case recv(Socket, Length, Touts) of
        {ok, ?TNS_DATA, Data} ->
            case handle_token(Data, State) of
                {ok, State2} -> handle_login(State2);
                State2 -> {ok, State2}                  %connected
            end;
        {ok, ?TNS_RESEND, _Data} ->
            {ok, Socket2} = sock_renegotiate(Socket, Env, Touts),
            {ok, State2} = send_req(login, State#oraclient{socket=Socket2}),
            handle_login(State2);
        {ok, ?TNS_ACCEPT, <<_Ver:16,_Opts:16,Sdu:16,_Rest/bits>>} ->
            Task = spawn(fun() -> loop(0) end),
            {ok, State2} = send_req(pro, State#oraclient{seq=Task,sdu=Sdu}),
            handle_login(State2);
        {ok, ?TNS_MARKER, _Data} ->
            handle_req(marker, State, []);
        {ok, ?TNS_REDIRECT, <<_Length:16,_Bin:80,Rest/bits>>} ->
            {ok, Opts} = ?DECODER:decode_token(net, {Rest, Env}),
            reconnect(State#oraclient{env=Opts});
        {ok, ?TNS_REFUSE, <<_Bin:16,_Length:16,Rest/bits>>} ->
            handle_error(local, binary_to_list(Rest), State);
        {error, Type, Reason} ->
            handle_error(Type, Reason, State)
    end.

handle_token(<<Token, Data/binary>>, State) ->
    case Token of
        ?TTI_PRO -> send_req(dty, State);
        ?TTI_DTY -> send_req(sess, State);
        ?TTI_RPA ->
            case ?DECODER:decode_token(rpa, Data) of
                {?TTI_SESS, Request} ->
                    send_req(auth, State#oraclient{req=Request});
                {?TTI_AUTH, Resp, Ver, SessId} ->
                    #oraclient{auth = KeyConn} = State,
                    Cursors = spawn(fun() -> loop([]) end),
                    case jamdb_oracle_crypt:validate(#logon{auth=Resp, key=KeyConn}) of
                        ok -> State#oraclient{conn_state=connected,auth=SessId,server=Ver,cursors=Cursors};
                        error -> handle_error(remote, Resp, State)
                    end
            end;
        ?TTI_WRN -> handle_token(?DECODER:decode_token(wrn, Data), State);
        _ -> handle_error(remote, Token, State)
    end.

handle_error(remote, Reason, State) ->
    {error, remote, Reason, State};
handle_error(socket, Reason, State) ->
    disconnect(State),
    {error, socket, Reason, State#oraclient{conn_state=disconnected}};
handle_error(local, Reason, State) ->
    disconnect(State),
    {ok, Reason, State#oraclient{conn_state=disconnected}}.

handle_bind(Query, Bind) ->
    Ks = string:tokens(Query," \t\r\n;,()="),
    {X, Y} = ?ENCODER:encode_helper(type, string:to_upper(hd(Ks))),
    handle_bind(X, Y, lists:filtermap(fun(L) -> if hd(L) =:= $: -> {true, tl(L)}; true -> false end end, Ks), Bind).

handle_bind(Select, Change, Data, Bind) when is_list(Bind) ->
    try lists:map(fun(L) -> list_to_integer(L) end, Data) of
        Bs -> {Select, Change, lists:map(fun(I) -> lists:nth(I, Bind) end, Bs)}
    catch
        error:_ -> {Select, Change, Bind}
    end;
handle_bind(Select, Change, Data, Bind) when is_map(Bind) ->
    {Select, Change, lists:map(fun(L) -> maps:get(list_to_atom(L), Bind) end, Data)}.

handle_req(pig, #oraclient{cursors=Cursors,seq=Task} = State, {Type, Request}) ->
    {LPig, LPig2} = unzip([get_param(defcols, DefCol) || DefCol <- get_result(Cursors)]),
    Pig = if LPig =/= [] -> get_record(pig, [], {?TTI_CANA, LPig}, Task); true -> <<>> end,
    Pig2 = if LPig2 =/= [] -> get_record(pig, [], {?TTI_OCCA, LPig2}, Task); true -> <<>> end,
    Data = get_record(Type, [], Request, Task),
    handle_req(State, ?TNS_DATA, <<Pig/binary, Pig2/binary, Data/binary>>, []);
handle_req(marker, State, Acc) ->
    handle_req(State, ?TNS_MARKER, <<1,0,2>>, Acc);
handle_req(fob, State, Acc) ->
    handle_req(State, ?TNS_DATA, <<?TTI_FOB>>, Acc);
handle_req(Type, #oraclient{seq=Task} = State, Request) ->
    Data = get_record(Type, [], Request, Task),
    handle_req(State, ?TNS_DATA, Data, []).

handle_req(State, PacketType, Data, Acc) ->
    case send(State, PacketType, Data) of
        {ok, State2} -> handle_resp(Acc, State2);
        Result -> Result
    end.

unzip(Ts) -> unzip(Ts, [], []).

unzip([{X, 0} | Ts], Xs, Ys) -> unzip(Ts, [X | Xs], Ys);
unzip([{X, Y} | Ts], Xs, Ys) -> unzip(Ts, [X | Xs], [Y | Ys]);
unzip([], Xs, Ys) -> {Ys, Ys ++ Xs}.

send_req(login, State) ->
    Data = get_record(login, State, [], 0),
    send(State, ?TNS_CONNECT, Data);
send_req(auth, #oraclient{req=Request,seq=Task} = State) ->
    {Data, KeyConn} = get_record(auth, State, Request, Task),
    send(State#oraclient{auth=KeyConn,req=[]}, ?TNS_DATA, Data);
send_req(close, #oraclient{server=0,seq=Task} = State) ->
    freeval(Task),
    send(State, ?TNS_DATA, <<64>>);
send_req(close, #oraclient{auto=0} = State) ->
    _ = handle_req(tran, State, ?TTI_ROLLBACK),
    send_req(close, State#oraclient{auto=1});
send_req(close, #oraclient{cursors=Cursors} = State) ->
    _ = handle_req(pig, State, {close, 0}),
    freeval(Cursors),
    send_req(close, State#oraclient{server=0});
send_req(reset, #oraclient{cursors=Cursors} = State) ->
    handle_req(pig, State, {tran, ?TTI_PING}),
    Cursors ! {set, []};
send_req(Type, #oraclient{req=Request,seq=Task} = State) ->
    Data = get_record(Type, State, Request, Task),
    send(State, ?TNS_DATA, Data).

send_req(fetch, #oraclient{seq=Task} = State, {Cursor, RowFormat}) ->
    Data = get_record(exec, State#oraclient{type=fetch}, {Cursor, [], [], [], RowFormat}, Task),
    send(State, ?TNS_DATA, Data);
send_req(fetch, #oraclient{seq=Task} = State, Cursor) ->
    Data = get_record(fetch, State, Cursor, Task),
    send(State, ?TNS_DATA, Data);
send_req(exec, #oraclient{charset=Charset,fetch=Fetch,cursors=Cursors,seq=Task} = State, {Query, Bind, Batch}) ->
    {Select, Change, Bind2} = handle_bind(Query, Bind),
    {Type, Fetch2} = get_param(type, {Select, Change, [B || {out, B} <- Bind2], Fetch}),
    Sum = erlang:crc32(?ENCODER:encode_str(Query)),
    DefCol = get_param(defcols, {Sum, Cursors}),
    {LCursor, Cursor} = get_param(defcols, DefCol),
    Pig = if Cursor =/= 0 -> get_record(pig, [], {?TTI_CANA, [Cursor]}, Task); true -> <<>> end,
    Pig2 = if Cursor =/= 0 -> get_record(pig, [], {?TTI_OCCA, [Cursor]}, Task); true -> <<>> end,
    Data = get_record(exec, State#oraclient{type=Type,fetch=Fetch2}, {LCursor, if LCursor =:= 0 -> Query; true -> [] end,
        [get_param(data, B) || B <- Bind2], Batch, []}, Task),
    send(State#oraclient{type=Type,defcols=DefCol,params=[get_param(format, B, #format{charset=Charset}) || B <- Bind2]},
        ?TNS_DATA, <<Pig/binary, Pig2/binary, Data/binary>>).

handle_resp(Acc, #oraclient{socket=Socket, sdu=Length, timeouts=Touts} = State) ->
    case recv(Socket, Length, Touts) of
        {ok, ?TNS_DATA, Data} ->
            handle_resp(Data, Acc, State);
        {ok, ?TNS_MARKER, _Data} ->
            handle_req(marker, State, Acc);
        {error, Type, Reason} ->
            handle_error(Type, Reason, State)
    end.

handle_resp(Data, Acc, #oraclient{type=Type, cursors=Cursors} = State) ->
    case ?DECODER:decode_two_task(Data, Acc) of
        {0, _RowNumber, Cursor, {LCursor, RowFormat}, []} when Type =/= change, RowFormat =/= [] ->
            Type2 = if LCursor =:= Cursor -> Type; true -> cursor end,
            {ok, State2} = send_req(fetch, State, {Cursor, RowFormat}),
            #oraclient{defcols=DefCol} = State2,
            {_, DefCol2} = currval(DefCol, {LCursor, Cursor, RowFormat}, Cursors),
            handle_resp({Cursor, RowFormat, []}, State2#oraclient{defcols=DefCol2, type=Type2});
        {RetCode, RowNumber, Cursor, {LCursor, RowFormat}, Rows} ->
            case get_result(Type, RetCode, RowNumber, RowFormat, Rows) of
                more when Type =:= fetch ->
                    {ok, [{fetched_rows, Cursor, RowFormat, Rows}], State};
                more ->
                    {ok, State2} = send_req(fetch, State, Cursor),
                    handle_resp({Cursor, RowFormat, Rows}, State2);
                {ok, Result} ->
                    #oraclient{defcols=DefCol} = State,
                    case currval(DefCol, {LCursor, Cursor, RowFormat}, Cursors) of
                        {reset, _} -> send_req(reset, State);
                        _ -> more
                    end,
                    {ok, Result, State};
                {error, Result} ->
                    case get_result(Cursors) of
                        [] -> more;
                        _ -> send_req(reset, State)
                    end,
                    {ok, Result, State}
            end;
        {ok, Result} -> %tran
            {ok, Result, State};
        {error, fob} -> %return
            handle_req(fob, State, Acc);
        {error, Reason} ->
            handle_error(remote, Reason, State)
    end.

get_result(cursor, 0, _RowNumber, _RowFormat, _Rows) ->
    more;
get_result(cursor, 1405, _RowNumber, _Reason, Rows) ->
    {error, [{proc_result, 1405, Rows}]};
get_result(change, 0, RowNumber, _RowFormat, []) ->
    {ok, [{affected_rows, RowNumber}]};
get_result(return, 0, _RowNumber, _RowFormat, Rows) ->
    {ok, [{proc_result, 0, Rows}]};
get_result(block, 0, _RowNumber, _RowFormat, Rows) ->
    {ok, [{proc_result, 0, [Rows]}]};
get_result(_Type, 0, _RowNumber, [], Rows) ->
    {ok, [{proc_result, 0, Rows}]};
get_result(_Type, 1403, _RowNumber, RowFormat, Rows) ->
    Column = [get_result(Fmt) || Fmt <- RowFormat],
    {ok, [{result_set, Column, [], Rows}]};
get_result(_Type, RetCode, _RowNumber, Reason, []) ->
    {error, [{proc_result, RetCode, Reason}]};
get_result(_Type, _RetCode, _RowNumber, _RowFormat, _Rows) ->
    more.

get_result(undefined) -> [];
get_result(Cursors) when is_pid(Cursors) -> Cursors ! {get, self()}, receive Reply -> Reply end;
get_result(#format{column_name=Column}) -> Column.

freeval(undefined) -> true;
freeval(Pid) when is_pid(Pid) -> exit(Pid, ok).

currval({Sum, {0, _Cursor, _RowFormat}}, Result, Cursors) when is_pid(Cursors) ->
    Acc = get_result(Cursors),
    DefCol = {Sum, Result},
    case length(Acc) > 127 of
        true -> {reset, DefCol};
        _ -> Cursors ! {set, [DefCol|Acc]}, {more, DefCol}
    end;
currval(DefCol, _Result, _Cursors) -> {more, DefCol}.

nextval(Task) when is_pid(Task) ->
    Task ! {get, self()},
    Tseq = receive 127 -> 0; Reply -> Reply end,
    Task ! {set, Tseq + 1}, Tseq + 1;
nextval(Tseq) -> Tseq.

get_param(format, {out, Data}, Format) -> get_param(out, ?ENCODER:encode_helper(param, Data), Format);
get_param(format, {in, Data}, Format) -> get_param(in, Data, Format);
get_param(format, Data, Format) -> get_param(in, Data, Format);
get_param(Type, Data, Format) when is_atom(Type) ->
    {<<>>, DataType, Length, Scale, Charset} = ?DECODER:decode_helper(param, Data, Format),
    #format{param=Type,data_type=DataType,data_length=Length,data_scale=Scale,charset=Charset}.

get_param(defcols, {Sum, Cursors}) when is_pid(Cursors) ->
    Acc = get_result(Cursors),
    {Sum, proplists:get_value(Sum, Acc, {0,0,[]})};
get_param(defcols, {_Sum, {LCursor, Cursor, _RowFormat}}) when LCursor =:= Cursor -> {LCursor, 0};
get_param(defcols, {_Sum, {LCursor, Cursor, _RowFormat}}) -> {LCursor, Cursor};
get_param(defcols, {{_Sum, {LCursor, Cursor, _RowFormat}}, RowFormat, Type}) when LCursor =:= 0; LCursor =/= Cursor ->
    {0, RowFormat, Type};
get_param(defcols, {{_Sum, {LCursor, _Cursor, RowFormat}}, _RowFormat, Type}) ->
    {LCursor, RowFormat, Type};
get_param(type, {true, false, [], Fetch}) -> {select, Fetch};
get_param(type, {false, true, [], _Fetch}) -> {change, 0};
get_param(type, {false, true, _Bind, _Fetch}) -> {return, 0};
get_param(type, {false, false, _Bind, _Fetch}) -> {block, 0};
get_param(type, {_Type, fetch}) -> fetch;
get_param(type, {Type, []}) -> Type;
get_param(data, {out, Data}) -> ?ENCODER:encode_helper(param, Data);
get_param(data, {in, Data}) -> Data;
get_param(data, Data) -> Data.

get_record(Type, [], Request, Task) ->
    ?ENCODER:encode_record(Type, #oraclient{req=Request, seq=nextval(Task)});
get_record(Type, State, Request, Task) ->
    ?ENCODER:encode_record(Type, State#oraclient{req=Request, seq=nextval(Task)}).

sock_renegotiate(Socket, _Opts, _Touts) when is_port(Socket) -> {ok, Socket};
sock_renegotiate(Socket, Opts, {Tout, _ReadTout}) ->
    SslOpts = proplists:get_value(ssl, Opts, []),
    {ok, Socket2} = ssl:close(Socket, {self(), Tout}),
    ssl:connect(Socket2, SslOpts, Tout).

sock_connect(Socket, [], _Tout) when is_port(Socket) -> {ok, Socket};
sock_connect(Socket, SslOpts, Tout) -> ssl:connect(Socket, SslOpts, Tout).

sock_close(undefined) -> ok;
sock_close(Socket) when is_port(Socket) -> gen_tcp:close(Socket);
sock_close(Socket) -> ssl:close(Socket).

sock_send(Socket, Packet) when is_port(Socket) -> gen_tcp:send(Socket, Packet);
sock_send(Socket, Packet) -> ssl:send(Socket, Packet).

sock_recv(Socket, Length, Tout) when is_port(Socket) -> gen_tcp:recv(Socket, Length, Tout);
sock_recv(Socket, Length, Tout) -> ssl:recv(Socket, Length, Tout).

send(State, _PacketType, <<>>) ->
    {ok, State};
send(#oraclient{socket=Socket,sdu=Length} = State, PacketType, Data) ->
    {Packet, Rest} = ?ENCODER:encode_packet(PacketType, Data, Length),
    case sock_send(Socket, Packet) of
        ok ->
            send(State, PacketType, Rest);
        {error, Reason} ->
            handle_error(socket, Reason, State)
    end.

recv(Socket, Length, {Tout, _ReadTout} = Touts) ->
    case sock_recv(Socket, 0, Tout) of
        {ok, NetworkData} ->
            recv(Socket, Length, Touts, NetworkData, <<>>);
        {error, Reason} ->
            {error, socket, Reason}
    end.

recv(read_timeout, Socket, Length, {_Tout, ReadTout} = Touts, Acc, Data) ->
    case sock_recv(Socket, 0, ReadTout) of
        {ok, NetworkData} ->
            recv(Socket, Length, Touts, <<Acc/bits, NetworkData/bits>>, Data);
        {error, timeout} ->
            {ok, ?TNS_DATA, Data};
        {error, Reason} ->
            {error, socket, Reason}
    end.

recv(Socket, Length, Touts, Acc, Data) ->
    case ?DECODER:decode_packet(Acc, Length) of
        {ok, ?TNS_MARKER, <<1,0,1>>, _Rest} ->
            recv(read_timeout, Socket, Length, Touts, <<>>, <<>>);
        {ok, Type, PacketBody, <<>>} ->
            {ok, Type, <<Data/bits, PacketBody/bits>>};
        {ok, _Type, PacketBody, Rest} ->
            recv(Socket, Length, Touts, Rest, <<Data/bits, PacketBody/bits>>);
        {more, _Type, PacketBody, <<>>} ->
            recv(read_timeout, Socket, Length, Touts, <<>>, <<Data/bits, PacketBody/bits>>);
        {more, _Type, PacketBody, Rest} ->
            recv(Socket, Length, Touts, Rest, <<Data/bits, PacketBody/bits>>);
        {error, more} ->
            recv(read_timeout, Socket, Length, Touts, Acc, Data)
    end.
