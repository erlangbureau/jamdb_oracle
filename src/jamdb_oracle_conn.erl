-module(jamdb_oracle_conn).

%% API
-export([connect/1, connect/2]).
-export([reconnect/1]).
-export([disconnect/1, disconnect/2]).
-export([sql_query/2, sql_query/3]).

-include("jamdb_oracle.hrl").
-include("jamdb_oracle_network_hash.hrl").

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
    Debug       = proplists:get_value(debug, Opts, false),
    Desc        = proplists:get_value(description, Opts, []),
    Pass        = proplists:get_value(password, Opts),
    NewPass     = proplists:get_value(newpassword, Opts, []),
    EnvOpts     = proplists:delete(password, proplists:delete(newpassword, Opts)),
    Passwd = spawn(fun() -> loop({Pass, NewPass}) end),

    %% Detect SSL mode
    UseSSL = SslOpts =/= [] andalso SslOpts =/= undefined,

    debug_log(Debug, "Connecting to ~p:~p (SSL: ~p)", [Host, Port, UseSSL]),

    %% Connect using appropriate socket type
    case do_connect(Host, Port, SocketOpts, SslOpts, UseSSL, Tout, Debug) of
        {ok, Socket, IsSSL} ->
            {ok, [{recbuf, RecBuf}]} = get_socket_opts(Socket, IsSSL, [recbuf]),
            set_socket_opts(Socket, IsSSL, [{buffer, RecBuf}]),

            State = #oraclient{
                socket=Socket,
                env=EnvOpts,
                passwd=Passwd,
                auth=Desc,
                auto=Auto,
                fetch=Fetch,
                sdu=Sdu,
                charset=Charset,
                timeouts={Tout, ReadTout},
                use_ssl=IsSSL,
                ssl_opts=SslOpts,
                debug=Debug
            },

            debug_log(Debug, "Connection established, starting login", []),
            {ok, State2} = send_req(login, State),
            handle_login(State2#oraclient{conn_state=auth_negotiate});
        {error, Reason} ->
            debug_log(Debug, "Connection failed: ~p", [Reason]),
            handle_error(socket, Reason, #oraclient{debug=Debug})
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
    %% Convert binary (Elixir string) to charlist for Erlang string functions
    QueryList = case is_binary(Query) of
        true -> binary_to_list(Query);
        false -> Query
    end,
    case lists:nth(1, string:tokens(string:to_upper(QueryList)," \t;")) of
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

%% Debug logging helper
debug_log(false, _Format, _Args) ->
    ok;
debug_log(true, Format, Args) ->
    io:format("[jamdb_oracle] " ++ Format ++ "~n", Args),
    %% Force output to appear immediately
    io:format([]).

%% Socket connection abstraction - handles both TCP and SSL
do_connect(Host, Port, SocketOpts, SslOpts, true = _UseSSL, Tout, Debug) ->
    io:format("[CONNECT] Attempting SSL/TLS connection to ~p:~p~n", [Host, Port]),
    debug_log(Debug, "Using SSL/TLS connection", []),
    %% Merge socket options with SSL options
    SockOpts = [binary, {active, false}, {packet, raw},
                 {nodelay, true}, {keepalive, true}] ++ SocketOpts,
    case ssl:connect(Host, Port, SockOpts ++ SslOpts, Tout) of
        {ok, Socket} ->
            io:format("[CONNECT] SSL/TLS connection established~n", []),
            debug_log(Debug, "SSL/TLS connection established", []),
            {ok, Socket, true};
        {error, Reason} ->
            io:format("[CONNECT] SSL/TLS connection failed: ~p~n", [Reason]),
            debug_log(Debug, "SSL/TLS connection failed: ~p", [Reason]),
            {error, Reason}
    end;
do_connect(Host, Port, SocketOpts, _SslOpts, false = _UseSSL, Tout, Debug) ->
    io:format("[CONNECT] Attempting plain TCP connection to ~p:~p~n", [Host, Port]),
    debug_log(Debug, "Using plain TCP connection", []),
    SockOpts = [binary, {active, false}, {packet, raw},
                 {nodelay, true}, {keepalive, true}] ++ SocketOpts,
    case gen_tcp:connect(Host, Port, SockOpts, Tout) of
        {ok, Socket} ->
            io:format("[CONNECT] TCP connection established~n", []),
            debug_log(Debug, "TCP connection established", []),
            {ok, Socket, false};
        {error, Reason} ->
            io:format("[CONNECT] TCP connection failed: ~p~n", [Reason]),
            debug_log(Debug, "TCP connection failed: ~p", [Reason]),
            {error, Reason}
    end.

%% Socket options abstraction
get_socket_opts(Socket, true = _IsSSL, Opts) ->
    ssl:getopts(Socket, Opts);
get_socket_opts(Socket, false = _IsSSL, Opts) ->
    inet:getopts(Socket, Opts).

set_socket_opts(Socket, true = _IsSSL, Opts) ->
    ssl:setopts(Socket, Opts);
set_socket_opts(Socket, false = _IsSSL, Opts) ->
    inet:setopts(Socket, Opts).

%% internal
handle_login(#oraclient{socket=Socket, env=Env, sdu=Length, timeouts=Touts, use_ssl=UseSSL, debug=Debug} = State) ->
    debug_log(Debug, "handle_login: waiting for server response", []),
    case recv(Socket, Length, Touts, State) of
        {ok, ?TNS_DATA, Data} ->
            debug_log(Debug, "Received TNS_DATA packet (~p bytes)", [byte_size(Data)]),
            %% Decrypt and verify data if security is enabled
            {DecryptedData, State1} = decrypt_and_verify_data(Data, State),

            case handle_token(DecryptedData, State1) of
                {ok, State2} ->
                    handle_login(State2);
                {error, Type, Reason, State2} ->
                    debug_log(Debug, "handle_token error: ~p, ~p", [Type, Reason]),
                    {error, Type, Reason, State2};
                State2 ->
                    debug_log(Debug, "Authentication successful, connected", []),
                    {ok, State2}                  %connected
            end;
        {ok, ?TNS_RESEND, _Data} ->
            debug_log(Debug, "Received TNS_RESEND", []),
            case sock_renegotiate(Socket, Env, Touts) of
                {ok, Socket2} ->
                    try send_req(login, State#oraclient{socket=Socket2}) of
                        {ok, State2} ->
                            handle_login(State2);
                        _SendError ->
                            debug_log(Debug, "Send failed during renegotiation", []),
                            handle_error(socket, send_failed, State)
                    catch
                        _Class:Reason:_Stack ->
                            debug_log(Debug, "Exception during renegotiation: ~p", [Reason]),
                            handle_error(socket, Reason, State)
                    end;
                {error, Reason} ->
                    debug_log(Debug, "Renegotiation failed: ~p", [Reason]),
                    handle_error(socket, Reason, State)
            end;
        {ok, ?TNS_ACCEPT, <<Ver:16,_Opts:16,Sdu:16,_Tdu:16,_Histone:16,_BufLen:16,_DataOff:16,Acfl0:8,Acfl1:8,_Rest/bits>>} ->
            debug_log(Debug, "Received TNS_ACCEPT (version=~p, SDU=~p, ACFL0=~p, ACFL1=~p)", [Ver, Sdu, Acfl0, Acfl1]),
            %% Check if advanced negotiation/encryption is indicated by flags
            HasAdvancedService = ((Acfl0 band 1) =/= 0) andalso ((Acfl0 band 4) =:= 0) andalso ((Acfl1 band 8) =:= 0),

            %% Skip native encryption when SSL is active (SSL handles encryption at transport layer)
            ShouldNegotiate = HasAdvancedService andalso not UseSSL,

            case ShouldNegotiate of
                true ->
                    debug_log(Debug, "Advanced service negotiation requested, starting...", []),
                    StateWithSdu = State#oraclient{sdu=Sdu, version=Ver},
                    case jamdb_oracle_adv_nego:negotiate(StateWithSdu) of
                        {ok, State2} ->
                            debug_log(Debug, "Advanced negotiation successful, activating encryption...", []),
                            case jamdb_oracle_adv_nego:activate_encryption(State2#oraclient.crypto_algo, State2) of
                                {ok, State3} ->
                                    debug_log(Debug, "Encryption activated successfully", []),
                                    Task = spawn(fun() -> loop(0) end),
                                    %% Clear crypto_algo so legacy flow doesn't try to activate encryption again
                                    State3WithSeq = State3#oraclient{seq=Task, crypto_algo=undefined},
                                    {ok, State4} = send_req(pro, State3WithSeq),
                                    handle_login(State4);
                                {error, Reason} ->
                                    debug_log(Debug, "Failed to activate encryption: ~p", [Reason]),
                                    handle_error(remote, Reason, State2)
                            end;
                        {error, Reason} ->
                            debug_log(Debug, "Advanced negotiation failed: ~p", [Reason]),
                            handle_error(remote, Reason, StateWithSdu)
                    end;
                false ->
                    debug_log(Debug, "Using standard TNS protocol (no advanced negotiation)", []),
                    Task = spawn(fun() -> loop(0) end),
                    {ok, State2} = send_req(pro, State#oraclient{seq=Task, sdu=Sdu, version=Ver}),
                    handle_login(State2)
            end;
        {ok, ?TNS_MARKER, _Data} ->
            debug_log(Debug, "Received TNS_MARKER", []),
            handle_req(marker, State, []);
        {ok, ?TNS_REDIRECT, Data} ->
            debug_log(Debug, "Received TNS_REDIRECT", []),
            Addresses = parse_redirect_addresses(binary_to_list(Data)),
            debug_log(Debug, "Trying ~p addresses", [length(Addresses)]),
            try_redirect(Addresses, State);
        {ok, ?TNS_REFUSE, <<_Bin:16,_Length:16,Rest/bits>>} ->
            RefuseMsg = binary_to_list(Rest),
            handle_error(local, RefuseMsg, State);
        {error, Type, Reason} ->
            handle_error(Type, Reason, State)
    end.

handle_token(<<Token, Data/binary>>, State) ->
    case Token of
        ?TTI_PRO ->
            send_req(dty, State);
        ?TTI_DTY ->
            send_req(sess, State);
        ?TTI_RPA ->
            case ?DECODER:decode_token(rpa, Data) of
                {?TTI_SESS, Request} ->
                    send_req(auth, State#oraclient{req=Request});
                {?TTI_AUTH, Resp, Ver, SessId} ->
                    #oraclient{auth = KeyConn, crypto_algo = CryptoAlgo} = State,
                    Cursors = spawn(fun() -> loop([]) end),
                    case jamdb_oracle_crypt:validate(#logon{auth=Resp, key=KeyConn}) of
                        ok ->
                            ConnectedState = State#oraclient{conn_state=connected,auth=KeyConn,server=Ver,cursors=Cursors},
                            case jamdb_oracle_adv_nego:activate_encryption(CryptoAlgo, ConnectedState) of
                                {ok, FinalState} ->
                                    FinalState#oraclient{auth=SessId};
                                {error, Reason} ->
                                    handle_error(remote, Reason, ConnectedState)
                            end;
                        error ->
                            handle_error(remote, Resp, State)
                    end
            end;
        ?TTI_WRN -> handle_token(?DECODER:decode_token(wrn, Data), State);
        _ -> handle_error(remote, Token, State)
    end.

handle_error(remote, Reason, #oraclient{debug = Debug}) ->
    debug_log(Debug, "handle_error: remote error - ~p", [Reason]),
    {error, remote, Reason, #oraclient{conn_state=disconnected}};
handle_error(socket, Reason, #oraclient{debug = Debug}) ->
    debug_log(Debug, "handle_error: socket error - ~p", [Reason]),
    disconnect(#oraclient{conn_state=disconnected}),
    {error, socket, Reason, #oraclient{conn_state=disconnected}};
handle_error(local, Reason, #oraclient{debug = Debug} = State) ->
    debug_log(Debug, "handle_error: local error - ~p", [Reason]),
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

%% Decrypt and verify data if security is enabled (removes folding key, decrypts, verifies hash)
decrypt_and_verify_data(Data, #oraclient{crypto=Crypto, hash_state=HashState} = State) ->
    case {Crypto, HashState} of
        {undefined, undefined} ->
            {Data, State};
        _ when Crypto =/= undefined orelse HashState =/= undefined ->
            %% Check if data is long enough for encryption (go-ora checks len > 1)
            DataLen = byte_size(Data),
            case DataLen of
                Len when Len =< 1 ->
                    {Data, State};
                _ ->
                    %% Step 1: Remove folding key byte (last byte)
                    DataWithoutFolding = binary:part(Data, 0, DataLen - 1),

                    %% Step 2: Decrypt if crypto is active
                    {DecryptedWithHash, NewCrypto} = case Crypto of
                        undefined -> {DataWithoutFolding, undefined};
                        _ ->
                            case jamdb_oracle_network_crypto:decrypt(DataWithoutFolding, Crypto) of
                                {ok, Dec, NC} ->
                                    {Dec, NC};
                                {error, _DecReason} ->
                                    {Data, Crypto}
                            end
                    end,

                    %% Step 3: Verify and remove Oracle hash if data integrity is active
                    %% Skip hash if data appears unencrypted (same as original Data)
                    {PlainDataFinal, NewHashState} = case {HashState, DecryptedWithHash =:= Data} of
                        {undefined, _} -> {DecryptedWithHash, undefined};
                        {_, true} ->
                            %% Data wasn't decrypted (unencrypted response), skip hash verification
                            {DecryptedWithHash, HashState};
                        {_, false} ->
                            %% Data was decrypted, verify hash
                            HashSize = case HashState of
                                #oracle_hash_state{hash_size = HS} -> HS;
                                _ -> 16  %% Default to MD5 size
                            end,
                            PlainSize = byte_size(DecryptedWithHash) - HashSize,
                            case PlainSize >= 0 of
                                true ->
                                    <<Plain:PlainSize/binary, _RecvHash:HashSize/binary>> = DecryptedWithHash,
                                    %% TODO: Optionally verify hash matches
                                    {Plain, HashState};
                                false ->
                                    {DecryptedWithHash, HashState}
                            end
                    end,

                    {PlainDataFinal, State#oraclient{crypto=NewCrypto, hash_state=NewHashState}}
            end
    end.

handle_resp(Acc, State) ->
    case recv(State#oraclient.socket, State#oraclient.sdu, State#oraclient.timeouts, State) of
        {ok, ?TNS_DATA, Data} ->
            handle_resp(Data, Acc, State);
        {ok, ?TNS_MARKER, _Data} ->
            handle_req(marker, State, Acc);
        {error, Type, Reason} ->
            handle_error(Type, Reason, State)
    end.

handle_resp(Data, Acc, #oraclient{type=Type, cursors=Cursors} = State) ->
    %% Decrypt and verify data if security is enabled
    {PlainData, State2} = decrypt_and_verify_data(Data, State),

    case ?DECODER:decode_two_task(PlainData, Acc) of
        {0, _RowNumber, Cursor, {LCursor, RowFormat}, []} when Type =/= change, RowFormat =/= [] ->
            Type2 = if LCursor =:= Cursor -> Type; true -> cursor end,
            {ok, State3} = send_req(fetch, State2, {Cursor, RowFormat}),
            #oraclient{defcols=DefCol} = State3,
            {_, DefCol2} = currval(DefCol, {LCursor, Cursor, RowFormat}, Cursors),
            handle_resp({Cursor, RowFormat, []}, State2#oraclient{defcols=DefCol2, type=Type2});
        {RetCode, RowNumber, Cursor, {LCursor, RowFormat}, Rows} ->
            case get_result(Type, RetCode, RowNumber, RowFormat, Rows) of
                more when Type =:= fetch ->
                    {ok, [{fetched_rows, Cursor, RowFormat, Rows}], State2};
                more ->
                    {ok, State3} = send_req(fetch, State2, Cursor),
                    handle_resp({Cursor, RowFormat, Rows}, State3);
                {ok, Result} ->
                    #oraclient{defcols=DefCol} = State2,
                    case currval(DefCol, {LCursor, Cursor, RowFormat}, Cursors) of
                        {reset, _} -> send_req(reset, State2);
                        _ -> more
                    end,
                    {ok, Result, State2};
                {error, Result} ->
                    case get_result(Cursors) of
                        [] -> more;
                        _ -> send_req(reset, State2)
                    end,
                    {ok, Result, State2}
            end;
        {ok, Result} -> %tran
            {ok, Result, State2};
        {error, fob} -> %return
            handle_req(fob, State2, Acc);
        {error, Reason} ->
            handle_error(remote, Reason, State2)
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

sock_renegotiate(Socket, _Opts, _Touts) when is_port(Socket) ->
    %% Plain TCP socket - TNS_RESEND just means "resend your login", not "upgrade to SSL"
    {ok, Socket};
sock_renegotiate(Socket, Opts, {Tout, _ReadTout}) ->
    %% Already SSL socket - close and reopen for renegotiation
    SslOpts = proplists:get_value(ssl, Opts, []),
    case ssl:close(Socket, {self(), Tout}) of
        {ok, Socket2} ->
            case ssl:connect(Socket2, SslOpts, Tout) of
                {ok, NewSocket} ->
                    {ok, NewSocket};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.

sock_close(undefined) -> ok;
sock_close(Socket) when is_port(Socket) -> gen_tcp:close(Socket);
sock_close(Socket) -> ssl:close(Socket).

sock_send(Socket, Packet) when is_port(Socket) ->
    io:format("[SOCKET TCP SEND] ~p bytes~n", [byte_size(Packet)]),
    io:format("  Data: ~p~n", [Packet]),
    gen_tcp:send(Socket, Packet);
sock_send(Socket, Packet) ->
    io:format("[SOCKET SSL SEND] ~p bytes~n", [byte_size(Packet)]),
    io:format("  Data: ~p~n", [Packet]),
    ssl:send(Socket, Packet).

sock_recv(Socket, Length, Tout) when is_port(Socket) ->
    debug_log(true, "[TCP RECV] Waiting for ~p bytes (timeout=~p)", [Length, Tout]),
    Result = gen_tcp:recv(Socket, Length, Tout),
    case Result of
        {ok, Data} ->
            debug_log(true, "[TCP RECV] Got ~p bytes~n", [byte_size(Data)]),
            debug_log(true, "  Data: ~p~n", [Data]),
            {ok, Data};
        {error, Reason} ->
            debug_log(true, "[TCP RECV] Error: ~p~n", [Reason]),
            {error, Reason}
    end;
sock_recv(Socket, Length, Tout) ->
    debug_log(true, "[SSL RECV] Waiting for ~p bytes (timeout=~p)", [Length, Tout]),
    Result = ssl:recv(Socket, Length, Tout),
    case Result of
        {ok, Data} ->
            debug_log(true, "[SSL RECV] Got ~p bytes~n", [byte_size(Data)]),
            debug_log(true, "  Data: ~p~n", [Data]),
            {ok, Data};
        {error, Reason} ->
            debug_log(true, "[SSL RECV] Error: ~p~n", [Reason]),
            {error, Reason}
    end.

send(State, _PacketType, <<>>) ->
    {ok, State};
send(#oraclient{socket=Socket,sdu=Length,version=Version,crypto=Crypto,hash_state=HashState} = State, PacketType, Data) ->
    %% Apply security (hash + encrypt + folding) if enabled (for TNS_DATA packets after negotiation)
    {DataToSend, State2} = case {PacketType, Crypto, HashState} of
        {?TNS_DATA, undefined, undefined} ->
            {Data, State};
        {?TNS_DATA, _, _} when Crypto =/= undefined orelse HashState =/= undefined ->
            %% Step 1: Compute Oracle hash if data integrity is active
            {DataWithHash, NewHashState} = case HashState of
                undefined -> {Data, undefined};
                _ ->
                    {Hash, HS2} = jamdb_oracle_network_hash:compute(Data, HashState),
                    {<<Data/binary, Hash/binary>>, HS2}
            end,

            %% Step 2: Encrypt if crypto is active
            {EncryptedData, NewCrypto} = case Crypto of
                undefined -> {DataWithHash, undefined};
                _ ->
                    case jamdb_oracle_network_crypto:encrypt(DataWithHash, Crypto) of
                        {ok, Enc, NC} -> {Enc, NC};
                        {error, _} -> {DataWithHash, Crypto}
                    end
            end,

            %% Step 3: Add folding key byte (0x00) if either hash or crypto is active
            FinalData = <<EncryptedData/binary, 0>>,

            {FinalData, State#oraclient{crypto=NewCrypto, hash_state=NewHashState}};
        _ ->
            {Data, State}
    end,

    {Packet, Rest} = ?ENCODER:encode_packet(PacketType, DataToSend, Length, Version),
    case sock_send(Socket, Packet) of
        ok ->
            debug_log(State2#oraclient.debug, "Sent TNS packet type ~p (~p bytes)~n", [PacketType, byte_size(Packet)]),
            debug_log(State2#oraclient.debug, "  Data: ~p~n", [Packet]),
            send(State2, PacketType, Rest);
        {error, Reason} ->
            debug_log(State2#oraclient.debug, "Send failed: ~p~n", [Reason]),
            handle_error(socket, Reason, State2)
    end.

recv(Socket, Length, {Tout, _ReadTout} = Touts, #oraclient{}) ->
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
            FullData = <<Data/bits, PacketBody/bits>>,
            {ok, Type, FullData};
        {ok, _Type, PacketBody, Rest} ->
            recv(Socket, Length, Touts, Rest, <<Data/bits, PacketBody/bits>>);
        {more, _Type, PacketBody, <<>>} ->
            recv(read_timeout, Socket, Length, Touts, <<>>, <<Data/bits, PacketBody/bits>>);
        {more, _Type, PacketBody, Rest} ->
            recv(Socket, Length, Touts, Rest, <<Data/bits, PacketBody/bits>>);
        {error, more} ->
            recv(read_timeout, Socket, Length, Touts, Acc, Data)
    end.

try_redirect([], _State) -> {error, redirect_failed};
try_redirect([{Host, Port} | Rest], #oraclient{debug=Debug, use_ssl=UseSSL, ssl_opts=SslOpts} = State) ->
    debug_log(Debug, "Trying ~s:~p", [Host, Port]),
    Opts = lists:keydelete(host, 1, State#oraclient.env) ++ [{host, Host}, {port, Port}],
    case do_connect(Host, Port, [], SslOpts, UseSSL, 2000, Debug) of
        {ok, Sock, _SSL} -> gen_tcp:close(Sock), reconnect(State#oraclient{env = Opts});
        {error, _} -> try_redirect(Rest, State)
    end.

parse_redirect_addresses(Data) ->
    case re:run(Data, "\\(ADDRESS=\\(PROTOCOL=(TCP|TCPS)\\)\\(HOST=([^)]+)\\)\\(PORT=(\\d+)\\)\\)", [global, {capture, all_but_first, list}, caseless]) of
        {match, Matches} ->
            lists:map(fun([_Proto, Host, PortStr]) -> {Host, list_to_integer(PortStr)} end, Matches);
        nomatch -> []
    end.
