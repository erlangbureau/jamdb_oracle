-module(jamdb_oracle_tns_decoder).

%% API
-export([decode_packet/2]).
-export([decode_token/2]).
-export([decode_helper/3]).

-include("jamdb_oracle.hrl").

%% API
decode_packet(<<PacketSize:16, _PacketFlags:16, ?TNS_DATA, _Flags:8, 0:16, _DataFlags:16, Rest/bits>>, Length) ->
    BodySize = PacketSize-10,
    case Rest of
        <<PacketBody:BodySize/binary, Rest2/bits>> when PacketSize =:= Length-37; PacketSize =:= Length-81 ->
            {error, more, PacketBody, Rest2};
        <<PacketBody:BodySize/binary, Rest2/bits>> ->
            {ok, ?TNS_DATA, PacketBody, Rest2};
        _ ->
            {error, more}
    end;
decode_packet(<<_PacketSize:16, _PacketFlags:16, ?TNS_REDIRECT, _Flags:8, 0:16, _Length:16, Rest/bits>>, Length) ->
    case decode_packet(Rest, Length) of
        {ok, ?TNS_DATA, PacketBody, <<>>} ->
            {ok, ?TNS_REDIRECT, PacketBody, <<>>};
        _ ->
            {error, more}
    end;
decode_packet(<<PacketSize:16, _PacketFlags:16, Type, _Flags:8, 0:16, Rest/bits>>, _Length) ->
    BodySize = PacketSize-8,
    case Rest of
        <<PacketBody:BodySize/binary, Rest2/bits>> ->
            {ok, Type, PacketBody, Rest2};
        _ ->
            {error, more}
    end;
decode_packet(_,_) ->
    {error, socket}.

decode_token(<<Token, Data/binary>>, Acc) ->
    case Token of
        ?TTI_DCB -> decode_token(dcb, Data, Acc);
        ?TTI_IOV -> decode_token(iov, Data, Acc);
        ?TTI_RXH -> decode_token(rxh, Data, Acc);
        ?TTI_RXD -> decode_token(rxd, Data, Acc);
        ?TTI_BVC -> decode_token(bvc, Data, Acc);
        ?TTI_LOB -> decode_token(lob, Data, Acc);
        ?TTI_RPA -> decode_token(rpa, Data, Acc);
        ?TTI_OER -> decode_token(oer, Data, Acc);
        ?TTI_STA -> {ok, Acc};     %tran
        ?TTI_FOB -> {error, fob};  %return
        _ -> 
            {error, <<Token, (hd(binary:split(Data, <<0>>)))/binary>>}
    end;
decode_token(net, {Data, EnvOpts}) ->
    Values = lists:map(fun(L) -> list_to_tuple(string:tokens(L, "=")) end,
             string:tokens(binary_to_list(hd(binary:split(Data, <<0>>))), "()")),
    Host = proplists:get_value("HOST", Values),
    Port = proplists:get_value("PORT", Values),
    {ok, [{host, Host}, {port, list_to_integer(Port)}]++EnvOpts};
decode_token(rpa, Data) ->
    Num = decode_ub4(Data),
    Values = decode_keyval(decode_next(Data), Num, []),
    SessKey = get_value("AUTH_SESSKEY", Values),
    Salt = get_value("AUTH_VFR_DATA", Values),
    Type = get_value("AUTH_VFR_DATA", Values, 3),
    DerivedSalt = get_value("AUTH_PBKDF2_CSK_SALT", Values),
    Logon = #logon{type=Type, auth=SessKey, salt=Salt, der_salt=DerivedSalt},
    case get_value("AUTH_SVR_RESPONSE", Values) of
        undefined ->
            {?TTI_SESS, Logon};
        Resp ->
            Value = get_value("AUTH_VERSION_NO", Values),
            SessId = get_value("AUTH_SESSION_ID", Values),
            Ver = decode_version(Value),
            {?TTI_AUTH, Resp, Ver, SessId}
    end;
decode_token(oac, Data) ->
    DataType = decode_ub1(Data),
    A = decode_next(ub1,Data),     %data type
    B = decode_next(ub1,A),        %flg
    C = decode_next(ub1,B),        %pre
    Scale = decode_ub2(C),
    D = decode_next(ub2,C),        %data scale
    Length = decode_ub4(D),
    E = decode_next(ub4,D),        %max data length
    F = decode_next(ub4,E),        %mal
    G = decode_next(ub4,F),        %fl2
    J = decode_next(dalc,G),       %toid
    K = decode_next(ub2,J),        %vsn
    Charset = decode_ub2(K),
    L = decode_next(ub2,K),        %charset
    M = decode_next(ub1,L),        %form of use
    N = decode_next(ub4,M),        %mxlc
    {N, DataType, Length, Scale, Charset};
decode_token(wrn, Data) ->
    A = decode_next(ub2,Data),     %retCode
    Length = decode_ub2(A),
    B = decode_next(ub2,A),        %warnLength
    C = decode_next(ub2,B),        %warnFlag
    decode_next(ub1, C, Length).   %warnMsg

decode_token(dcb, Data, {Ver, _RowFormat, Type}) when is_atom(Type) ->
    {A, RowFormat} = decode_token(dcb, decode_next(Data), Ver),
    decode_token(A, {0, RowFormat, []});
decode_token(dcb, Data, Ver) ->
    A = decode_next(ub4,Data),
    Num = decode_ub4(A),
    B = decode_next(ub4,A),
    C =
    case Num of
        0 -> B;
        _ -> decode_next(ub1,B)
    end,
    {RowFormat, D} = decode_token(uds, C, {Ver, [], Num}),
    E = decode_next(dalc,D),
    F = decode_next(ub4,E),
    G = decode_next(ub4,F),
    J = decode_next(ub4,G),
    K = decode_next(ub4,J),
    L =
    case Ver of
        10 -> K;
        _ -> decode_next(dalc,K)
    end,
    {L, RowFormat};
decode_token(uds, Data, {_Ver, RowFormat, 0}) ->
    {lists:reverse(RowFormat), Data};
decode_token(uds, Data, {Ver, RowFormat, Num}) ->
    {A, DataType, Length, Scale, Charset} = decode_token(oac, Data),
    B = decode_next(ub1,A),        %nullable
    C = decode_next(ub1,B),
    Column = decode_dalc(C),
    D = decode_next(dalc,C),       %column name
    E = decode_next(dalc,D),       %schema name
    F = decode_next(dalc,E),       %type name
    G = decode_next(ub2,F),
    J =
    case Ver of
        10 -> G;
        _ -> decode_next(ub4,G)
    end,
    decode_token(uds, J, {Ver, [#format{column_name=list_to_binary(Column),
    data_type=DataType,data_length=Length,data_scale=Scale,charset=Charset}|RowFormat], Num-1});
decode_token(rxh, Data, {Cursor, RowFormat, Type}) when is_atom(Type) ->
    A = decode_next(rxh,Data),
    decode_token(A, {Cursor, RowFormat, [0], []});
decode_token(rxh, Data, {Cursor, RowFormat, Rows}) ->
    A = decode_next(ub1,Data),
    B = decode_next(ub2,A),
    C = decode_next(ub2,B),
    D = decode_next(ub2,C),
    E = decode_next(ub2,D),
    Bitvec = decode_dalc(E),
    {Bvc, _Num} =
    case length(Bitvec) of
        0 -> {[0], 0};
        _ -> decode_bvc(list_to_binary(Bitvec), RowFormat, [])
    end,
    F = decode_next(rxh,Data),
    decode_token(F, {Cursor, RowFormat, Bvc, Rows});
decode_token(iov, Data, {Ver, RowFormat, Type}) when is_atom(Type) ->
    A = decode_next(ub1,Data),
    Num = decode_ub2(A),
    <<Mode:Num/binary, Rest/bits>> = decode_next(rxh,Data),
    case binary:matches(Mode,[<<16>>,<<48>>]) of
        [] -> decode_token(Rest, {0, [], []});               %proc_result
        _ ->
            Bind = lists:zip(binary_to_list(Mode), RowFormat),
            decode_token(Rest, {Ver, [decode_param(B) || B <- Bind], Type})
    end;
decode_token(rxd, Data, {Ver, _RowFormat, fetch}) ->
    {A, CursorRowFormat} = decode_token(dcb, decode_next(ub1,Data), Ver),
    Cursor = decode_ub4(A),
    B = decode_next(ub4,A),
    {{Cursor, CursorRowFormat}, decode_next(ub2,B)};
decode_token(rxd, Data, {Ver, _RowFormat, cursor}) ->
    {A, _CursorRowFormat} = decode_token(dcb, decode_next(ub1,Data), Ver),
    {decode_ub4(A), decode_next(ub4,A)};
decode_token(rxd, Data, {Ver, RowFormat, Type}) when is_atom(Type) ->
    case decode_data(Data, [], {[], RowFormat, Ver, Type}) of
    	{{Cursor, CursorRowFormat}, A} ->
            decode_token(A, {Cursor, CursorRowFormat, []});  %fetch cursor
        {Rows, A} -> decode_token(A, {0, RowFormat, Rows})   %proc_result
    end;
decode_token(rxd, Data, {Cursor, RowFormat, Bvc, Rows}) ->
    LastRow = last(Rows),
    {A, Row} = decode_rxd(Data, RowFormat, 1, Bvc, LastRow, []),
    decode_token(A, {Cursor, RowFormat, Bvc, Rows++[Row]});
decode_token(bvc, Data, {Cursor, RowFormat, _Bvc, Rows}) ->
    A = decode_next(ub2,Data),
    {Bvc, Num} = decode_bvc(A, RowFormat, []),
    B = decode_next(ub1, A, Num),
    decode_token(B, {Cursor, RowFormat, Bvc, Rows});
decode_token(lob, Data, _Loc) ->
    try decode_chr(Data) of
        Value -> {ok, Value}
    catch
        error:_ -> {ok, [eof]}
    end;
decode_token(rpa, Data, []) ->
    {ok, [decode_ub4(Data)]};
decode_token(rpa, Data, {_Ver, RowFormat, Type}) when is_atom(Type) ->
    decode_token(rpa, Data, {0, RowFormat, []});
decode_token(rpa, Data, {0, RowFormat, Rows}) ->
    Cursor =
    case decode_ub2(Data) of
        0 -> 0;
        _ ->
            A = decode_next(ub2,Data),
            B = decode_next(ub4, A),
            C = decode_next(ub4, B),
            decode_ub4(C)
    end,
    D = decode_next(rpa,Data),
    decode_token(D, {Cursor, RowFormat, Rows});
decode_token(rpa, Data, {Cursor, RowFormat, _Bvc, Rows}) ->
    decode_token(rpa, Data, {Cursor, RowFormat, Rows});
decode_token(rpa, Data, {Cursor, RowFormat, Rows}) ->
    A = decode_next(rpa,Data),
    decode_token(A, {Cursor, RowFormat, Rows});
decode_token(oer, Data, []) ->
    decode_token(oer, Data, {0, [], []});
decode_token(oer, Data, {_Ver, RowFormat, Type}) when is_atom(Type) ->
    decode_token(oer, Data, {0, RowFormat, []});
decode_token(oer, Data, {Cursor, RowFormat, _Bvc, Rows}) ->
    decode_token(oer, Data, {Cursor, RowFormat, Rows});
decode_token(oer, Data, {Cursor, RowFormat, Rows}) ->
    A = decode_next(ub2,Data),
    B = decode_next(ub2,A),              %Sequence Number
    RowNumber = decode_ub4(B),
    C = decode_next(ub4,B),              %Current Row Number
    RetCode = decode_ub2(C),
    RetFormat =
    case lists:member(RetCode, [0,1403]) of
        true ->
            D = decode_next(ub2,C),
            E = decode_next(ub2,D),
            F = decode_next(ub2,E),
            {decode_ub2(F), RowFormat};  %defcols
        false ->
            D = decode_next(ub2,C),      %Returned Code
            E = decode_next(ub2,D),      %Array Element w/error
            F = decode_next(ub2,E),      %Array Element errno
            G = decode_next(ub2,F),      %Current Cursor ID
            H = decode_next(ub2,G),      %Error Position 
            I = decode_next(ub1,H),      %SQL command type 
            J = decode_next(ub2,I),      %Fatal 
            K = decode_next(ub2,J),      %Various flags
            L = decode_next(ub2,K),      %User cursor options
            M = decode_next(ub1,L),      %UPI parameter that generated the error
            N = decode_next(ub1,M),      %Warning flags
            O = decode_next(ub4,N),      %Row ID rba
            P = decode_next(ub2,O),      %partitionid
            Q = decode_next(ub1,P),      %tableid
            R = decode_next(ub4,Q),      %blocknumber
            S = decode_next(ub2,R),      %slotnumber
            T = decode_next(ub4,S),      %Operating System Error
            U = decode_next(ub1,T),      %Statement number
            V = decode_next(ub1,U),      %Procedure call number
            W = decode_next(ub2,V),      %Pad
            X = decode_next(ub4,W),      %Successful iterations
            {Cursor, decode_dalc(X)}
    end,
    {RetCode, RowNumber, Cursor, RetFormat, Rows}.

decode_next(<<Length,Rest/bits>>) ->
    <<_Data:Length/binary,Rest2/bits>> = Rest,
    Rest2.

decode_next(_Type, Data, 0) ->
    Data;
decode_next(Type, Data, I) when is_integer(I) ->
    decode_next(Type, decode_next(Type, Data), I-1);
decode_next(chr, <<0,Rest/bits>>, I) when is_binary(I) ->
    Rest;
decode_next(chr, Data, I) when is_binary(I) ->
    decode_next(chr, decode_next(Data), I).

decode_next(Length,Data) when is_integer(Length) ->
    <<_Data:Length/binary,Rest/bits>> = Data,
    Rest;
decode_next(ub1,<<_Data:8,Rest/bits>>) ->
    Rest;
decode_next(ub2,Data) ->
    decode_next(ub4,Data);
decode_next(ub4,<<0,Rest/bits>>) ->
    Rest;
decode_next(ub4,<<I,_Rest/bits>> = Data) when I band 128 =:= 0 ->
    decode_next(Data);
decode_next(ub4,<<_I,_N:8,Rest/bits>>) ->
    Rest;
decode_next(dalc,<<0,Rest/bits>>) ->
    Rest;
decode_next(dalc,<<254,Rest/bits>>) ->
    decode_next(chr,Rest,<<>>);
decode_next(dalc,<<Length,Rest/bits>>) ->
    <<_Data:Length/binary,Rest2/bits>> = Rest,
    decode_next(Rest2);
decode_next(chr,<<254,Rest/bits>>) ->
    decode_next(chr,Rest,<<>>);
decode_next(chr,Data) ->
    decode_next(Data);
decode_next(keyword,Data) ->
    A =
    case decode_ub2(Data) of
        0 -> decode_next(ub2,Data);
        _ -> decode_next(decode_next(ub2,Data))
    end,
    B =
    case decode_ub2(A) of
        0 -> decode_next(ub2,A);
        _ -> decode_next(decode_next(ub2,A))
    end,
    decode_next(ub2,B);
decode_next(rxh,Data) ->
    A = decode_next(ub1,Data),     %Flags
    B = decode_next(ub2,A),        %Number of Requests
    C = decode_next(ub2,B),        %Iteration Number
    D = decode_next(ub2,C),        %Num. Iterations this time
    E = decode_next(ub2,D),        %UAC buffer length
    F = decode_next(dalc,E),       %Bitvec
    decode_next(dalc,F);
decode_next(rpa,Data) ->
    I = decode_ub2(Data),
    A = decode_next(ub2,Data),
    B = decode_next(ub4, A, I),
    M = decode_ub2(B),
    C = decode_next(ub2,B),
    D = decode_next(M,C),
    N = decode_ub2(D),
    E = decode_next(ub2,D),
    F = decode_next(keyword, E, N),
    R = decode_ub4(F),
    G = decode_next(ub4,F),
    decode_next(R,G).

decode_rxd(Data, [], _I, _Bvc, _LastRow, Values) ->
    {Data, lists:reverse(Values)};
decode_rxd(Data, _RowFormat, _I, [], LastRow, _Values) ->
    {Data, LastRow};
decode_rxd(Data, [ValueFormat|RestRowFormat], I, [0], LastRow, Values) ->
    {Value, RestData} = decode_data(Data, ValueFormat),
    decode_rxd(RestData, RestRowFormat, I+1, [0], LastRow, [Value|Values]);
decode_rxd(Data, [ValueFormat|RestRowFormat], I, Bvc, LastRow, Values) ->
    {Value, RestData} = 
    case lists:member(I, Bvc) of
        true -> decode_data(Data, ValueFormat);
        false -> {lists:nth(I, LastRow), Data}
    end,
    decode_rxd(RestData, RestRowFormat, I+1, Bvc, LastRow, [Value|Values]).

decode_bvc(Data, RowFormat, Acc) ->
    Length = length(RowFormat),
    Num = Length div 8 + 
    case Length rem 8 of
        0 -> 0;
        _ -> 1
    end,
    {decode_bvc(Data, Acc, Num, 0), Num}.

decode_bvc(_Data, Acc, 8, _I) when is_tuple(Acc) ->
    Acc;
decode_bvc(Data, Acc, Num, I) when is_tuple(Acc) ->
    Bvc =
    case (Data band (1 bsl Num)) of
        0 -> Acc;
        _ -> erlang:append_element(Acc, I * 8 + Num + 1)
    end,
    decode_bvc(Data, Bvc, Num+1, I);    
decode_bvc(_Data, Acc, 0, _I) when is_list(Acc) ->
    Acc;
decode_bvc(Data, Acc, Num, I) when is_list(Acc) ->
    Bvc = decode_bvc(decode_ub1(Data), {}, 0, I),
    decode_bvc(decode_next(ub1,Data), Acc++tuple_to_list(Bvc), Num-1, I+1).

decode_data(Data, Values, {[], [], _Ver, _Type}) ->
    {lists:reverse(Values), Data};
decode_data(Data, _Values, {DefCol, [], _Ver, _Type}) ->
    {DefCol, Data};
decode_data(Data, Values, {DefCol, [#format{param=in}|RestRowFormat], Ver, Type}) ->
    decode_data(Data, Values, {DefCol, RestRowFormat, Ver, Type});
decode_data(Data, Values, {_DefCol, [#format{data_type=?TNS_TYPE_REFCURSOR}|RestRowFormat], Ver, Type}) ->
    {DefCol, Bin} = decode_token(rxd, Data, {Ver, [], fetch}),
    decode_data(Bin, Values, {DefCol, RestRowFormat, Ver, Type});
decode_data(Data, Values, {DefCol, [ValueFormat|RestRowFormat], Ver, Type=return}) ->
    Num = decode_ub4(Data),
    {Value, RestData} = decode_data(decode_next(ub4,Data), ValueFormat, [], Num, Type),
    decode_data(RestData, [Value|Values], {DefCol, RestRowFormat, Ver, Type});
decode_data(Data, Values, {DefCol, [ValueFormat|RestRowFormat], Ver, Type=block}) ->
    {Value, RestData} = decode_data(Data, ValueFormat),
    decode_data(decode_next(ub2,RestData), [Value|Values], {DefCol, RestRowFormat, Ver, Type}).

decode_data(Data, _ValueFormat, Values, 0, _Type) ->
    {lists:reverse(Values), Data};
decode_data(Data, ValueFormat, Values, Num, Type) ->
    {Value, RestData} = decode_data(Data, ValueFormat, Num, Type),
    decode_data(decode_next(ub2,RestData), ValueFormat, [Value|Values], Num-1, Type).

decode_data(Bin, #format{data_type=DataType}, _Num, Type=return) when ?IS_LONG_TYPE(DataType) ->
    decode_long(Bin, Type);
decode_data(Bin, DataType, _Num, _Type) ->
    decode_data(Bin, DataType).

decode_data(Data, #format{data_type=DataType, data_length=0}) when ?IS_NULL_TYPE(DataType) ->
    {null, Data};
decode_data(<<0, Rest/bits>>, #format{data_type=DataType}) when ?IS_NULL_TYPE(DataType) ->
    {null, Rest};
decode_data(Data, #format{data_type=DataType, charset=Charset}=ValueFormat)
    when Charset =:= ?AL16UTF16_CHARSET; Charset =:= ?AL32UTF8_CHARSET, DataType =:= ?TNS_TYPE_CLOB ->
    {Value, RestData} = decode_data(Data, ValueFormat#format{charset=?UTF8_CHARSET}),
    {binary_to_list(unicode:characters_to_binary(list_to_binary(Value), utf16)), RestData};
decode_data(Data, #format{data_type=DataType}) when ?IS_CHAR_TYPE(DataType); ?IS_RAW_TYPE(DataType) ->
    {decode_value(Data, DataType), decode_next(chr,Data)};
decode_data(Data, #format{data_type=DataType, data_scale=Scale}) when ?IS_NUMBER_TYPE(DataType) ->
    <<Length, Bin:Length/binary, Rest/binary>> = Data,
    {{lsc(decode_number(Bin), Scale)}, Rest};
decode_data(Data, #format{data_type=DataType}) when ?IS_FIXED_TYPE(DataType) ->
    <<Length, Bin:Length/binary, Rest/binary>> = Data,
    {decode_value(Bin, DataType), Rest};
decode_data(Data, #format{data_type=?TNS_TYPE_REFCURSOR}) ->
    {_Value, RestData} = decode_token(rxd, Data, {0, [], cursor}),
    {null, RestData};
decode_data(Data, #format{data_type=DataType}) ->
    decode_value(Data, DataType).

decode_value(Bin, DataType) when ?IS_CHAR_TYPE(DataType) ->
    decode_chr(Bin);
decode_value(Bin, DataType) when ?IS_RAW_TYPE(DataType) ->
    decode_chr(Bin);
decode_value(Bin, DataType) when ?IS_NUMBER_TYPE(DataType) ->
    {decode_number(Bin)};
decode_value(Bin, DataType) when ?IS_BINARY_TYPE(DataType) ->
    {decode_binary(Bin)};
decode_value(Bin, DataType) when ?IS_DATE_TYPE(DataType) ->
    decode_date(Bin);
decode_value(Bin, DataType) when ?IS_INTERVAL_TYPE(DataType) ->
    decode_interval(Bin);
decode_value(Bin, DataType) when ?IS_ROWID_TYPE(DataType) ->
    decode_rowid(Bin);
decode_value(Bin, DataType) when ?IS_LONG_TYPE(DataType) ->
    decode_long(Bin);
decode_value(Bin, DataType) when DataType =:= ?TNS_TYPE_UROWID ->
    decode_urowid(Bin);
decode_value(Bin, DataType) when DataType =:= ?TNS_TYPE_CLOB  ->
    decode_clob(Bin);
decode_value(Bin, DataType) when DataType =:= ?TNS_TYPE_BLOB ->
    decode_blob(Bin);
decode_value(Bin, DataType) when DataType =:= ?TNS_TYPE_ADT ->
    decode_adt(Bin);
decode_value(Bin, _DataType) ->
    decode_value(Bin).

decode_value(Data) ->
    A = decode_next(ub4,Data),
    Value = decode_chr(A),
    {Value, decode_next(chr,A)}.

decode_param({Data, #format{param=in}=ValueFormat}) when Data =/= 32 ->
    ValueFormat#format{param=out};
decode_param({_Data, ValueFormat}) ->
    ValueFormat.

decode_keyval(_Data,0,Acc) ->
    Acc;
decode_keyval(Data,Num,Acc) ->
    {Key, A} =
    case decode_ub4(Data) of
	0 -> {undefined, decode_next(Data)};
	_ ->
	    B = decode_next(Data),
	    {decode_chr(B), decode_next(chr,B)}
    end,
    {Value, C} =
    case decode_ub4(A) of
	0 -> {undefined, decode_next(A)};
	_ ->
	    D = decode_next(A),
	    {decode_chr(D), decode_next(chr,D)}
    end,
    NbPair = decode_ub4(C),
    E = decode_next(C),
    decode_keyval(E,Num-1,[{Key,Value,NbPair}|Acc]).

decode_ub1(<<Data:8,_Rest/bits>>) ->
    Data.

decode_ub2(Data) ->
    decode_ub4(Data).

decode_ub4(<<0,_Rest/bits>>) -> 0;
decode_ub4(<<I,Rest/bits>>) when I band 128 =:= 0 ->
    <<Data:I/binary,_Rest2/bits>> = Rest,
    binary:decode_unsigned(Data);
decode_ub4(<<_I,N:8,_Rest/bits>>) -> -N.

decode_dalc(<<0,_Rest/bits>>) -> [];
decode_dalc(<<254,Rest/bits>>) ->
    decode_chr(Rest, <<>>);
decode_dalc(<<Length,Rest:Length/binary>>) ->
    binary_to_list(Rest);
decode_dalc(Data) ->
    decode_chr(decode_next(ub4,Data)).

decode_chr(<<254,Rest/bits>>) ->
    decode_chr(Rest, <<>>);
decode_chr(<<Length,Rest/bits>>) ->
    <<Data:Length/binary,_Rest2/bits>> = Rest,
    binary_to_list(Data).

decode_chr(<<0,_Rest/bits>>, Acc) ->
    binary_to_list(Acc);
decode_chr(<<Length,Rest/bits>>, Acc) ->
    <<Data:Length/binary,Rest2/bits>> = Rest,
    decode_chr(Rest2, <<Acc/binary, Data/binary>>).

decode_number(<<128>>) -> 0;
decode_number(Data) ->
    {N, [I|L]} = lnxfmt(binary_to_list(Data)),
    H = length(L),
    N *
    case (I + 1) > (H - 1) of
        true ->  lnxsni([I|L],H);
        false -> lnxnur([I|L],H)
    end.

lnxsni([I|L],20) ->
    lnxnur(L,I,0);
lnxsni(L,I) ->
    lnxsni(L++[0],I+1).

lnxnur([H|L],I) ->
    lnxnur(L,I,0) / lnxnur(1,I-H-1);
lnxnur(N,0) when is_integer(N) ->
    N;
lnxnur(N,I) when is_integer(N) ->
    lnxnur(N * 100, I-1).

lnxnur([],0,Acc) ->
    Acc;
lnxnur([H|_L],0,Acc) ->
    Acc * 100 + H;
lnxnur([H|L],I,Acc) ->
    lnxnur(L,I-1,Acc * 100 + H).

lnxneg([102]) -> [];
lnxneg([H|T]) -> [H|lnxneg(T)].

lnxfmt([I|L]) when I band 128 =:= 0 ->
    {-1, [(((I bxor 255) band 127) - 65)|[ 101-N || N <- lnxneg(L)]]};
lnxfmt([I|L]) ->
    {1, [((I band 127) - 65)|[ N-1 || N <- L]]}.

lsc(I, 0) when I-trunc(I) =:= 0.0 -> trunc(I);
lsc(I, 0) -> I;
lsc(I, _S) -> I / 1.

decode_binary(<<I,_Rest/binary>> = Data) when I band 128 =:= 0 ->
    Length = byte_size(Data),
    <<Value:Length/float-unit:8>> = << <<(B bxor 255)>> || <<B>> <= Data >>,
    Value;
decode_binary(<<I,Rest/binary>> = Data) ->
    Length = byte_size(Data),
    <<Value:Length/float-unit:8>> = <<(I band 127),Rest/binary>>,
    Value.

decode_date(<<Century,Year,Mon,Day,Hour,Min,Sec>>) ->
    {{(Century - 100) * 100 + (Year - 100),(Mon),(Day)},
     {(Hour - 1),(Min - 1),(Sec - 1)}};
decode_date(<<Data:7/binary,Ms:4/integer-unit:8>>) ->
    {Date,{Hour,Min,Sec}} = decode_date(Data),
    {Date,{Hour,Min,Sec + Ms / 1.0e9}};
decode_date(<<Data:11/binary,H,M>>) ->
    erlang:append_element(decode_date(Data),
    case (H band -128) of
        0 -> ltz(H - 20);
        _ ->
            Zoneid = ((H band 127) bsl 6) + ((M band 252) bsr 2),
            try lists:nth(Zoneid, [0,-14,-13,-12,-11,-10,-9,-8,-7,-6,-5,-4,-3,-2,-1,1,2,3,4,5,6,7,8,9,10,11,12]) of
                Hour -> ltz(Hour)
            catch
                error:_ -> case proplists:get_value(Zoneid, ?ZONEIDMAP) of
                               undefined -> {Zoneid};
                               {Region, Zone} -> lists:nth(Region, ?REGION)++"/"++Zone
                           end
            end
    end).

decode_interval(<<Year:4/integer-unit:8,Mon>>) ->
    lym(Year - 2147483648, Mon - 60);
decode_interval(<<Day:4/integer-unit:8,Hour,Min,Sec,Ms:4/integer-unit:8>>) ->
    lds(Day - 2147483648, Hour - 60, Min - 60, Sec - 60, (Ms - 2147483648) / 1.0e9).

ltz(I) when I < 0 -> ltz(abs(I), "-");
ltz(I) -> ltz(abs(I), "+").

ltz(I, S) when I < 10 -> S++"0"++integer_to_list(I)++":00";
ltz(I, S) -> S++integer_to_list(I)++":00".

lym(I, M) when I < 0; M < 0 -> "-"++lym(abs(I), abs(M));
lym(I, M) -> integer_to_list(abs(I))++"-"++integer_to_list(abs(M)).

lds(I, H, M, S, Ms) when I < 0; H < 0; M < 0; S < 0; Ms < 0 ->
    {-1 * abs(I), {abs(H), abs(M), abs(S) + abs(Ms)}};
lds(I, H, M, S, Ms) ->
    {abs(I), {abs(H), abs(M), abs(S) + abs(Ms)}}.

last([]) -> [];
last([E|Es]) -> last(E, Es).

last(_, [E|Es]) -> last(E, Es);
last(E, []) -> E.

get_value(Key, L) -> get_value(Key, L, 2).

get_value(_Key, [], _N) ->
    undefined;
get_value(Key, [P | Ps], N) ->
    if element(1, P) =:= Key -> element(N, P); true -> get_value(Key, Ps, N) end.

%decode_version(I) when is_integer(I) ->
%    {(I band 4278190080) bsr 24 band 255, (I band 15728640) bsr 20 band 255,
%    (I band 1044480) bsr 12 band 255, (I band 3840) bsr 8 band 255, I band 255};
decode_version(undefined) -> 0;
decode_version(Data) -> list_to_integer(Data) bsr 24.

decode_rowid(Data) ->
    A = decode_next(ub1,Data),
    Objid = decode_ub4(A),
    B = decode_next(ub4,A),
    Partid = decode_ub2(B),
    C = decode_next(ub2,B),
    D = decode_next(ub1,C),
    Blocknum = decode_ub4(D),
    E = decode_next(ub4,D),
    Slotnum = decode_ub2(E),
    F = decode_next(ub2,E),
    {lid(Objid,Partid,Blocknum,Slotnum),F}.

decode_urowid(Data) ->
    A = decode_next(ub4,Data),
    Value = decode_chr(A),
    B = decode_next(chr,A),
    case hd(Value) of
        1 ->
            <<Objid:4/integer-unit:8,Partid:2/integer-unit:8,
            Blocknum:4/integer-unit:8,Slotnum:2/integer-unit:8,
            _Rest/bits>> = list_to_binary(tl(Value)),
            {lid(Objid,Partid,Blocknum,Slotnum),B};
        _ -> {Value, B}
    end.

lid(O,P,B,S) -> lid(O,6,[])++lid(P,3,[])++lid(B,6,[])++lid(S,3,[]).

lid(_N,0,Acc) -> Acc;
lid(N,I,Acc) ->
    H = lists:nth((N band 63)+1,
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
    lid(N bsr 6 band 67108863,I-1,[H|Acc]).

decode_clob(Data) ->
    A = decode_next(ub4,Data),
    case decode_ub1(A) of
        114 -> {[], decode_next(A)};   %LobLocator
        _ -> decode_clob_value(Data)
    end.

decode_clob_value(Data) ->
    A = decode_next(ub4,Data),
    B = decode_next(ub4,A),        %LobSize
    C = decode_next(ub4,B),        %LobChunkSize
    Vary = decode_ub1(C),
    D = decode_next(ub1,C),        %ClobDBVary
    E =
    case Vary of
        1 -> decode_next(ub2,D);   %ClobCharset
        _ -> D
    end,
    F = decode_next(ub1,E),        %ClobFormOfUse
    Value = decode_chr(F),
    G = decode_next(chr,F),
    {Value, decode_next(G)}.

decode_blob(Data) ->
    A = decode_next(ub4,Data),
    case decode_ub1(A) of
        114 -> {[], decode_next(A)};   %LobLocator
        _ -> decode_blob_value(Data)
    end.

decode_blob_value(Data) ->
    A = decode_next(ub4,Data),
    B = decode_next(ub4,A),        %LobSize
    C = decode_next(ub4,B),        %LobChunkSize
    Value = decode_chr(C),
    D = decode_next(chr,C),
    {Value, decode_next(D)}.

decode_adt(Data) ->
    A = decode_next(ub4,Data),
    B = decode_next(chr,A),
    C = decode_next(chr,B),
    D = decode_next(chr,C),
    E = decode_next(ub2,D),
    Length = decode_ub4(E),
    F = decode_next(ub4,E),
    G = decode_next(ub2,F),
    case Length of
        0 -> {null, G};
        _ ->
            Value = decode_chr(G),
            {Value, decode_next(chr,G)}
    end.

decode_long(<<0, Rest/bits>>, _Type) ->
    {null, Rest};
decode_long(Data, _Type) ->
    Value = decode_chr(Data),
    {Value, decode_next(chr,Data)}.

decode_long(<<0, Rest/bits>>) ->
    {null, decode_next(ub2,Rest,2)};
decode_long(Data) ->
    Value = decode_chr(Data),
    A = decode_next(chr,Data),
    {Value, decode_next(ub2,A,2)}.

decode_helper(param, Data, Format) -> decode_token(oac, ?ENCODER:encode_token(oac, Data, Format));
decode_helper(tz, Data, _) -> ltz(Data);
decode_helper(dump, Data, DataType) -> decode_value(Data, DataType).
