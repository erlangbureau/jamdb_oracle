-module(jamdb_oracle_tns_decoder).

%% API
-export([decode_packet/2]).
-export([decode_token/2]).
-export([decode_helper/2]).

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
	?TTI_STA -> {ok, Acc};  %tran
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
    SessKey = proplists:get_value("AUTH_SESSKEY", Values),
    Salt = proplists:get_value("AUTH_VFR_DATA", Values),
    DerivedSalt = proplists:get_value("AUTH_PBKDF2_CSK_SALT", Values),
    case proplists:get_value("AUTH_SVR_RESPONSE", Values) of
        undefined ->
            {?TTI_SESS, SessKey, Salt, DerivedSalt};
        Resp ->
            Value = proplists:get_value("AUTH_VERSION_NO", Values),
	    SessId = proplists:get_value("AUTH_SESSION_ID", Values),
            Ver = decode_version(Value),
            {?TTI_AUTH, Resp, Ver, SessId}
    end;
decode_token(oac, Data) ->
    DataType = decode_ub1(Data),
    Rest2 = decode_next(ub1,Data),	%%data type
    Rest3 = decode_next(ub1,Rest2),     %%flg
    Rest4 = decode_next(ub1,Rest3),     %%pre
    Scale = decode_ub2(Rest4),
    Rest5 = decode_next(ub2,Rest4),	%%data scale
    Length = decode_ub4(Rest5),
    Rest6 = decode_next(ub4,Rest5),	%%max data lenght
    Rest7 = decode_next(ub4,Rest6),     %%mal
    Rest8 = decode_next(ub4,Rest7),     %%fl2
    Rest9 = decode_next(dalc,Rest8),    %%toid
    Rest10 = decode_next(ub2,Rest9),    %%vsn
    Charset = decode_ub2(Rest10),
    Rest11 = decode_next(ub2,Rest10),	%%charset
    Rest12 = decode_next(ub1,Rest11),	%%form of use
    Rest13 = decode_next(ub4,Rest12),   %%mxlc
    {Rest13, DataType, Length, Scale, Charset};
decode_token(wrn, Data) ->
    Rest2 = decode_next(ub2,Data),	%%retCode
    Rest3 = decode_next(ub2,Rest2),	%%warnLength
    Rest4 = decode_next(ub2,Rest3),	%%warnFlag
    decode_next(chr, Rest4).            %%errorMsg

decode_token(dcb, Data, {Ver, _RowFormat, Type}) when is_atom(Type) ->
    {Rest2, RowFormat} = decode_token(dcb, decode_next(Data), Ver),
    decode_token(Rest2, {0, RowFormat, []});
decode_token(dcb, Data, Ver) ->
    Rest3 = decode_next(ub4,Data),
    Num = decode_ub4(Rest3),
    Rest4 = decode_next(ub4,Rest3),
    Rest5 =
    case Num of
	0 -> Rest4;
	_ -> decode_next(ub1,Rest4)
    end,
    {RowFormat, Rest6} = decode_token(uds, Rest5, {Ver, [], Num}),
    Rest7 = decode_next(dalc,Rest6),
    Rest8 = decode_next(ub4,Rest7),
    Rest9 = decode_next(ub4,Rest8),
    Rest10 = decode_next(ub4,Rest9),
    Rest11 = decode_next(ub4,Rest10),
    Rest12 =
    case Ver of
        10 -> Rest11;
        _ -> decode_next(dalc,Rest11)
    end,
    {Rest12, RowFormat};
decode_token(uds, Data, {_Ver, RowFormat, 0}) ->
    {lists:reverse(RowFormat), Data};
decode_token(uds, Data, {Ver, RowFormat, Num}) ->
    {Rest2, DataType, Length, Scale, Charset} = decode_token(oac, Data),
    Rest3 = decode_next(ub1,Rest2),	%%nullable
    Rest4 = decode_next(ub1,Rest3),
    Column = decode_dalc(Rest4),
    Rest5 = decode_next(dalc,Rest4),	%%column name
    Rest6 = decode_next(dalc,Rest5),	%%schema name
    Rest7 = decode_next(dalc,Rest6),	%%type name
    Rest8 = decode_next(ub2,Rest7),
    Rest9 =
    case Ver of
        10 -> Rest8;
        _ -> decode_next(ub4,Rest8)
    end,
    decode_token(uds, Rest9, {Ver, [#format{column_name=list_to_binary(Column),
    data_type=DataType,data_length=Length,data_scale=Scale,charset=Charset}|RowFormat], Num-1});
decode_token(rxh, Data, {Cursor, RowFormat, Type}) when is_atom(Type) ->
    Rest = decode_next(rxh,Data),
    decode_token(Rest, {Cursor, RowFormat, [0], []});
decode_token(rxh, Data, {Cursor, RowFormat, Rows}) ->
    Rest2 = decode_next(ub1,Data),
    Rest3 = decode_next(ub2,Rest2),
    Rest4 = decode_next(ub2,Rest3),
    Rest5 = decode_next(ub2,Rest4),
    Rest6 = decode_next(ub2,Rest5),
    Bitvec = decode_dalc(Rest6),
    {Bvc, _Num} =
    case length(Bitvec) of
        0 -> {[0], 0};
        _ -> decode_bvc(list_to_binary(Bitvec), RowFormat, [])
    end,
    Rest7 = decode_next(rxh,Data),
    decode_token(Rest7, {Cursor, RowFormat, Bvc, Rows});
decode_token(iov, Data, {Ver, RowFormat, Type}) when is_atom(Type) ->
    Rest2 = decode_next(ub1,Data),
    Num = decode_ub2(Rest2),
    <<Mode:Num/binary, Rest3/bits>> = decode_next(rxh,Data),
    case binary:matches(Mode,[<<16>>,<<48>>]) of
        [] -> decode_token(Rest3, {0, [], []});                      %%proc_result
        _ ->
	    Bind = lists:zip(binary_to_list(Mode), RowFormat),
	    decode_token(Rest3, {Ver, [decode_param(B) || B <- Bind], Type})
    end;
decode_token(rxd, Data, {Ver, _RowFormat, fetch}) ->
    {Rest2, CursorRowFormat} = decode_token(dcb, decode_next(ub1,Data), Ver),
    Cursor = decode_ub4(Rest2),
    Rest3 = decode_next(ub4,Rest2),
    {{Cursor, CursorRowFormat}, decode_next(ub2,Rest3)};
decode_token(rxd, Data, {Ver, RowFormat, Type}) when is_atom(Type) ->
    case decode_data(Data, [], {[], RowFormat, Ver, Type}) of
    	{{Cursor, CursorRowFormat}, Rest2} ->
	    decode_token(Rest2, {Cursor, CursorRowFormat, []});      %%fetch cursor
        {Rows, Rest2} -> decode_token(Rest2, {0, RowFormat, Rows})   %%proc_result
    end;
decode_token(rxd, Data, {Cursor, RowFormat, Bvc, Rows}) ->
    LastRow = last(Rows),
    {Rest2, Row} = decode_rxd(Data, RowFormat, 1, Bvc, LastRow, []),
    decode_token(Rest2, {Cursor, RowFormat, Bvc, Rows++[Row]});
decode_token(bvc, Data, {Cursor, RowFormat, _Bvc, Rows}) ->
    Rest2 = decode_next(ub2,Data),
    {Bvc, Num} = decode_bvc(Rest2, RowFormat, []),
    Rest3 = decode_next(ub1, Rest2, Num),
    decode_token(Rest3, {Cursor, RowFormat, Bvc, Rows});
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
	    Rest2 = decode_next(ub2,Data),
	    Rest3 = decode_next(ub4, Rest2),
	    Rest4 = decode_next(ub4, Rest3),
	    decode_ub4(Rest4)
    end,
    Rest5 = decode_next(rpa,Data),
    decode_token(Rest5, {Cursor, RowFormat, Rows});
decode_token(rpa, Data, {Cursor, RowFormat, _Bvc, Rows}) ->
    decode_token(rpa, Data, {Cursor, RowFormat, Rows});
decode_token(rpa, Data, {Cursor, RowFormat, Rows}) ->
    Rest2 = decode_next(rpa,Data),
    decode_token(Rest2, {Cursor, RowFormat, Rows});
decode_token(oer, Data, []) ->
    decode_token(oer, Data, {0, [], []});
decode_token(oer, Data, {_Ver, RowFormat, Type}) when is_atom(Type) ->
    decode_token(oer, Data, {0, RowFormat, []});
decode_token(oer, Data, {Cursor, RowFormat, _Bvc, Rows}) ->
    decode_token(oer, Data, {Cursor, RowFormat, Rows});
decode_token(oer, Data, {Cursor, RowFormat, Rows}) ->
    Rest2 = decode_next(ub2,Data),
    Rest3 = decode_next(ub2,Rest2),             %%Sequence Number
    RowNumber = decode_ub4(Rest3),
    Rest4 = decode_next(ub4,Rest3),             %%Current Row Number
    RetCode = decode_ub2(Rest4),
    RetFormat =
    case lists:member(RetCode, [0,1403]) of
        true ->
            Rest5 = decode_next(ub2,Rest4),
            Rest6 = decode_next(ub2,Rest5),
            Rest7 = decode_next(ub2,Rest6),
	    {decode_ub2(Rest7), RowFormat};     %%defcols
        false ->
            Rest5 = decode_next(ub2,Rest4),	%%Returned Code
            Rest6 = decode_next(ub2,Rest5),	%%Array Element w/error
            Rest7 = decode_next(ub2,Rest6),	%%Array Element errno
            Rest8 = decode_next(ub2,Rest7),	%%Current Cursor ID
            Rest9 = decode_next(ub2,Rest8),	%%Error Position 
            Rest10 = decode_next(ub1,Rest9),	%%SQL command type 
            Rest11 = decode_next(ub2,Rest10),	%%Fatal 
            Rest12 = decode_next(ub2,Rest11),	%%Various flags
            Rest13 = decode_next(ub2,Rest12),	%%User cursor options
            Rest14 = decode_next(ub1,Rest13),	%%UPI parameter that generated the error
            Rest15 = decode_next(ub1,Rest14),	%%Warning flags
            Rest16 = decode_next(ub4,Rest15),	%%Row ID rba
            Rest17 = decode_next(ub2,Rest16),	%%partitionid
            Rest18 = decode_next(ub1,Rest17),	%%tableid
            Rest19 = decode_next(ub4,Rest18),	%%blocknumber
            Rest20 = decode_next(ub2,Rest19),	%%slotnumber
            Rest21 = decode_next(ub4,Rest20),	%%Operating System Error
            Rest22 = decode_next(ub1,Rest21),	%%Statement number
            Rest23 = decode_next(ub1,Rest22),	%%Procedure call number
            Rest24 = decode_next(ub2,Rest23),	%%Pad
            Rest25 = decode_next(ub4,Rest24),	%%Successful iterations
            {Cursor, decode_dalc(Rest25)}
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
    Rest2 =
    case decode_ub2(Data) of
	0 -> decode_next(ub2,Data);
	_ -> decode_next(decode_next(ub2,Data))
    end,
    Rest3 =
    case decode_ub2(Rest2) of
	0 -> decode_next(ub2,Rest2);
	_ -> decode_next(decode_next(ub2,Rest2))
    end,
    decode_next(ub2,Rest3);
decode_next(rxh,Data) ->
    Rest2 = decode_next(ub1,Data),      %%Flags
    Rest3 = decode_next(ub2,Rest2),     %%Number of Requests
    Rest4 = decode_next(ub2,Rest3),     %%Iteration Number
    Rest5 = decode_next(ub2,Rest4),     %%Num. Iterations this time
    Rest6 = decode_next(ub2,Rest5),     %%UAC bufffer length
    Rest7 = decode_next(dalc,Rest6),    %%Bitvec
    decode_next(dalc,Rest7);
decode_next(rpa,Data) ->
    I = decode_ub2(Data),
    Rest2 = decode_next(ub2,Data),
    Rest3 = decode_next(ub4, Rest2, I),
    M = decode_ub2(Rest3),
    Rest4 = decode_next(ub2,Rest3),
    Rest5 = decode_next(M,Rest4),
    N = decode_ub2(Rest5),
    Rest6 = decode_next(ub2,Rest5),
    Rest7 = decode_next(keyword, Rest6, N),
    R = decode_ub4(Rest7),
    Rest8 = decode_next(ub4,Rest7),
    decode_next(R,Rest8).

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
    {DefCol, Rest2} = decode_token(rxd, Data, {Ver, [], fetch}),
    decode_data(Rest2, Values, {DefCol, RestRowFormat, Ver, Type});
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
    {Value, RestData} = decode_data(Data, ValueFormat),
    decode_data(decode_next(ub2,RestData), ValueFormat, [Value|Values], Num-1, Type).    

decode_data(Data, #format{data_type=DataType, data_length=0}) when ?IS_NULL_TYPE(DataType) ->
    {null, Data};
decode_data(<<0, Rest/bits>>, #format{data_type=DataType}) when ?IS_NULL_TYPE(DataType) ->
    {null, Rest};
decode_data(Data, #format{data_type=DataType, charset=Charset}=ValueFormat)
    when Charset =:= ?AL16UTF16_CHARSET; Charset =:= ?AL32UTF8_CHARSET, DataType =:= ?TNS_TYPE_CLOB ->
    {Value, RestData} = decode_data(Data, ValueFormat#format{charset=?UTF8_CHARSET}),
    {xmerl_ucs:to_utf8(xmerl_ucs:from_utf16be(list_to_binary(Value))), RestData};
decode_data(Data, #format{data_type=DataType}) when ?IS_CHAR_TYPE(DataType); ?IS_RAW_TYPE(DataType) ->
    {decode_value(Data, DataType), decode_next(chr,Data)};
decode_data(Data, #format{data_type=DataType, data_scale=Scale}) when ?IS_NUMBER_TYPE(DataType) ->
    <<Length, Bin:Length/binary, Rest/binary>> = Data,
    {{lsc(decode_number(Bin), Scale)}, Rest};
decode_data(Data, #format{data_type=DataType}) when ?IS_FIXED_TYPE(DataType) ->
    <<Length, Bin:Length/binary, Rest/binary>> = Data,
    {decode_value(Bin, DataType), Rest};
decode_data(Data, #format{data_type=DataType}) ->
    decode_value(Data, DataType).

decode_value(Bin, DataType) when ?IS_CHAR_TYPE(DataType); ?IS_RAW_TYPE(DataType) ->
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
    Rest2 = decode_next(ub4,Data),
    Value = decode_chr(Rest2),
    {Value, decode_next(chr,Rest2)}.

decode_param({Data, #format{param=in}=ValueFormat}) when Data =/= 32 ->
    ValueFormat#format{param=out};
decode_param({_Data, ValueFormat}) ->
    ValueFormat.

%decode_len(L, DataType) ->
%    case L of
%        L when DataType =:= ?TNS_TYPE_NUMBER -> 22;
%        L when DataType =:= ?TNS_TYPE_DATE -> 7;
%        L when DataType =:= ?TNS_TYPE_TIMESTAMPTZ -> 13;
%        L -> L
%    end.      

decode_keyval(_Data,0,Acc) ->
    Acc;
decode_keyval(Data,Num,Acc) ->
    {Key, Rest2} =
    case decode_ub4(Data) of
	0 -> {undefined, decode_next(Data)};
	_ ->
	    Rest3 = decode_next(Data),
	    {decode_chr(Rest3), decode_next(chr,Rest3)}
    end,
    {Value, Rest4} =
    case decode_ub4(Rest2) of
	0 -> {undefined, decode_next(Rest2)};
	_ ->
	    Rest5 = decode_next(Rest2),
	    {decode_chr(Rest5), decode_next(chr,Rest5)}
    end,
    Rest6 = decode_next(Rest4),
    decode_keyval(Rest6,Num-1,[{Key,Value}|Acc]).

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
            try lists:nth(Zoneid,
            [0,-14,-13,-12,-11,-10,-9,-8,-7,-6,-5,-4,-3,-2,-1,1,2,3,4,5,6,7,8,9,10,11,12]) of
                Hour -> ltz(Hour)
            catch
                error:_ -> proplists:get_value(Zoneid, ?ZONEIDMAP, {Zoneid})
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

decode_version(undefined) -> 0;
decode_version(Data) ->
    L = integer_to_list(list_to_integer(Data), 16),
    list_to_integer([hd(L)], 16).

decode_rowid(Data) ->
    Rest2 = decode_next(ub1,Data),
    Objid = decode_ub4(Rest2),
    Rest3 = decode_next(ub4,Rest2),
    Partid = decode_ub2(Rest3),
    Rest4 = decode_next(ub2,Rest3),
    Rest5 = decode_next(ub1,Rest4),
    Blocknum = decode_ub4(Rest5),
    Rest6 = decode_next(ub4,Rest5),
    Slotnum = decode_ub2(Rest6),
    Rest7 = decode_next(ub2,Rest6),
    {lid(Objid,Partid,Blocknum,Slotnum),Rest7}.

decode_urowid(Data) ->
    Rest2 = decode_next(ub4,Data),
    Value = decode_chr(Rest2),
    Rest3 = decode_next(chr,Rest2),
    case hd(Value) of
        1 ->
            <<Objid:4/integer-unit:8,Partid:2/integer-unit:8,
            Blocknum:4/integer-unit:8,Slotnum:2/integer-unit:8,
            _Rest4/bits>> = list_to_binary(tl(Value)),
            {lid(Objid,Partid,Blocknum,Slotnum),Rest3};
        _ -> {Value, Rest3}
    end.
    
lid(O,P,B,S) -> lid(O,6,[])++lid(P,3,[])++lid(B,6,[])++lid(S,3,[]).

lid(_N,0,Acc) -> Acc;
lid(N,I,Acc) ->
    H = lists:nth((N band 63)+1,
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
    lid(N bsr 6 band 67108863,I-1,[H|Acc]).

decode_clob(Data) ->
    Rest2 = decode_next(ub4,Data),
    Rest3 = decode_next(ub4,Rest2), %LobSize
    Rest4 = decode_next(ub4,Rest3), %LobChunkSize
    Vary = decode_ub1(Rest4),
    Rest5 = decode_next(ub1,Rest4), %ClobDBVary
    Rest6 =
    case Vary of
        1 -> decode_next(ub2,Rest5); %ClobCharset
        _ -> Rest5
    end,
    Rest7 = decode_next(ub1,Rest6), %ClobFormOfUse
    Value = decode_chr(Rest7),
    Rest8 = decode_next(chr,Rest7),
    {Value, decode_next(Rest8)}.

decode_blob(Data) ->
    Rest2 = decode_next(ub4,Data),
    Rest3 = decode_next(ub4,Rest2), %LobSize
    Rest4 = decode_next(ub4,Rest3), %LobChunkSize
    Value = decode_chr(Rest4),
    Rest5 = decode_next(chr,Rest4),
    {Value, decode_next(Rest5)}.

decode_adt(Data) ->
    Rest2 = decode_next(ub4,Data),
    Rest3 = decode_next(chr,Rest2),
    Rest4 = decode_next(chr,Rest3),
    Rest5 = decode_next(chr,Rest4),
    Rest6 = decode_next(ub2,Rest5),
    Num = decode_ub4(Rest6),
    Rest7 = decode_next(ub4,Rest6),
    Rest8 = decode_next(ub2,Rest7),
    case Num of
        0 -> {null, Rest8};
        _ ->
            Value = decode_chr(Rest8),
            Rest9 = decode_next(chr,Rest8),
            try decode_adt(list_to_binary(Value), 0) of
                Values -> {Values, Rest9}
            catch
                error:_ -> {Value, Rest9}
            end
    end.

decode_adt(<<I,_Rest/bits>>, _Type) when I band 128 =:= 0 ->
    erlang:error(format);
decode_adt(Data, _Type) ->
    Rest2 = decode_next(ub1,Data),
    Rest3 = decode_next(ub1,Rest2),
    {_, Rest4} = lrd(Rest3),
    {_, Rest5} = lrd(Rest4),
    Rest6 = decode_next(ub1,Rest5),
    Rest7 = decode_next(ub1,Rest6),
    {Num, Rest8} = lrd(Rest7),
    decode_adt(Rest8, Num, []).

decode_adt(_Data, 0, Acc) ->
    lists:reverse(Acc);
decode_adt(<<255, Rest/bits>>, Num, Acc) ->
    decode_adt(Rest, Num-1, [null|Acc]);
decode_adt(Data, Num, Acc) ->
    {Length, Rest2} = lrd(Data),
   <<Bin:Length/binary, Rest3/binary>> = Rest2,
    decode_adt(Rest3, Num-1, [binary_to_list(Bin)|Acc]).

lrd(<<I,F,S,T,L, Rest/bits>>) when I > 245 -> {(F+S+T) * 256 + L, Rest};
lrd(<<L, Rest/bits>>) -> {L, Rest}.

decode_long(<<0, Rest/bits>>) ->
    {null, decode_next(ub2,Rest,2)};
decode_long(Data) ->
    Value = decode_chr(Data),
    Rest2 = decode_next(chr,Data),
    {Value, decode_next(ub2,Rest2,2)}.

decode_helper(param, Data) -> decode_token(oac, ?ENCODER:encode_token(oac, Data));
decode_helper(tz, Data) -> ltz(Data).
