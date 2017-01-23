-module(jamdb_oracle_tns_decoder).

%% API
-export([decode_packet/1]).
-export([decode_token/2]).

-include("TNS.hrl").
-include("jamdb_oracle.hrl").

%% API
decode_packet(<<PacketSize:16, 0:16, ?TNS_DATA, _Flags:8, 0:16, _DataFlags:16, Rest/bits>>) ->
    BodySize = PacketSize-10,
    case Rest of
        <<PacketBody:BodySize/binary, Rest2/bits>> ->
            {ok, ?TNS_DATA, PacketBody, Rest2};
        _ ->
            {error, more}
    end;
decode_packet(<<PacketSize:16, 0:16, ?TNS_REDIRECT, _Flags:8, 0:16, Length:16, Rest/bits>>) when Length > PacketSize-8 ->
    case Rest of
        <<>> ->
            {error, more};
        _ ->
            {ok, ?TNS_REDIRECT, Rest, <<>>}
    end;
decode_packet(<<PacketSize:16, 0:16, Type, _Flags:8, 0:16, Rest/bits>>) ->
    BodySize = PacketSize-8,
    case Rest of
        <<PacketBody:BodySize/binary, Rest2/bits>> ->
            {ok, Type, PacketBody, Rest2};
        _ ->
            {error, more}
    end;
decode_packet(_) ->
    {error, more}.

decode_token(<<Token, Data/binary>>, TokensBufer) ->
    case Token of
	?TTI_DCB -> decode_token(dcb, Data, TokensBufer);
	?TTI_IOV -> decode_token(iov, Data, TokensBufer);
	?TTI_RXH -> decode_token(rxh, Data, TokensBufer);
	?TTI_RXD -> decode_token(rxd, Data, TokensBufer);
	?TTI_BVC -> decode_token(bvc, Data, TokensBufer);
	?TTI_LOB -> decode_token(lob, Data, TokensBufer);
	?TTI_RPA -> decode_token(rpa, Data, TokensBufer);
	?TTI_OER -> decode_token(oer, Data, TokensBufer);
	?TTI_STA -> {ok, TokensBufer};  %tran
        _ -> 
    	    {error, undefined}
    end;
decode_token(net, {Data, EnvOpts}) ->
    Values = lists:map(fun(L) -> list_to_tuple(string:tokens(L, "=")) end, 
        string:tokens(binary_to_list(Data), "()")),
    Host = proplists:get_value("HOST", Values),     
    Port = proplists:get_value("PORT", Values, ?DEF_PORT),
    {ok, lists:append([{host, Host}, {port, list_to_integer(Port)}], EnvOpts)}.  
decode_token(rpa, Data) ->
    Count = decode_sb4(Data),
    Values = decode_keyval(decode_next(Data), Count, []),
    Sess = proplists:get_value("AUTH_SESSKEY", Values),
    Salt = proplists:get_value("AUTH_VFR_DATA", Values),
    case proplists:get_value("AUTH_SVR_RESPONSE", Values) of
        undefined ->
            {?TTI_SESS, Sess, Salt};
        Resp ->
            Value = proplists:get_value("AUTH_VERSION_NO", Values),
            Ver = decode_version(Value),
            {?TTI_AUTH, Resp, Ver, Values}
    end;
decode_token(oac, Data) ->
    DataType = decode_ub1(Data),
    Rest2 = decode_next(ub1,Data),	%%data type
    Rest3 = decode_next(ub1,Rest2),     %%flg
    Rest4 = decode_next(ub1,Rest3),     %%pre
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
    {Rest13, DataType, Length, Charset};
decode_token(wrn, Data) ->
    Rest2 = decode_next(ub2,Data),	%%retCode
    Rest3 = decode_next(ub2,Rest2),	%%warnLength
    Rest4 = decode_next(ub2,Rest3),	%%warnFlag
    decode_next(chr, Rest4).            %%errorMsg

decode_token(uds, Data, _Ver, 0, Acc) ->
    {lists:reverse(Acc), Data};
decode_token(uds, Data, Ver, Num, Acc) ->
    {Rest2, DataType, Length, Charset} = decode_token(oac, Data),
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
    decode_token(uds, Rest9, Ver, Num-1, 
    [#format{column_name=list_to_binary(Column),
    data_type=DataType,data_length=Length,charset=Charset}|Acc]);
decode_token(iov, <<?TTI_RXD, Data/bits>>, Ver, 0, RowFormat) ->
    try decode_data(Data, RowFormat, []) of
        {Rows, Rest2} -> decode_token(Rest2, {0, [], Rows}) %%proc_result
    catch
	error:_ -> decode_token(iov, Data, Ver, 1, [])      %%fetch cursor
    end;
decode_token(iov, Data, Ver, 1, _RowFormat) ->
    {Rest2, RowFormat} = decode_token(dcb, decode_next(ub1,Data), Ver),
    Cursor = decode_ub4(Rest2),
    Rest3 = decode_next(ub4,Rest2),
    Rest4 = decode_next(ub2,Rest3),
    decode_token(Rest4, {Cursor, RowFormat, []}).

decode_token(dcb, Data, {Ver, _RowFormat}) -> 
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
    {RowFormat, Rest6} = decode_token(uds, Rest5, Ver, Num, []),
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
decode_token(iov, Data, {Ver, RowFormat}) ->
    Rest2 = decode_next(ub1,Data),
    Num = decode_ub2(Rest2),
    Rest3 = decode_next(rxh,Data),
    <<Bind:Num/binary,_Rest/bits>> = Rest3,
    Rest4 = decode_next(Num,Rest3),
    case binary:match(Bind,<<16>>) of
        nomatch -> decode_token(Rest4, {0, [], []});        %%affected_rows
        _ -> decode_token(iov, Rest4, Ver, 0, RowFormat)
    end;
decode_token(rxh, Data, {Cursor, RowFormat, Rows}) ->
    Rest2 = decode_next(ub1,Data),
    Rest3 = decode_next(ub2,Rest2),
    Rest4 = decode_next(ub2,Rest3),
    Rest5 = decode_next(ub2,Rest4),
    Rest6 = decode_next(ub2,Rest5),
    Bitvec = decode_dalc(Rest6),
    {Bvc, _Count} = 
    case length(Bitvec) of
        0 -> {[0], 0};
        _ -> decode_bvc(list_to_binary(Bitvec), RowFormat, [])
    end,
    Rest7 = decode_next(rxh,Data),
    decode_token(Rest7, {Cursor, RowFormat, Bvc, Rows});
decode_token(rxd, Data, {Cursor, RowFormat, Bvc, Rows}) ->
    LastRow = last(Rows),
    {Rest2, Row} = decode_rxd(Data, RowFormat, 1, Bvc, LastRow, []),
    decode_token(Rest2, {Cursor, RowFormat, Bvc, Rows++[Row]});
decode_token(bvc, Data, {Cursor, RowFormat, _Bvc, Rows}) ->
    Rest2 = decode_next(ub2,Data),
    {Bvc, Count} = decode_bvc(Rest2, RowFormat, []),
    Rest3 = decode_next(ub1, Rest2, Count),
    decode_token(Rest3, {Cursor, RowFormat, Bvc, Rows});
decode_token(lob, Data, _Loc) ->
    try decode_chr(Data) of
        Value -> {ok, Value}
    catch
	error:_ -> {ok, [eof]}
    end;
decode_token(rpa, Data, {_Ver, RowFormat}) ->
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
decode_token(oer, Data, {Cursor, RowFormat, _Bvc, Rows}) ->
    decode_token(oer, Data, {Cursor, RowFormat, Rows});
decode_token(oer, Data, {Cursor, RowFormat, Rows}) ->
    Rest2 = decode_next(ub2,Data),
    Rest3 = decode_next(ub2,Rest2),             %%Sequence Number
    RowNumber = decode_ub4(Rest3),
    Rest4 = decode_next(ub4,Rest3),             %%Current Row Number
    RetCode = decode_ub2(Rest4),
    RetFormat = 
    case RetCode of
        0 -> RowFormat;
        1403 -> RowFormat;
        _ ->
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
            decode_dalc(Rest25)
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
decode_next(ub1,<<_Byte:8,Rest/bits>>) ->
    Rest;
decode_next(ub2,Data) ->
    decode_next(ub4,Data);
decode_next(ub4,<<0,Rest/bits>>) ->
    Rest;
decode_next(ub4,Data) ->
    <<Byte,Rest/bits>> = Data,
    case (Byte band 128) of
	0 -> decode_next(Data);
	_ -> decode_next(ub1, Rest)
    end;
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
    Count = Length div 8 + 
    case Length rem 8 of
        0 -> 0;
        _ -> 1
    end,
    {decode_bvc(Data, Acc, Count, 0), Count}.

decode_bvc(_Data, Acc, 8, _I) when is_tuple(Acc) ->
    Acc;
decode_bvc(Data, Acc, Count, I) when is_tuple(Acc) ->
    Bvc =
    case (Data band (1 bsl Count)) of
	0 -> Acc;
	_ -> erlang:append_element(Acc, I * 8 + Count + 1)
    end,
    decode_bvc(Data, Bvc, Count+1, I);    
decode_bvc(_Data, Acc, 0, _I) when is_list(Acc) ->
    Acc;
decode_bvc(Data, Acc, Count, I) when is_list(Acc) ->
    Bvc = decode_bvc(decode_ub1(Data), {}, 0, I),
    decode_bvc(decode_next(ub1,Data), Acc++tuple_to_list(Bvc), Count-1, I+1).

decode_data(Data, [], Values) ->
    {lists:reverse(Values), Data};
decode_data(Data, [#format{param=in}|RestRowFormat], Values) ->
    decode_data(Data, RestRowFormat, Values);
decode_data(_Data, [#format{data_type=?TNS_TYPE_REFCURSOR}|_RestRowFormat], _Values) ->
    erlang:error(cursor);
decode_data(Data, [ValueFormat|RestRowFormat], Values) ->
    {Value, RestData} = decode_data(Data, ValueFormat),
    decode_data(decode_next(ub2,RestData), RestRowFormat, [Value|Values]).

decode_data(<<0, Rest/bits>>, #format{data_type=DataType}) when ?IS_NULL_TYPE(DataType) ->
    {null, Rest};
decode_data(Data, #format{charset=?AL16UTF16_CHARSET}=ValueFormat) ->
    {Value, RestData} = decode_data(Data, ValueFormat#format{charset=?UTF8_CHARSET}),
    {xmerl_ucs:to_utf8(xmerl_ucs:from_utf16be(list_to_binary(Value))), RestData};
decode_data(Data, #format{data_type=DataType}) when ?IS_CHAR_TYPE(DataType); ?IS_RAW_TYPE(DataType) ->
    {decode_value(Data, DataType), decode_next(chr,Data)};
decode_data(Data, #format{data_type=DataType}) when ?IS_FIXED_TYPE(DataType) ->
    <<Length, BinValue:Length/binary, Rest/binary>> = Data,
    {decode_value(BinValue, DataType), Rest};
decode_data(Data, #format{data_type=DataType}) ->
    decode_value(Data, DataType).

decode_value(BinValue, DataType) when ?IS_CHAR_TYPE(DataType); ?IS_RAW_TYPE(DataType) ->
    decode_chr(BinValue);
decode_value(BinValue, DataType) when ?IS_NUMBER_TYPE(DataType) ->
    {decode_number(BinValue)};
decode_value(BinValue, DataType) when ?IS_BINARY_TYPE(DataType) ->
    {decode_binary(BinValue)};
decode_value(BinValue, DataType) when ?IS_DATE_TYPE(DataType) ->
    decode_date(BinValue);
decode_value(BinValue, DataType) when ?IS_INTERVAL_TYPE(DataType) ->
    decode_interval(BinValue);
decode_value(BinValue, DataType) when ?IS_ROWID_TYPE(DataType) ->
    decode_rowid(BinValue);
decode_value(BinValue, DataType) when ?IS_LONG_TYPE(DataType) ->
    decode_long(BinValue);
decode_value(BinValue, DataType) when DataType =:= ?TNS_TYPE_CLOB  ->
    decode_clob(BinValue);
decode_value(BinValue, DataType) when DataType =:= ?TNS_TYPE_BLOB ->
    decode_blob(BinValue);
decode_value(BinValue, _DataType) ->
    decode_value(BinValue).

decode_value(Data) ->
    Rest2 = decode_next(ub4,Data),
    Value = decode_chr(Rest2),
    {Value, decode_next(chr,Rest2)}.

%decode_len(L, DataType) ->
%    case L of
%        L when DataType =:= ?TNS_TYPE_NUMBER -> 22;
%        L when DataType =:= ?TNS_TYPE_DATE -> 7;
%        L when DataType =:= ?TNS_TYPE_TIMESTAMPTZ -> 13;
%        L -> L
%    end.      

decode_keyval(_Data,0,Acc) ->
    Acc;
decode_keyval(Data,Count,Acc) ->
    {Key, Rest2} =
    case decode_sb4(Data) of
	0 -> {undefined, decode_next(Data)};
	_ ->
	    Rest3 = decode_next(Data),
	    {decode_chr(Rest3), decode_next(chr,Rest3)}
    end,
    {Value, Rest4} =
    case decode_sb4(Rest2) of
	0 -> {undefined, decode_next(Rest2)};
	_ ->
	    Rest5 = decode_next(Rest2),
	    {decode_chr(Rest5), decode_next(chr,Rest5)}
    end,
    Rest6 = decode_next(Rest4),
    decode_keyval(Rest6,Count-1,Acc++[{Key,Value}]).

decode_ub1(<<Byte,_Rest/bits>>) ->
    Byte.

decode_ub2(Data) ->
    decode_ub4(Data).

decode_ub4(<<0,_Rest/bits>>) -> 0;
decode_ub4(Data) ->
    <<Byte,Rest/bits>> = Data,
    case (Byte band 128) of
	0 -> decode_sb4(Data);
	_ -> -1 * decode_ub1(Rest)
    end.

decode_sb4(<<0,_Rest/bits>>) -> 0;
decode_sb4(<<Length,Rest/bits>>) ->
    <<Data:Length/binary,_Rest2/bits>> = Rest,
    binary:decode_unsigned(Data).

decode_dalc(<<0,_Rest/bits>>) -> [];
decode_dalc(<<254,Rest/bits>>) ->
    decode_chr(Rest, <<>>);
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

lnxfmt([I|L]) when I band 128 > 0 ->
    {1, [((I band 127) - 65)|[ N-1 || N <- L]]};
lnxfmt([I|L]) when I band 128 =:= 0 ->
    {-1, [(((I bxor 255) band 127) - 65)|[ 101-N || N <- lnxneg(L)]]}.

decode_binary(<<I,Rest/binary>> = Data) when I band 128 > 0 ->
    Length = byte_size(Data),
    <<Value:Length/float-unit:8>> = <<(I band 127),Rest/binary>>,
    Value;
decode_binary(<<I,_Rest/binary>> = Data) when I band 128 =:= 0 ->
    Length = byte_size(Data),
    <<Value:Length/float-unit:8>> = << <<(B bxor 255)>> || <<B>> <= Data >>,
    Value.

decode_date(<<Century,Year,Month,Day,Hour,Minute,Second>>) ->
    {{(Century - 100) * 100 + (Year - 100),(Month),(Day)},
     {(Hour - 1),(Minute - 1),(Second - 1)}};
decode_date(<<Data:7/binary,Ms:4/integer-unit:8>>) ->
    {Date,{Hour,Minute,Second}} = decode_date(Data),
    {Date,{Hour,Minute,Second + Ms / 1.0e9}};
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

decode_interval(<<Year:4/integer-unit:8,Month>>) ->
    lym(Year - 2147483648, Month - 60);
decode_interval(<<Day:4/integer-unit:8,Hour,Minute,Second,Ms:4/integer-unit:8>>) ->
    lds(Day - 2147483648, Hour - 60, Minute - 60, Second - 60, (Ms - 2147483648) / 1.0e9).

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
    {decode_rowid(Objid,6,[])++decode_rowid(Partid,3,[])++
    decode_rowid(Blocknum,6,[])++decode_rowid(Slotnum,3,[]),Rest7}.

decode_rowid(_Data,0,Acc) ->
    Acc;
decode_rowid(Data,Count,Acc) ->
    Value = lists:nth((Data band 63)+1,
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"),
    decode_rowid(Data bsr 6 band 67108863,Count-1,[Value|Acc]).

decode_clob(Data) ->
    Rest2 = decode_next(ub4,Data,3),
    Rest3 = decode_next(ub1,Rest2,2),
    Value = decode_chr(Rest3),
    Rest4 = decode_next(chr,Rest3),
    {Value, decode_next(Rest4)}.

decode_blob(Data) ->
    Rest2 = decode_next(ub4,Data,3),
    Value = decode_chr(Rest2),
    Rest3 = decode_next(chr,Rest2),
    {Value, decode_next(Rest3)}.

decode_long(<<0, Rest/bits>>) ->
    {null, decode_next(ub2,Rest,2)};
decode_long(Data) ->
    Value = decode_chr(Data),
    Rest2 = decode_next(chr,Data),
    {Value, decode_next(ub2,Rest2,2)}.
