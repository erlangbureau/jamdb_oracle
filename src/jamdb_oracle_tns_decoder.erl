-module(jamdb_oracle_tns_decoder).

%% API
-export([decode_packet/1]).
-export([decode_token/2]).

-include("TNS.hrl").
-include("jamdb_oracle.hrl").

%% decode_data_format
-define(IS_CHAR_TYPE(DataType),
    DataType =:= ?TNS_TYPE_CHAR;
    DataType =:= ?TNS_TYPE_VARCHAR
).

-define(IS_NUMBER_TYPE(DataType),
    DataType =:= ?TNS_TYPE_NUMBER;
    DataType =:= ?TNS_TYPE_VARNUM
).

-define(IS_DATE_TYPE(DataType),
    DataType =:= ?TNS_TYPE_DATE;
    DataType =:= ?TNS_TYPE_TIMESTAMP
).

-define(IS_ROWID_TYPE(DataType),
    DataType =:= ?TNS_TYPE_ROWID;
    DataType =:= ?TNS_TYPE_UROWID
).

%% API
decode_packet(<<PacketSize:16, 0:16, ?TNS_DATA, 0:8, 0:16, _DataFlags:16, Rest/bits>>) ->
    BodySize = PacketSize-10,
    case Rest of
        <<PacketBody:BodySize/binary, Rest2/bits>> ->
            {ok, ?TNS_DATA, PacketBody, Rest2};
        _ ->
            {error, incomplete_packet}
    end;
decode_packet(<<PacketSize:16, 0:16, Type, 0:8, 0:16, Rest/bits>>) ->
    BodySize = PacketSize-8,
    case Rest of
        <<PacketBody:BodySize/binary, Rest2/bits>> ->
            {ok, Type, PacketBody, Rest2};
        _ ->
            {error, incomplete_packet}
    end;
decode_packet(_) ->
    {error, incomplete_packet}.


decode_token(<<Token, Data/binary>>, TokensBufer) ->
    case Token of
	?TTI_STA -> {ok, ?TTI_STA};
	?TTI_DCB -> decode_token(dcb, Data);
	?TTI_IOV -> decode_token(iov, Data, TokensBufer);
	?TTI_RXH -> decode_token(rxh, Data, TokensBufer);
	?TTI_RPA -> decode_token(rpa, Data, TokensBufer);
	?TTI_OER -> decode_token(oer, Data, TokensBufer);
        _ -> 
    	    {error, unknown_token}
    end;
decode_token(tti, Data) ->
    case binary:match(Data,<<"AUTH_">>) of
	nomatch ->
	    Rest = decode_next(chr,decode_next(Data)),
	    Ver = decode_sb4(Rest),
	    {?TTI_VERSION, Ver};
	_ ->
	    Count = decode_sb4(Data),
	    Rest = decode_keyval(decode_next(Data), Count, []),
	    Sess = proplists:get_value("AUTH_SESSKEY", Rest),
	    Salt = proplists:get_value("AUTH_VFR_DATA", Rest),
	    case proplists:get_value("AUTH_SVR_RESPONSE", Rest) of
		undefined ->
		    {?TTI_SESS, Sess, Salt};
		Resp ->
		    {?TTI_AUTH, Resp}
	    end
    end;
decode_token(dcb, Data) -> 
    Rest2 = decode_next(Data),
    Rest3 = decode_next(Rest2),
    Num = decode_ub4(Rest3),
    Rest4 = decode_next(ub4,Rest3),
    Rest5 = 
    case Num of
	0 -> Rest4;
	_ -> decode_next(ub1,Rest4)
    end,
    {RowFormat, Rest6} = decode_token(uds, Rest5, Num, []),
    Rest7 = decode_next(dalc,Rest6),
    Rest8 = decode_next(ub4,Rest7),
    Rest9 = decode_next(ub4,Rest8),
    Rest10 = decode_next(ub4,Rest9),
    Rest11 = decode_next(ub4,Rest10),
    Rest12 = decode_next(dalc,Rest11),
    decode_token(Rest12, {0, RowFormat, []});
decode_token(oac, Data) ->
    Type = decode_ub1(Data),
    Rest2 = decode_next(ub1,Data),	%%data type
    Rest3 = decode_next(ub1,Rest2),
    Rest4 = decode_next(ub1,Rest3),
    Scale = decode_ub2(Rest4),
    Rest5 = decode_next(ub2,Rest4),	%%data scale
    Length = decode_ub4(Rest5),
    Rest6 = decode_next(ub4,Rest5),	%%max data lenght
    Rest7 = decode_next(ub4,Rest6),
    Rest8 = decode_next(ub4,Rest7),
    Rest9 = decode_next(dalc,Rest8),
    Rest10 = decode_next(ub2,Rest9),
    Charset = decode_ub2(Rest10),
    Rest11 = decode_next(ub2,Rest10),	%%charset
    Rest12 = decode_next(ub1,Rest11),	%%form of use
    Rest13 = decode_next(ub4,Rest12),
    {Rest13, Type, Scale, Length, Charset}.


decode_token(iov, <<?TTI_RXD, Data/bits>>, 0, RowFormat) -> %%out binds
    decode_out_params(Data, RowFormat, []);
decode_token(iov, Data, 0, _RowFormat) ->                   %%in binds
    {[], Data};
decode_token(iov, <<32, Data/bits>>, Num, RowFormat) ->	    %%in binds
    decode_token(iov, Data, Num-1, RowFormat);
decode_token(iov, <<16, Data/bits>>, Num, RowFormat) ->	    %%out binds
    decode_token(iov, Data, Num-1, RowFormat);
decode_token(uds, Data, 0, Acc) ->
    {lists:reverse(Acc), Data};
decode_token(uds, Data, Num, Acc) ->
    {Rest2, Type, Scale, Length, Charset} = decode_token(oac, Data),
    Rest3 = decode_next(ub1,Rest2),	%%nullable
    Rest4 = decode_next(ub1,Rest3),
    Column = decode_dalc(Rest4),
    Rest5 = decode_next(dalc,Rest4),	%%column name
    Schema = decode_dalc(Rest5),
    Rest6 = decode_next(dalc,Rest5),	%%schema name
    Rest7 = decode_next(dalc,Rest6),	%%type name
    Rest8 = decode_next(ub2,Rest7),
    Rest9 = decode_next(ub4,Rest8),
    decode_token(uds, Rest9, Num-1, [#format{owner_name=Schema,
					column_name=Column,
					data_type=Type,
					data_length=Length,
					scale=Scale,
					locale=Charset}|Acc]).


decode_token(iov, Data, RowFormat) ->
    Rest2 = decode_next(ub1,Data),
    Num = decode_ub2(Rest2),
    Rest3 = decode_next(rxh,Data),
    {Rows, Rest4} = decode_token(iov, Rest3, Num, RowFormat),
    decode_token(Rest4, {0, [], Rows});    
decode_token(rxh, Data, {Cursor, RowFormat, Rows}) ->
    Rest2 = decode_next(ub1,Data),
    Rest3 = decode_next(ub2,Rest2),
    Rest4 = decode_next(ub2,Rest3),
    Iters = decode_ub2(Rest4),
    Rest5 = decode_next(rxh,Data),
    {Rows2, Rest6} = decode_rows(Rest5, RowFormat, Iters, decode_rows([], Rows), []),    
    decode_token(Rest6, {Cursor, RowFormat, Rows++Rows2});
decode_token(rpa, Data, RowFormat) when is_list(RowFormat) ->
    decode_token(rpa, Data, {0, RowFormat, []});
decode_token(rpa, Data, {_Cursor, RowFormat, Rows}) ->
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
decode_token(oer, Data, RowFormat) when is_list(RowFormat) ->
    decode_token(oer, Data, {0, RowFormat, []});
decode_token(oer, Data, {Cursor, RowFormat, Rows}) ->
    Rest2 = decode_next(ub2,Data),
    Rest3 = decode_next(ub2,Rest2),
    RowNumber = decode_ub4(Rest3),
    Rest4 = decode_next(ub4,Rest3),
    RetCode = decode_ub2(Rest4),
    {RetCode, RowNumber, Cursor, RowFormat, Rows}.

%%lager:log(info,self(),"~p",[Data]),

decode_rows([], []) -> [];
decode_rows(Values, []) -> hd(Values);
decode_rows([], Rows) -> lists:last(Rows).

decode_rows(Data, _RowFormat, 0, _LastRow, Values) ->
    {lists:reverse(Values), Data};
decode_rows(Data, RowFormat, Iters, LastRow, Values) ->
    LastRow2 = 
    case length(Values) of
        0 -> LastRow;
        _ -> decode_rows(Values, [])
    end,    
    try decode_row(Data, RowFormat, LastRow2, []) of
	{Value, RestData} -> decode_rows(RestData, RowFormat, Iters-1, LastRow, [Value|Values])
    catch
	error:_ -> decode_rows(Data, RowFormat, 0, LastRow, Values)
    end.

decode_row(<<?TTI_RXD, ?TTI_BVC, Data/bits>>, RowFormat, LastRow, []) when is_list(LastRow) ->
    try decode_bvc(Data, RowFormat) of
        {Rest2, I, Bvc} -> decode_row(decode_next(ub1, Rest2, I), RowFormat, Bvc, 0, LastRow, [])
    catch
	error:_ -> decode_row(<<?TTI_BVC, Data/bits>>, RowFormat, {}, [])
    end;
decode_row(<<?TTI_RXD, Data/bits>>, RowFormat, LastRow, []) when is_list(LastRow) ->
    decode_row(Data, RowFormat, {}, []);
decode_row(<<?TTI_BVC, Data/bits>>, RowFormat, LastRow, []) when is_list(LastRow) ->
    {Rest2, I, Bvc} = decode_bvc(Data, RowFormat),
    decode_row(decode_next(ub1, Rest2, I), RowFormat, Bvc, 0, LastRow, []);
decode_row(Data, [], LastRow, Values) when is_tuple(LastRow) ->
    {lists:reverse(Values), Data};
decode_row(Data, [ValueFormat|RestRowFormat], LastRow, Values) when is_tuple(LastRow) ->
    {Value, RestData} = decode_data(Data, ValueFormat),
    decode_row(RestData, RestRowFormat, LastRow, [Value|Values]).

decode_row(<<?TTI_RXD, Data/bits>>, _RowFormat, [], 0, LastRow, []) ->
    {LastRow, Data};
decode_row(<<?TTI_RXD, Data/bits>>, RowFormat, Bvc, 0, LastRow, []) ->
    decode_row(Data, RowFormat, Bvc, 1, LastRow, []);
decode_row(Data, [], _Bvc, _Iters, _LastRow, Values) ->
    {lists:reverse(Values), Data};
decode_row(Data, [ValueFormat|RestRowFormat], Bvc, Iters, LastRow, Values) ->
    {Value, RestData} = 
    case lists:member(Iters, Bvc) of
	true -> decode_data(Data, ValueFormat);
	false -> {lists:nth(Iters, LastRow), Data}    
    end,    
    decode_row(RestData, RestRowFormat, Bvc, Iters+1, LastRow, [Value|Values]).
    
decode_bvc(Data, RowFormat) ->
    I = decode_ub2(Data),
    Rest2 = decode_next(ub2,Data),
    Len = length(RowFormat),
    Count = Len div 8 + 
    case Len rem 8 of
        0 -> 0;
        _ -> 1
    end,
    Bvc = decode_bvc(Rest2, [], Count, 0),
    case length(Bvc) of
        I -> {Rest2, Count, Bvc};
        _ -> erlang:error(badmask)
    end.
    
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

decode_out_params(Data, [], Values) ->
    {lists:reverse(Values), Data};
decode_out_params(Data, [ValueFormat|RestRowFormat], Values) ->
    {Value, <<0, RestData/binary>>} = decode_data(Data, ValueFormat),
    decode_out_params(RestData, RestRowFormat, [Value|Values]).    

decode_data(<<0, Rest/bits>>, _ValueFormat) ->
    {null, Rest};
decode_data(<<254, Rest/bits>>, #format{data_type=DataType}) when ?IS_CHAR_TYPE(DataType) ->
    decode_value(Rest, DataType, <<>>);
decode_data(Data, #format{data_type=DataType}) when ?IS_ROWID_TYPE(DataType) ->
    decode_value(Data, DataType);
decode_data(Data, #format{data_type=DataType}) ->
    <<Length, BinValue:Length/binary, Rest/binary>> = Data,
    {decode_value(BinValue, DataType), Rest}.

decode_value(<<0, Rest/bits>>, DataType, Value) when ?IS_CHAR_TYPE(DataType) ->
    {decode_value(Value, DataType), Rest};
decode_value(Data, DataType, Value) when ?IS_CHAR_TYPE(DataType) ->
    <<Length, BinValue:Length/binary, Rest/binary>> = Data,
    decode_value(Rest, DataType, <<Value/binary, BinValue/binary>>).

decode_value(BinValue, DataType) when ?IS_NUMBER_TYPE(DataType) ->
    {number, decode_number(BinValue)};
decode_value(BinValue, DataType) when ?IS_DATE_TYPE(DataType) ->
    decode_date(BinValue);
decode_value(BinValue, DataType) when ?IS_ROWID_TYPE(DataType) ->
    decode_rowid(BinValue);
decode_value(BinValue, _DataType) ->
    BinValue.

decode_next(<<Len,Rest/bits>>) ->
    <<_Data:Len/binary,Rest2/bits>> = Rest,
    Rest2.

decode_next(_Type, Data, 0) ->
    Data;
decode_next(Type, Data, I) when is_integer(I) ->
    decode_next(Type, decode_next(Type, Data), I-1);
decode_next(chr, <<0,Rest/bits>>, I) when is_binary(I) ->
    Rest;
decode_next(chr, Data, I) when is_binary(I) ->
    decode_next(chr, decode_next(Data), I).

decode_next(Len,Data) when is_integer(Len) ->
    <<_Data:Len/binary,Rest/bits>> = Data,
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
decode_next(dalc,<<Len,Rest/bits>>) ->
    <<_Data:Len/binary,Rest2/bits>> = Rest,
    decode_next(Rest2);
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
    Rest2 = decode_next(ub1,Data),	%%flg
    Rest3 = decode_next(ub2,Rest2),	%%bindcnt
    Rest4 = decode_next(ub2,Rest3),	%%iternum
    Rest5 = decode_next(ub2,Rest4),	%%itersthistime
    Rest6 = decode_next(ub2,Rest5),	%%uacbuflen
    Rest7 = decode_next(dalc,Rest6),
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
    decode_next(R,Rest8);
decode_next(chr,<<254,Rest/bits>>) ->
    decode_next(chr,Rest,<<>>);
decode_next(chr,Data) ->
    decode_next(Data).
%decode_next(oer,Data) ->
%    Rest2 = decode_next(ub2,Data),
%    Rest3 = decode_next(ub2,Rest2),	%%sequencenumber
%    Rest4 = decode_next(ub4,Rest3),	%%currownumber
%    Rest5 = decode_next(ub2,Rest4),	%%retcode
%    Rest6 = decode_next(ub2,Rest5),	%%werror
%    Rest7 = decode_next(ub2,Rest6),	%%errno
%    Rest8 = decode_next(ub2,Rest7),	%%cursorid
%    Rest9 = decode_next(ub2,Rest8),	%%errorposition
%    Rest10 = decode_next(ub1,Rest9),	%%sqltype
%    Rest11 = decode_next(ub2,Rest10),	%%fatal
%    Rest12 = decode_next(ub2,Rest11),	%%flags
%    Rest13 = decode_next(ub2,Rest12),	%%cursoropt
%    Rest14 = decode_next(ub1,Rest13),	%%upiparam
%    Rest15 = decode_next(ub1,Rest14),	%%warniningflag
%    Rest16 = decode_next(ub4,Rest15),	%%rba
%    Rest17 = decode_next(ub2,Rest16),	%%partitionid
%    Rest18 = decode_next(ub1,Rest17),	%%tableid
%    Rest19 = decode_next(ub4,Rest18),	%%blocknumber
%    Rest20 = decode_next(ub2,Rest19),	%%slotnumber
%    Rest21 = decode_next(ub4,Rest20),	%%oserror
%    Rest22 = decode_next(ub1,Rest21),	%%stmtnumber
%    Rest23 = decode_next(ub1,Rest22),	%%callnumber
%    Rest24 = decode_next(ub2,Rest23),	%%pad
%    Rest25 = decode_next(ub4,Rest24),	%%successiters
%    Rest26 = decode_next(dalc,Rest25),
%    I = decode_ub2(Rest26),
%    Rest27 = decode_next(ub2,Rest26),
%    Rest28 = decode_next(ub2, Rest27, I),
%    J = decode_ub4(Rest28),
%    Rest29 = decode_next(ub4,Rest28),
%    Rest30 = decode_next(ub4, Rest29, J),
%    Rest31 = decode_next(ub2,Rest30),
%    case byte_size(Rest31) of
%	0 -> Rest31;
%	_ -> decode_next(chr,Rest31)
%    end.

decode_rowid(Data) ->
    Rest2 = decode_next(ub1,Data),
    Objid = decode_ub4(Rest2),
    Rest3 = decode_next(ub4,Rest2),
    Filenum = decode_ub2(Rest3),
    Rest4 = decode_next(ub2,Rest3),
    Rest5 = decode_next(ub1,Rest4),	
    Blocknum = decode_ub4(Rest5),
    Rest6 = decode_next(ub4,Rest5),
    Rowslot = decode_ub2(Rest6),
    Rest7 = decode_next(ub2,Rest6),
    {{rowid, Objid, Filenum, Blocknum, Rowslot}, Rest7}.
    
decode_keyval(_Data,0,List) ->
    List;
decode_keyval(Data,Count,List) ->
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
    decode_keyval(Rest6,Count-1,List++[{Key,Value}]).

decode_ub1(<<Byte,_Rest/bits>>) ->
    Byte.

decode_ub2(Data) ->
    decode_ub4(Data).

decode_ub4(<<0,_Rest/bits>>) ->
    0;
decode_ub4(Data) ->
    <<Byte,Rest/bits>> = Data,
    case (Byte band 128) of
	0 -> decode_sb4(Data);
	_ -> -1 * decode_ub1(Rest)
    end.

decode_sb4(<<0,_Rest/bits>>) ->
    0;
decode_sb4(<<Len,Rest/bits>>) ->
    <<Data:Len/binary,_Rest2/bits>> = Rest,
    binary:decode_unsigned(Data).
    
decode_dalc(<<0,_Rest/bits>>)->
    <<>>;
decode_dalc(Data) ->
    list_to_binary(decode_chr(decode_next(Data))).

decode_chr(<<254,Rest/bits>>) ->
    decode_chr(Rest, <<>>);
decode_chr(<<Len,Rest/bits>>) ->
    <<Data:Len/binary,_Rest2/bits>> = Rest,
    binary_to_list(Data).

decode_chr(<<0,_Rest/bits>>, Acc) ->
    binary_to_list(Acc);
decode_chr(<<Len,Rest/bits>>, Acc) ->
    <<Data:Len/binary,Rest2/bits>> = Rest,
    decode_chr(Rest2, <<Acc/binary, Data/binary>>).

decode_number(<<128>>) ->
    0;
decode_number(Data) ->
    {N, [I|L]} = from_lnxfmt(binary_to_list(Data)),
    Len = length(L),
    N *
    case (I + 1) > (Len - 1) of
	true ->  lnxsni([I|L],Len);
	false -> lnxnur([I|L],Len)
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

from_lnxfmt([I|L]) when I band 128 > 0 ->
    {1, [to_byte((I band 127) - 65)|[ N-1 || N <- L]]};
from_lnxfmt([I|L]) when I band 128 =:= 0 ->
    {-1, [to_byte(((I bxor 255) band 127) - 65)|[ 101-N || N <- lnxneg(L)]]}.

to_byte(Byte) ->
    [Int] = [B || <<B:1/little-signed-integer-unit:8>> <= <<Byte>>],
    Int.
    
decode_date(<<Century,Year,Month,Day,Hour,Minute,Second>>) ->
    {{(Century - 100) * 100 + (Year - 100),(Month),(Day)},
     {(Hour - 1),(Minute - 1),(Second - 1)}}.
