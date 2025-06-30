-module(jamdb_oracle_tns_encoder).

%% API
-export([encode_packet/3]).
-export([encode_record/2]).
-export([encode_token/3]).
-export([encode_str/1]).
-export([encode_helper/2]).

-include("jamdb_oracle.hrl").

%% API
encode_packet(?TNS_DATA, Data, Length) ->
    PacketSize = byte_size(Data) + 10,
    BodySize = Length - 10,
    case Data of
        <<PacketBody:BodySize/binary, Rest/bits>> when PacketSize > Length ->
            {<<Length:16, 0:16, ?TNS_DATA:8, 0:8, 0:16, 32:16, PacketBody/binary>>, Rest};
        _ ->  {<<PacketSize:16, 0:16, ?TNS_DATA:8, 0:8, 0:16, 0:16, Data/binary>>, <<>>}
    end;
encode_packet(Type, Data, _Length) ->
    PacketSize = byte_size(Data) + 8,
    {<<PacketSize:16, 0:16, Type:8, 0:8, 0:16, Data/binary>>, <<>>}.

encode_record(description, EnvOpts) ->
    {ok, UserHost}  = inet:gethostname(),
    User            = proplists:get_value(user, EnvOpts),
    Host            = proplists:get_value(host, EnvOpts, ?DEF_HOST),
    Port            = proplists:get_value(port, EnvOpts, ?DEF_PORT),
    Sid             = proplists:get_value(sid, EnvOpts, ?DEF_SID),
    ServiceName     = proplists:get_value(service_name, EnvOpts),
    AppName         = proplists:get_value(app_name, EnvOpts, "jamdb"),
    SslOpts         = proplists:get_value(ssl, EnvOpts, []),
    encode_str(
    "(DESCRIPTION=(CONNECT_DATA=("++ case ServiceName of
        undefined -> "SID="++Sid;
                _ -> "SERVICE_NAME="++ServiceName end ++
    ")(CID=(PROGRAM="++AppName++
    ")(HOST="++UserHost++")(USER="++User++
    ")))(ADDRESS=(PROTOCOL="++ case SslOpts of
               [] -> "TCP";
                _ -> "TCPS" end ++
    ")(HOST="++Host++")(PORT="++integer_to_list(Port)++")))");
encode_record(login, #oraclient{env=EnvOpts,sdu=Sdu,auth=Desc}) ->
    Data = if Desc =/= [] -> encode_str(Desc); true -> encode_record(description, EnvOpts) end,
    <<
    1,57,                    % Packet version number
    1,57,                    % Lowest compatible version number
    0,0,                     % Global service options supported
    Sdu:16,                  % SDU
    255,255,                 % TDU
    79,152,                  % Protocol Characteristics
    0,0,                     % Max packets before ACK
    0,1,                     % 1 in hardware byte order
    (byte_size(Data)):16,    % Connect Data length
    0,58,                    % Connect Data offset
    0,0,0,0,                 % Max connect data that can be received
    132,132,                 % ANO disabled
    0:192,
    Data/binary
    >>;
encode_record(sess, #oraclient{env=EnvOpts,seq=Tseq}) ->
    {ok, UserHost}  = inet:gethostname(),
    UserPID         = os:getpid(),
    User            = proplists:get_value(user, EnvOpts),
    Role            = proplists:get_value(role, EnvOpts, 0),
    Prelim          = proplists:get_value(prelim, EnvOpts, 0),
    AppName         = proplists:get_value(app_name, EnvOpts, "jamdb"),
    User2 = encode_str(User),
    <<
    ?TTI_FUN,
    ?TTI_SESS, Tseq,
    1,                                                                         %authusr
    (encode_sb2(byte_size(User2)))/binary,
    (encode_sb2((Role * 32) bor (Prelim * 128) bor 1))/binary,                 %auth mode
    1,                                                                         %authivl
    (encode_sb2(4))/binary,                                                    %number of keyval pairs
    1,1,                                                                       %authovl
    User2/binary,
    (encode_keyval("AUTH_PROGRAM_NM", AppName))/binary,
    (encode_keyval("AUTH_MACHINE", UserHost))/binary,
    (encode_keyval("AUTH_PID", UserPID))/binary,
    (encode_keyval("AUTH_SID", User))/binary
    >>;
encode_record(auth, #oraclient{env=EnvOpts,passwd=Passwd,req=Request,seq=Tseq}) ->
    User            = proplists:get_value(user, EnvOpts),
    Role            = proplists:get_value(role, EnvOpts, 0),
    Prelim          = proplists:get_value(prelim, EnvOpts, 0),
    Passwd ! {get, self()},
    {Pass, NewPass} = receive Reply -> Reply end,
    User2 = encode_str(User),
    Pass2 = binary_to_list(encode_str(Pass)),
    NewPass2 = binary_to_list(encode_str(NewPass)),
    #logon{auth=AuthSess, speedy_key=SpeedyKey, key=KeyConn, password=AuthPass, newpassword=AuthNewPass} =
    jamdb_oracle_crypt:generate(Request#logon{user=binary_to_list(User2), password=Pass2, newpassword=NewPass2}),
    {PassMode, PassInd} = if AuthNewPass =/= [] -> {18, 1}; true -> {1, 0} end,
    KeyInd = if SpeedyKey =/= [] -> 1; true -> 0 end,
    {<<
    ?TTI_FUN,
    ?TTI_AUTH, Tseq,
    1,                                                                         %authusr
    (encode_sb2(byte_size(User2)))/binary,
    (encode_sb2((Role * 32) bor (Prelim * 128) bor PassMode bor 256))/binary,  %auth mode
    1,                                                                         %authivl
    (encode_sb2(4 + KeyInd + PassInd))/binary,                                 %number of keyval pairs
    1,1,                                                                       %authovl
    User2/binary,
    (encode_keyval("AUTH_PASSWORD", AuthPass))/binary,
    (if PassInd =/= 0 -> encode_keyval("AUTH_NEWPASSWORD", AuthNewPass); true -> <<>> end)/binary,
    (if KeyInd =/= 0 -> encode_keyval("AUTH_PBKDF2_SPEEDY_KEY", SpeedyKey); true -> <<>> end)/binary,
    (encode_keyval(<<"AUTH_SESSKEY">>, AuthSess, 1))/binary,
    (encode_keyval("SESSION_CLIENT_DRIVER_NAME", "beam"))/binary,
    (encode_keyval("SESSION_CLIENT_VERSION", "186647296"))/binary
    >>,
    KeyConn};
encode_record(dty, #oraclient{charset=Charset}) ->
    <<
    ?TTI_DTY,
    (encode_ub2(Charset))/binary,                                              %cli in charset
    (encode_ub2(encode_helper(utf16, Charset)))/binary,                        %cli out charset
    1,
    38,6,1,0,0,106,1,1,6,1,1,1,1,1,1,0,41,144,3,7,3,0,1,0,79,1,55,4,0,0,0,0,12,0,0,6,0,1,1,
    7,2,0,0,0,0,0,0,
    1,1,1,0,2,2,10,0,8,8,1,0,12,12,10,0,23,23,1,0,24,24,1,0,25,25,1,0,
    26,26,1,0,27,27,1,0,28,28,1,0,29,29,1,0,30,30,1,0,31,31,1,0,32,32,1,0,
    33,33,1,0,10,10,1,0,11,11,1,0,40,40,1,0,41,41,1,0,117,117,1,0,120,120,1,0,
    34,34,1,0,35,35,1,0,36,36,1,0,37,37,1,0,38,38,1,0,42,42,1,0,43,43,1,0,
    44,44,1,0,45,45,1,0,46,46,1,0,47,47,1,0,48,48,1,0,49,49,1,0,50,50,1,0,
    51,51,1,0,52,52,1,0,53,53,1,0,54,54,1,0,55,55,1,0,56,56,1,0,57,57,1,0,
    59,59,1,0,60,60,1,0,61,61,1,0,62,62,1,0,63,63,1,0,64,64,1,0,65,65,1,0,
    66,66,1,0,67,67,1,0,71,71,1,0,72,72,1,0,73,73,1,0,75,75,1,0,77,77,1,0,
    78,78,1,0,79,79,1,0,80,80,1,0,81,81,1,0,82,82,1,0,83,83,1,0,84,84,1,0,
    85,85,1,0,86,86,1,0,87,87,1,0,88,88,1,0,89,89,1,0,90,90,1,0,92,92,1,0,
    93,93,1,0,98,98,1,0,99,99,1,0,103,103,1,0,107,107,1,0,124,124,1,0,
    125,125,1,0,126,126,1,0,127,127,1,0,128,128,1,0,129,129,1,0,130,130,1,0,
    131,131,1,0,132,132,1,0,133,133,1,0,134,134,1,0,135,135,1,0,137,137,1,0,
    138,138,1,0,139,139,1,0,140,140,1,0,141,141,1,0,142,142,1,0,143,143,1,0,
    144,144,1,0,145,145,1,0,148,148,1,0,149,149,1,0,150,150,1,0,151,151,1,0,
    157,157,1,0,158,158,1,0,159,159,1,0,160,160,1,0,161,161,1,0,162,162,1,0,
    163,163,1,0,164,164,1,0,165,165,1,0,166,166,1,0,167,167,1,0,168,168,1,0,
    169,169,1,0,170,170,1,0,171,171,1,0,173,173,1,0,174,174,1,0,175,175,1,0,
    176,176,1,0,177,177,1,0,193,193,1,0,194,194,1,0,198,198,1,0,199,199,1,0,
    200,200,1,0,201,201,1,0,202,202,1,0,203,203,1,0,204,204,1,0,205,205,1,0,
    206,206,1,0,207,207,1,0,210,210,1,0,211,211,1,0,212,212,1,0,213,213,1,0,
    214,214,1,0,215,215,1,0,216,216,1,0,217,217,1,0,218,218,1,0,219,219,1,0,
    220,220,1,0,221,221,1,0,222,222,1,0,223,223,1,0,224,224,1,0,225,225,1,0,
    226,226,1,0,227,227,1,0,228,228,1,0,229,229,1,0,230,230,1,0,234,234,1,0,
    235,235,1,0,236,236,1,0,237,237,1,0,238,238,1,0,239,239,1,0,240,240,1,0,
    242,242,1,0,243,243,1,0,244,244,1,0,245,245,1,0,246,246,1,0,252,252,0,0,
    253,253,1,0,254,254,1,0,2,2,1,0,4,4,1,0,5,5,1,0,6,6,1,0,7,7,1,0,9,9,1,0,
    12,12,1,0,13,13,1,0,14,14,1,0,15,15,1,0,16,16,1,0,17,17,1,0,18,18,1,0,
    19,19,1,0,20,20,1,0,21,21,1,0,22,22,1,0,68,68,1,0,69,69,1,0,70,70,1,0,
    3,2,10,0,4,2,10,0,5,1,1,0,6,2,10,0,7,2,10,0,9,1,1,0,13,0,14,0,15,23,1,0,
    16,0,17,0,18,0,19,0,20,0,21,0,22,0,39,120,1,0,58,0,68,2,10,0,69,0,70,0,
    74,0,76,0,91,2,10,0,94,1,1,0,95,23,1,0,96,96,1,0,97,96,1,0,100,100,1,0,
    101,101,1,0,102,102,1,0,104,11,1,0,105,0,106,106,1,0,108,109,1,0,109,109,
    1,0,110,111,1,0,111,111,1,0,112,112,1,0,113,113,1,0,114,114,1,0,115,115,
    1,0,116,102,1,0,118,0,119,0,121,0,122,0,123,0,136,0,146,146,1,0,147,0,
    152,2,10,0,153,2,10,0,154,2,10,0,155,1,1,0,156,12,10,0,172,2,10,0,
    178,178,1,0,179,179,1,0,180,180,1,0,181,181,1,0,182,182,1,0,183,183,1,0,
    184,12,10,0,185,185,1,0,186,186,1,0,187,187,1,0,188,188,1,0,189,189,1,0,
    190,190,1,0,191,0,192,0,195,112,1,0,196,113,1,0,197,114,1,0,208,208,1,0,
    209,0,231,231,1,0,232,231,1,0,233,233,1,0,241,109,1,0,3,0,104,104,1,0,
    91,91,1,0,110,110,1,0,111,111,1,0,112,112,1,0,113,113,1,0,114,114,1,0,
    115,115,1,0,116,116,1,0,118,118,1,0,119,119,1,0,0
    >>;
encode_record(pro, _EnvOpts) ->
    <<
    ?TTI_PRO,
    6,0,98,101,97,109,0
    >>;
encode_record(spfp, #oraclient{seq=Tseq}) ->
    <<
    ?TTI_FUN,
    ?TTI_SPFP, Tseq,
    1,1,100,1,1,0,0,0,0,0
    >>;
encode_record(start, #oraclient{req=Request,seq=Tseq}) ->
    <<
    ?TTI_FUN,
    ?TTI_STRT, Tseq,
    (encode_sb4(Request))/binary,   %mode 0 norestrict, 1 restrict, 16 force
    1
    >>;
encode_record(stop, #oraclient{req=Request,seq=Tseq}) ->
    <<
    ?TTI_FUN,
    ?TTI_STOP, Tseq,
    (encode_sb4(Request))/binary,   %mode 2 immediate, 4 normal, 8 final, 64 abort, 128 tran
    1
    >>;
encode_record(tran, #oraclient{req=Request,seq=Tseq}) ->
    <<
    ?TTI_FUN,
    Request, Tseq
    >>;
encode_record(fetch, #oraclient{fetch=Fetch,req=Cursor,seq=Tseq}) ->
    <<
    ?TTI_FUN,
    ?TTI_FETCH, Tseq,
    (encode_sb4(Cursor))/binary,    %cursor
    (encode_sb4(Fetch))/binary      %rows to fetch
    >>;
encode_record(exec, #oraclient{type=Type,auto=Auto,charset=Charset,fetch=Fetch,req={Cursor,Query,Bind,Batch,Def},seq=Tseq}) ->
    QueryData = encode_str(Query),
    QueryLen = if Cursor =/= 0 -> 0; true -> byte_size(QueryData) end,
    BindLen = length(Bind),
    BindInd =
    case {Cursor, BindLen} of
        {0, 0} -> 0;
        {0, BindLen} -> 1;
        _ -> 0
    end,
    BatchLen = length(Batch),
    DefLen = length(Def),
    DefInd = if DefLen =/= 0 -> 1; true -> 0 end,
    {Opt, LMax, Max, All8} =
    case {Cursor, Type} of
        {0, Type} -> setopts(Type, BindInd, BatchLen, Auto);
        {Cursor, fetch} -> setopts(fetch, DefInd, 0, Fetch);
        {Cursor, select} -> setopts(select, cursor, 0, Fetch);
        {Cursor, Type} -> setopts(Type, cursor, BatchLen, Auto)
    end,
    <<
    ?TTI_FUN,
    ?TTI_ALL8, Tseq,
    (encode_sb4(Opt))/binary,               %options
    (encode_sb4(Cursor))/binary,            %cursor
    if QueryLen =/= 0 -> 1; true -> 0 end,  %query is empty
    (encode_sb4(QueryLen))/binary,          %query length
    if All8 =/= [] -> 1; true -> 0 end,     %all8 is empty
    (encode_sb4(length(All8)))/binary,      %all8 length
    0,0,
    (encode_sb4(LMax))/binary,              %long max value
    (encode_sb4(Fetch))/binary,             %rows to fetch
    (encode_sb4(Max))/binary,               %max value
    BindInd,                                %bindindicator
    (if BindInd =/= 0 -> encode_sb4(BindLen); true -> <<0>> end)/binary,  %bindcols count
    0,0,0,0,0,
    DefInd,                                 %defcols is empty
    (encode_sb4(DefLen))/binary,            %defcols count
    0,                                      %registration
    0,1,
    0,0,0,0,0,
    (if QueryLen =/= 0 -> QueryData; true -> <<>> end)/binary,
    (encode_array(All8))/binary,
    (case {BindLen, DefLen, QueryLen} of
        {0, 0, QueryLen} -> <<>>;
        {BindLen, 0, 0} -> encode_token(rxd, [Bind|Batch], <<>>);
        {BindLen, 0, QueryLen} -> encode_token(rxd, [Bind|Batch], encode_token(oac, Bind, #format{charset=Charset}, <<>>));
        {0, DefLen, 0} -> encode_token(oac, Def, #format{charset=Charset}, <<>>)
    end)/binary
    >>;
encode_record(pig, #oraclient{req={Request,Cursors},seq=Tseq}) ->
    <<
    ?TTI_PFN,
    Request, Tseq,
    1,
    (encode_sb4(length(Cursors)))/binary,   %cursors count
    (encode_array(Cursors))/binary          %cursors
    >>;
encode_record(close, #oraclient{seq=Tseq}) ->
    <<
    ?TTI_FUN,
    ?TTI_LOGOFF, Tseq
    >>.

setopts(all8, {Opts, Fetch, Type}) -> [Opts,Fetch,0,0,0,0,0,Type,0,0,0,0,0];
setopts(size, Data) when length(Data) > 4000 -> 33554432;  %clob
setopts(size, _Data) -> 4000.

setopts(fetch, DefInd, _BatchLen, Fetch) ->
    {32832 bor (DefInd * 16), 0, 2147483647, setopts(all8, {0, Fetch, 1})};
setopts(select, cursor, _BatchLen, Fetch) ->
    {32864, 0, 2147483647, setopts(all8,{0, Fetch, 1})};
setopts(select, BindInd, _BatchLen, _Auto) ->
    {32801 bor (BindInd * 8), 4294967295, 2147483647, setopts(all8, {1, 0, 1})};
setopts(change, cursor, BatchLen, Auto) ->
    {32800 bor (Auto * 256), 0, 2147483647, setopts(all8, {0, 1 + BatchLen, 0})};
setopts(change, BindInd, BatchLen, Auto) ->
    {32801 bor (BindInd * 8) bor (Auto * 256), 0, 2147483647, setopts(all8, {1, 1 + BatchLen, 0})};
setopts(return, cursor, _BatchLen, Auto) ->
    {1056 bor (Auto * 256), 0, 2147483647, setopts(all8, {0, 1, 0})};
setopts(return, BindInd, _BatchLen, Auto) ->
    {1 bor 1056 bor (BindInd * 8) bor (Auto * 256), 0, 2147483647, setopts(all8, {1, 1, 0})};
setopts(block, cursor, _BatchLen, Auto) ->
    {1056 bor (Auto * 256), 0, 32760, setopts(all8, {0, 1, 0})};
setopts(block, BindInd, _BatchLen, Auto) ->
    {1 bor 1056 bor (BindInd * 8) bor (Auto * 256), 0, 32760, setopts(all8, {1, 1, 0})}.

encode_token([], Acc) -> Acc;
encode_token([Data|Rest], Acc) -> encode_token(Rest, <<Acc/binary, (encode_token(rxd, Data))/binary>>);
encode_token(rxd, Data) when is_list(Data) -> encode_chr(Data);
encode_token(rxd, Data) when is_binary(Data) -> encode_chr(Data);
encode_token(rxd, Data) when is_number(Data) -> encode_len(encode_number(Data));
encode_token(rxd, Data) when is_tuple(Data) -> encode_len(encode_date(Data));
encode_token(rxd, clob) -> <<0>>;
encode_token(rxd, cursor) -> <<1,0>>;
encode_token(rxd, null) -> <<0>>.

encode_token(rxd, [], Acc) -> Acc;
encode_token(rxd, [Data|Rest], Acc) ->
    encode_token(rxd, Rest, <<Acc/binary, (encode_token(Data, <<?TTI_RXD>>))/binary>>);
encode_token(oac, Data, #format{charset=Charset}) when is_list(Data) ->
    encode_token(oac, ?TNS_TYPE_VARCHAR, setopts(size, Data), 16, Charset, 0);
encode_token(oac, Data, _) when is_binary(Data) ->
    encode_token(oac, ?TNS_TYPE_LONGRAW, 33554432, 0, 0, 0);
encode_token(oac, Data, _) when is_number(Data) -> encode_token(oac, ?TNS_TYPE_NUMBER, 22, 0, 0, 0);
encode_token(oac, {{_Year,_Mon,_Day}, {_Hour,_Min,_Sec,_Ms}}, _) -> encode_token(oac, ?TNS_TYPE_TIMESTAMP, 11, 0, 0, 0);
encode_token(oac, {{_Year,_Mon,_Day}, {_Hour,_Min,_Sec,_Ms}, _}, _) -> encode_token(oac, ?TNS_TYPE_TIMESTAMPTZ, 13, 0, 0, 0);
encode_token(oac, Data, _) when is_tuple(Data) -> encode_token(oac, ?TNS_TYPE_DATE, 7, 0, 0, 0);
encode_token(oac, clob, #format{charset=Charset}) -> encode_token(oac, ?TNS_TYPE_VARCHAR, 33554432, 16, Charset, 0);
encode_token(oac, cursor, #format{charset=Charset}) -> encode_token(oac, ?TNS_TYPE_REFCURSOR, 1, 0, Charset, 0);
encode_token(oac, null, Format) -> encode_token(oac, [], Format).

encode_token(oac, [], _, Acc) when is_binary(Acc) -> Acc;
encode_token(oac, [Data|Rest], Format, Acc) when is_record(Data, format), is_binary(Acc) ->
    encode_token(oac, Rest, Format, <<Acc/binary, (encode_token(oac, Data, Format,[]))/binary>>);
encode_token(oac, [Data|Rest], Format, Acc) when is_binary(Acc) ->
    encode_token(oac, Rest, Format, <<Acc/binary, (encode_token(oac, Data, Format))/binary>>);
encode_token(oac, #format{data_type=DataType,charset=Charset}, _, Acc) when is_list(Acc), ?IS_CHAR_TYPE(DataType) ->
    encode_token(oac, ?TNS_TYPE_VARCHAR, 4000, 16, Charset, 0);
encode_token(oac, #format{data_type=DataType,charset=Charset}, _, Acc) when is_list(Acc), ?IS_LOB_TYPE(DataType) ->
    encode_token(oac, DataType, 0, 33554432, Charset, 33554432);
encode_token(oac, #format{data_type=DataType,data_length=Length,charset=Charset}, _, Acc) when is_list(Acc) ->
    encode_token(oac, DataType, Length, 0, Charset, 0).

encode_token(oac, DataType, Length, Flag, Charset, Max) ->
    <<
    (encode_ub1(DataType))/binary,  %data type
    3,                              %flags
    0,                              %precision
    0,                              %data scale
    (encode_sb4(Length))/binary,    %max data length
    0,                              %max number of array elem
    (encode_sb4(Flag))/binary,      %cont flags
    0,                              %OID
    0,                              %version
    (encode_sb4(Charset))/binary,   %character set id
    case Charset of                 %character set form
        ?AL16UTF16_CHARSET -> 2;
        _ -> 1
    end,
    (encode_sb4(Max))/binary        %mxlc
    >>.

encode_array(Data) ->
    encode_array(Data,<<>>).

encode_array([],Acc) ->
    Acc;
encode_array([H|T],Acc) ->
    encode_array(T,<<Acc/binary,(encode_sb4(H))/binary>>).

encode_len(Data) ->
    Length = byte_size(Data),
    <<Length, Data:Length/binary>>.

encode_keyval(Key, Value) ->
    encode_keyval(list_to_binary(Key), encode_str(Value), 0).

encode_keyval(Key, Value, Data) ->
    KeyLen = byte_size(Key),
    ValueLen = byte_size(Value),
    BinKey = if KeyLen =/= 0 -> <<(encode_sb4(KeyLen))/binary, (encode_len(Key))/binary>>; true -> <<0>> end,
    BinValue = if ValueLen =/= 0 -> <<(encode_sb4(ValueLen))/binary, (encode_len(Value))/binary>>; true -> <<0>> end,
    <<BinKey/binary, BinValue/binary, (encode_sb4(Data))/binary>>.

encode_ub1(Data) ->
    <<Data:8>>.

encode_ub2(Data) ->
    <<Data:16/little>>.

encode_sb2(Data) ->
    encode_sb4(Data).

encode_sb4(0) -> <<0>>;
encode_sb4(Data) ->
    <<F,S,T,L>> = <<Data:32>>,
    case F of
        0 -> case S of
            0 -> case T of
                0 -> <<1,L>>;
                _ -> <<2,T,L>>
                end;
            _ -> <<3,S,T,L>>
            end;
        _ -> <<4,F,S,T,L>>
    end.

%encode_dalc(<<>>) -> <<0>>;
%encode_dalc(Data) when byte_size(Data) > 64 -> <<(encode_chr(Data))/binary>>.
%encode_dalc(Data) -> <<(encode_sb4(byte_size(Data)))/binary,(encode_chr(Data))/binary>>.

encode_str(Data) ->
    try list_to_binary(Data) of    %latin-1
        Bin -> Bin
    catch
        error:_ -> unicode:characters_to_binary(Data)
    end.

encode_chr(Data) when is_list(Data) ->
    encode_chr(encode_str(Data));
encode_chr(Data) when byte_size(Data) > 64 ->
    encode_chr(Data,<<254>>);
encode_chr(Data) ->
    encode_len(Data).

encode_chr(Data,Acc) when byte_size(Data) > 64 ->
    <<Bin:64/binary,Rest/bits>> = Data,
    encode_chr(Rest,<<Acc/binary, 64, Bin/binary>>);
encode_chr(Data,Acc) ->
    Length = byte_size(Data),
    <<Acc/binary, Length, Data:Length/binary, 0>>.

encode_number(+0.0) -> <<128>>;
encode_number(0) -> <<128>>;
encode_number(Data) when is_integer(Data) ->
    list_to_binary([<<B>> || B <- lnxfmt(lnxmin(abs(Data),1,[]), Data)]);
encode_number(Data) when is_float(Data) ->
    list_to_binary([<<B>> || B <- lnxfmt(lnxren(abs(Data),0), Data)]).

lnxmin(N, I, Acc) when N div 100 =:= 0 ->
    lnxpak(lists:reverse([I-1|[N rem 100|Acc]]));
lnxmin(N, I, Acc) when I < 20 ->
    lnxmin(N div 100, I+1, [N rem 100|Acc]).

lnxren(N,I) when N < 1.0 ->
    lnxren(N * 100.0,I-1);
lnxren(N,I) when 1.0 =< N, N < 10.0 ->
    lnxpak(lists:reverse([I|lnxren(N,0,1,[])]));
lnxren(N,I) when 10.0 =< N, N < 100.0 ->
    lnxpak(lists:reverse([I|lnxren(N,0,0,[])]));
lnxren(N,I) when N >= 100.0 ->
    lnxren(N * 0.01,I+1).

lnxren(_N, I, 0, [H|L]) when I =:= 8 ->
    lists:reverse(lnxpak([(H+5) div 10 * 10|L],1));
lnxren(_N, I, 1, [H|L]) when I =:= 8 ->
    lists:reverse(lnxpak([H+(H div 50)|L],1));
lnxren(N, I, J, Acc) when I < 8 ->
    lnxren((N-trunc(N))*100.0, I+1, J, [trunc(N)|Acc]).

lnxpak([0|L])->
    lnxpak(L);
lnxpak(L)->
    lists:reverse(L).

lnxpak([100],I) when I =:= 8 ->
    [100-1];
lnxpak([100|[H|L]],I) when I < 8 ->
    lnxpak([H+1|L],I+1);
lnxpak(L,_I) ->
    L.

lnxfmt([I|L], Data) when Data > 0 ->
    [(I+192+1)|[ N+1 || N <- L]];
lnxfmt([I|L], Data) when Data < 0 ->
    [(I+192+1 bxor 255)|[ 101-N || N <- L]]++[102].

encode_date({{Year,Mon,Day}, {Hour,Min,Sec}}) ->
    <<
    (Year div 100 + 100),
    (Year rem 100 + 100),
    (Mon),
    (Day),
    (Hour + 1),
    (Min + 1),
    (Sec + 1)
    >>;
encode_date({{Year,Mon,Day}, {Hour,Min,Sec,Ms}}) ->
    <<(encode_date({{Year,Mon,Day}, {Hour,Min,Sec}}))/binary, (Ms * 1000):4/integer-unit:8>>;
encode_date({Year,Mon,Day}) when is_integer(Year)  ->
    encode_date({{Year,Mon,Day}, {0,0,0}});
encode_date({{Year,Mon,Day}, {Hour,Min,Sec,Ms}, Offset}) when is_integer(Offset) ->
    Secs = calendar:datetime_to_gregorian_seconds({{Year,Mon,Day}, {Hour,Min,Sec}}),
    {D, T} = calendar:gregorian_seconds_to_datetime(Secs - Offset),
    {H, M} = {(Offset div 3600 + 20), (Offset rem 3600 div 60 + 60)},
    <<(encode_date({D, erlang:append_element(T,Ms)}))/binary,H,M>>;
encode_date({{Year,Mon,Day}, {Hour,Min,Sec,Ms}, Data}) when is_list(Data) ->
    Zoneid = get_key(list_to_binary(Data), ?ZONEIDMAP),
    {D, T} = {{Year,Mon,Day}, {Hour,Min,Sec}},
    {H, M} = {((Zoneid band 8128) bsr 6) bor 128, ((Zoneid band 63) bsl 2)},
    <<(encode_date({D, erlang:append_element(T,Ms)}))/binary,H,M>>.

get_key(Data, [{Key, {_,Value}} | M]) ->
    case binary:match(Data,list_to_binary(Value)) of
        nomatch -> get_key(Data, M);
        _ -> Key
    end;
get_key(Data, [_|M]) -> get_key(Data, M);
get_key(_Data, []) -> 28.

encode_helper(type, Data) ->
    {lists:member(Data, ["SELECT", "WITH"]), lists:member(Data, ["INSERT", "UPDATE", "DELETE", "MERGE"])};
encode_helper(param, Data) ->
    Values =
    [
    {number, 0}, {integer, 0}, {float, 0}, {decimal, 0},
    {varchar, []}, {char, []}, {nvarchar, []}, {nchar, []}, {string, []}, {hexstring, []},
    {clob, clob}, {nclob, clob},
    {raw, <<>>}, {blob, <<>>}, {binary, <<>>},
    {date, {1900,1,1}}, {timestamp, {{1900,1,1}, {0,0,0,0}}}, {timestamptz, {{1900,1,1}, {0,0,0,0}, 0}}
    ],
    proplists:get_value(Data, Values, Data);
encode_helper(utf16, Data) ->
    case lists:member(Data, [?AL16UTF16_CHARSET,830,832,837,838,846,852,860,865,867,868]) of
        false -> Data;
        true -> ?UTF8_CHARSET
    end;
encode_helper(sess, L) ->
    Secs = calendar:datetime_to_gregorian_seconds(calendar:local_time()),
    USecs = calendar:datetime_to_gregorian_seconds(calendar:universal_time()),
    "ALTER SESSION SET TIME_ZONE='"++?DECODER:decode_helper(tz, (Secs - USecs) div 3600, L)++"'".
