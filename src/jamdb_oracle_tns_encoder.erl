-module(jamdb_oracle_tns_encoder).

%% API
-export([encode_packet/2]).
-export([encode_record/4]).
-export([encode_record/2]).
-export([encode_query/2]).
-export([encode_token/2]).

-include("TNS.hrl").
-include("jamdb_oracle.hrl").

%% API
encode_packet(Type, Data) ->
    case Type of
	?TNS_DATA ->
	    Length = byte_size(Data) + 10,
	    <<Length:16, 0:16, Type:8, 0:8, 0:16, 0:16, Data/binary>>;
	_ ->
	    Length = byte_size(Data) + 8,
	    <<Length:16, 0:16, Type:8, 0:8, 0:16, Data/binary>>
    end.

encode_record(auth, EnvOpts, Sess, Salt) ->
    User            = proplists:get_value(user, EnvOpts),
    Pass            = proplists:get_value(password, EnvOpts),
    {AuthPass, AuthSess, KeyConn} = jamdb_oracle_crypt:o5logon(Sess, Salt, Pass),
    {<<
    ?TTI_FUN,
    (encode_ub2(?TTI_AUTH))/binary,
    1,
    (encode_sb2(length(User)))/binary,
    (encode_sb2(1 bor 256))/binary,	%logon mode
    1,
    (encode_sb2(2))/binary,	%keyval count
    1,1,
    (encode_chr(string:to_upper(User)))/binary,
    (encode_keyval("AUTH_PASSWORD", AuthPass))/binary,
    (encode_keyval("AUTH_SESSKEY", AuthSess))/binary,
    1,1
    >>,
    KeyConn}.

encode_record(login, EnvOpts) ->
    {ok, UserHost}  = inet:gethostname(),
    User            = proplists:get_value(user, EnvOpts),
    Host            = proplists:get_value(host, EnvOpts), 
    Port            = proplists:get_value(port, EnvOpts),
    Sid             = proplists:get_value(sid, EnvOpts),
    AppName         = proplists:get_value(app_name, EnvOpts),
    Data = list_to_binary(
    "(DESCRIPTION=(CONNECT_DATA=(SID="++Sid++
    ")(CID=(PROGRAM="++AppName++
    ")(HOST="++UserHost++")(USER="++User++
    ")))(ADDRESS=(PROTOCOL=TCP)(HOST="++Host++
    ")(PORT="++integer_to_list(Port)++")))"),
    <<
    1,54,		% Packet version number
    1,44,		% Lowest compatible version number
    0,0,		% Global service options supported
    32,0,		% SDU
    127,255,		% TDU
    79,152,		% Protocol Characteristics
    0,0,		% Max packets before ACK
    0,1,		% 1 in hardware byte order
    (byte_size(Data)):16,	% Connect Data length
    0,58,		% Connect Data offset 
    0,0,0,0,		% Max connect data that can be received
    132,132,		% ANO disabled
    0:192,
    Data/binary
    >>;
encode_record(sess, EnvOpts) ->
    {ok, UserHost}  = inet:gethostname(),
    UserPID         = os:getpid(),
    User            = proplists:get_value(user, EnvOpts),
    AppName         = proplists:get_value(app_name, EnvOpts),
    <<
    ?TTI_FUN,
    (encode_ub2(?TTI_SESS))/binary,
    1,
    (encode_sb2(length(User)))/binary,
    (encode_sb2(1))/binary,	%logon mode
    1,
    (encode_sb2(4))/binary,	%keyval count
    1,1,
    (encode_chr(string:to_upper(User)))/binary,
    (encode_keyval("AUTH_PROGRAM_NM", AppName))/binary,
    (encode_keyval("AUTH_MACHINE", UserHost))/binary,
    (encode_keyval("AUTH_PID", UserPID))/binary,
    (encode_keyval("AUTH_SID", "erlang"))/binary
    >>;
encode_record(dty, _EnvOpts) ->
    <<
    ?TTI_DTY,
    (encode_ub2(?UTF8_CHARSET))/binary,	%cli in charset
    (encode_ub2(?UTF8_CHARSET))/binary,	%cli out charset
    2,
    38,6,1,0,0,10,1,1,6,1,1,1,1,1,1,0,41,144,3,7,3,0,1,0,79,1,55,4,0,0,0,0,12,0,0,6,0,1,1,
    7,2,0,0,0,0,0,0,
    1,1,1,0,2,2,10,0,8,8,1,0,12,12,10,0,23,23,1,0,24,24,1,0,
    25,25,1,0,26,26,1,0,27,27,1,0,28,28,1,0,29,29,1,0,30,30,1,0,31,31,1,0,
    32,32,1,0,33,33,1,0,
    10,10,1,0,11,11,1,0,40,
    40,1,0,41,41,1,0,117,117,1,0,120,120,1,0,34,34,1,0,35,35,1,0,36,36,1,0,37,37,1,0,
    38,38,1,0,42,42,1,0,43,43,1,0,44,44,1,0,45,45,1,0,46,46,1,0,47,47,1,0,48,48,1,0,
    49,49,1,0,50,50,1,0,51,51,1,0,52,52,1,0,53,53,1,0,54,54,1,0,55,55,1,0,56,56,1,0,
    57,57,1,0,59,59,1,0,60,60,1,0,61,61,1,0,62,62,1,0,63,63,1,0,64,64,1,0,65,65,1,0,
    66,66,1,0,67,67,1,0,71,71,1,0,72,72,1,0,73,73,1,0,75,75,1,0,77,77,1,0,78,78,1,0,
    79,79,1,0,80,80,1,0,81,81,1,0,82,82,1,0,83,83,1,0,84,84,1,0,85,85,1,0,86,86,1,0,
    87,87,1,0,88,88,1,0,89,89,1,0,90,90,1,0,92,92,1,0,93,93,1,0,98,98,1,0,99,99,1,0,
    103,103,1,0,107,107,1,0,124,124,1,0,125,125,1,0,126,126,1,0,127,127,1,0,128,128,1,0,
    129,129,1,0,130,130,1,0,131,131,1,0,132,132,1,0,133,133,1,0,134,134,1,0,135,135,1,0,
    137,137,1,0,138,138,1,0,139,139,1,0,140,140,1,0,141,141,1,0,142,142,1,0,143,143,1,0,
    144,144,1,0,145,145,1,0,148,148,1,0,149,149,1,0,150,150,1,0,151,151,1,0,157,157,1,0,
    158,158,1,0,159,159,1,0,160,160,1,0,161,161,1,0,162,162,1,0,163,163,1,0,164,164,1,0,
    165,165,1,0,166,166,1,0,167,167,1,0,168,168,1,0,169,169,1,0,170,170,1,0,171,171,1,0,
    173,173,1,0,174,174,1,0,175,175,1,0,176,176,1,0,177,177,1,0,193,193,1,0,194,194,1,0,
    198,198,1,0,199,199,1,0,200,200,1,0,201,201,1,0,202,202,1,0,203,203,1,0,204,204,1,0,
    205,205,1,0,206,206,1,0,207,207,1,0,210,210,1,0,211,211,1,0,212,212,1,0,213,213,1,0,
    214,214,1,0,215,215,1,0,216,216,1,0,217,217,1,0,218,218,1,0,219,219,1,0,220,220,1,0,
    221,221,1,0,222,222,1,0,223,223,1,0,224,224,1,0,225,225,1,0,226,226,1,0,227,227,1,0,
    228,228,1,0,229,229,1,0,230,230,1,0,234,234,1,0,235,235,1,0,236,236,1,0,237,237,1,0,
    238,238,1,0,239,239,1,0,240,240,1,0,242,242,1,0,243,243,1,0,244,244,1,0,245,245,1,0,
    246,246,1,0,253,253,1,0,254,254,1,0,1,1,1,0,2,2,1,0,4,4,1,0,5,5,1,0,6,6,1,0,7,7,1,0,
    8,8,1,0,9,9,1,0,10,10,1,0,11,11,1,0,12,12,1,0,13,13,1,0,14,14,1,0,15,15,1,0,16,16,1,0,
    17,17,1,0,18,18,1,0,19,19,1,0,20,20,1,0,21,21,1,0,22,22,1,0,23,23,1,0,24,24,1,0,
    25,25,1,0,26,26,1,0,27,27,1,0,28,28,1,0,29,29,1,0,30,30,1,0,31,31,1,0,48,48,1,0,
    53,53,1,0,60,60,1,0,61,61,1,0,62,62,1,0,63,63,1,0,64,64,1,0,66,66,1,0,68,68,1,0,
    69,69,1,0,70,70,1,0,71,71,1,0,72,72,1,0,73,73,1,0,
    3,2,10,0,4,2,10,0,5,1,1,0,6,2,10,0,7,2,10,0,9,1,1,0,13,0,14,0,15,23,1,0,16,0,17,0,
    18,0,19,0,20,0,21,0,22,0,39,120,1,0,58,0,68,2,10,0,69,0,70,0,74,0,76,0,91,2,10,0,
    94,1,1,0,95,23,1,0,96,96,1,0,97,96,1,0,100,100,1,0,101,101,1,0,102,102,1,0,
    104,11,1,0,105,0,106,106,1,0,108,109,1,0,109,109,1,0,110,111,1,0,111,111,1,0,
    112,112,1,0,113,113,1,0,114,114,1,0,115,115,1,0,116,102,1,0,118,0,119,0,121,0,122,0,
    123,0,136,0,146,146,1,0,147,0,152,2,10,0,153,2,10,0,154,2,10,0,155,1,1,0,156,12,10,0,
    172,2,10,0,178,178,1,0,179,179,1,0,180,180,1,0,181,181,1,0,182,182,1,0,183,183,1,0,
    184,12,10,0,185,185,1,0,186,186,1,0,187,187,1,0,188,188,1,0,189,189,1,0,190,190,1,0,
    191,0,192,0,195,112,1,0,196,113,1,0,197,114,1,0,208,208,1,0,209,0,231,231,1,0,
    232,231,1,0,233,233,1,0,241,109,1,0,3,0,78,78,1,0,79,79,1,0,80,80,1,0,0
    >>;
encode_record(pro, _EnvOpts) ->
    <<
    ?TTI_PRO,
    6,5,4,3,2,1,0,
    74,97,118,97,95,84,84,67,45,56,46,50,46,48,0
    >>;
encode_record(ver, _EnvOpts) ->
    <<
    ?TTI_FUN,
    (encode_ub2(?TTI_VERSION))/binary,
    1,
    (encode_sb2(256))/binary,
    1,1
    >>;
encode_record(func, Num) ->
    <<
    ?TTI_FUN,
    (encode_ub2(Num))/binary
    >>;
encode_record(fetch, Cursor) ->
    <<
    ?TTI_FUN,
    (encode_ub2(?TTI_FETCH))/binary,
    (encode_sb4(Cursor))/binary,	%cursor
    (encode_sb4(?TTI_ROW))/binary	%rows to fetch
    >>;
encode_record(close, Cursors) ->
    <<
    ?TTI_PFN,
    (encode_ub2(?TTI_OCCA))/binary,
    1,
    (encode_sb4(length(Cursors)))/binary,  %cursors count
    (encode_array(Cursors))/binary,        %cursors
    ?TTI_FUN,
    (encode_ub2(?TTI_LOGOFF))/binary
    >>.

encode_query(Query, Bind) ->
    BindLen = length(Bind),
    QueryPos =
    case lists:nth(1, string:tokens(string:to_upper(Query)," \t")) of
	"SELECT" -> 1;
	"BEGIN" -> -1;
	_ -> 0
    end,
    {BindPos, Opt, LMax, Max, Rows, Alt} = setopts(QueryPos, BindLen),
    <<
    ?TTI_FUN,
    (encode_ub2(?TTI_ALL8))/binary,
    (encode_sb4(Opt))/binary,		%options
    0,					%cursor
    1,					%query not empty
    (encode_sb4(length(Query)))/binary,	%query length
    1,					%alt not empty
    (encode_sb4(length(Alt)))/binary,   %alt length
    0,0,
    (encode_sb4(LMax))/binary,		%long max value
    (encode_sb4(Rows))/binary,		%rows to fetch
    (encode_sb4(Max))/binary,		%max value
    BindPos,				%bindpos
    (encode_sb4(BindLen))/binary,	%bindpos count
    0,0,0,0,0,
    0,					%no defcols
    0,					%defcols
    0,					%registration
    0,1,0,0,0,0,0,
    (encode_chr(Query))/binary,
    (encode_array(Alt))/binary,
    (encode_token(Bind))/binary
    >>.

setopts(QueryPos, BindLen) when QueryPos > 0, BindLen =:= 0 ->	%%select
    {0, 32801, 4294967295, 2147483647, ?TTI_ROW, [1,0,0,0,0,0,0,1,0,0,0,0,0]};
setopts(QueryPos, BindLen) when QueryPos > 0, BindLen > 0 ->
    {1, 32801 bor 8, 4294967295, 2147483647, ?TTI_ROW, [1,0,0,0,0,0,0,1,0,0,0,0,0]};
setopts(QueryPos, BindLen) when QueryPos =:= 0, BindLen =:= 0 ->	%%crud
    {0, 32801 bor 256, 0, 2147483647, 0, [1,1,0,0,0,0,0,0,0,0,0,0,0]};
setopts(QueryPos, BindLen) when QueryPos =:= 0, BindLen > 0 ->
    {1, 32801 bor 8 bor 256, 0, 2147483647, 0, [1,1,0,0,0,0,0,0,0,0,0,0,0]};
setopts(QueryPos, BindLen) when QueryPos < 0, BindLen =:= 0 ->	%%call
    {0, 1057 bor 256, 0, 32760, 0, [1,1,0,0,0,0,0,0,0,0,0,0,0]};
setopts(QueryPos, BindLen) when QueryPos < 0, BindLen > 0 ->
    {1, 1057 bor 8 bor 256, 0, 32760, 0, [1,1,0,0,0,0,0,0,0,0,0,0,0]}.


encode_token([]) ->
    <<>>;
encode_token(Data) ->
    encode_token(Data, <<(encode_token(oac, Data, <<>>))/binary, ?TTI_RXD>>).

encode_token([], Acc) ->
    Acc;
encode_token([Data|L], Acc) when is_list(Data) ->
    Bin = encode_token(rxd, Data),
    encode_token(L, <<Acc/binary, Bin/binary>>);
encode_token([Data|L], Acc) ->
    Bin = encode_token(rxd, Data),
    encode_token(L, <<Acc/binary, (encode_ub1(byte_size(Bin)))/binary, Bin/binary>>);
encode_token(rxd, Data) when is_list(Data) -> encode_chr(Data);
encode_token(rxd, Data) when is_number(Data) -> encode_number(Data);
encode_token(rxd, Data) when is_tuple(Data) -> encode_date(Data);
encode_token(oac, Data) when is_list(Data) -> encode_token(oac, ?TNS_TYPE_VARCHAR, 32766, 16, ?UTF8_CHARSET);
encode_token(oac, Data) when is_number(Data) -> encode_token(oac, ?TNS_TYPE_NUMBER, 22, 0, 0);
encode_token(oac, Data) when is_tuple(Data) -> encode_token(oac, ?TNS_TYPE_DATE, 7, 0, 0).

encode_token(oac, [], Acc) ->
    Acc;
encode_token(oac, [Data|L], Acc) ->
    encode_token(oac, L, <<Acc/binary, (encode_token(oac, Data))/binary>>).

encode_token(oac, Type, Length, Flag, Charset) ->
    <<
    (encode_ub1(Type))/binary,		%%data type
    (encode_ub1(3))/binary,		%%flg
    (encode_ub1(0))/binary,		%%pre
    (case Type of
	2 -> encode_sb4(0);
	_ -> encode_ub1(0)
    end)/binary,			%%data scale
    (encode_sb4(Length))/binary,	%%max data lenght
    (encode_sb4(0))/binary,		%%mal
    (encode_sb4(Flag))/binary,		%%fl2
    (encode_dalc(<<>>))/binary,		%%toid
    (encode_sb4(0))/binary,		%%vsn
    (encode_sb4(Charset))/binary,	%%charset
    (encode_ub1(1))/binary,		%%form of use
    (encode_sb4(0))/binary		%%mxlc
    >>.

%%lager:log(info,self(),"~p",[Data]),

encode_keyval(Key, Value) when is_list(Key), is_list(Value) ->
    BinKey = unicode:characters_to_binary(Key),
    BinValue = unicode:characters_to_binary(Value),
    encode_keyval(BinKey, BinValue);
encode_keyval(Key, Value) when is_binary(Key), is_binary(Value) ->
    KeyLen = byte_size(Key),
    ValueLen = byte_size(Value),
    Data = encode_chr(Value),
    BinKey =
    case KeyLen of
	0 -> <<0>>;
	_ -> <<(encode_sb4(KeyLen))/binary, (encode_chr(Key))/binary>>
    end,
    BinValue =
    case ValueLen of
	0 -> <<0>>;
	_ -> <<(encode_sb4(ValueLen))/binary, Data/binary>>
    end,
    BinData =
    case binary:last(Data) of
	0 -> <<>>;
	_ -> <<0>>
    end,
    <<BinKey/binary, BinValue/binary, BinData/binary>>.

encode_ub1(Data) ->
    <<Data:8>>.

encode_ub2(Data) ->
    <<Data:16/little>>.

%encode_sb1(Data) ->
%    encode_sb2(Data).

encode_sb2(Data) ->
    encode_sb4(Data).

encode_sb4(0) ->
    <<0>>;
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

encode_array(Data) ->
    encode_array(Data,<<>>).

encode_array([],Acc) ->
    Acc;
encode_array([H|T],Acc) ->
    encode_array(T,<<Acc/binary,(encode_sb4(H))/binary>>).

encode_dalc(<<>>) ->
    <<0>>;
encode_dalc(Data) ->
    <<(encode_sb4(byte_size(Data)))/binary,(encode_chr(Data))/binary>>.

encode_chr(Data) when is_list(Data) ->
    Binary = unicode:characters_to_binary(Data,utf8,latin1),
    encode_chr(Binary);
encode_chr(Data) when byte_size(Data) > 64 ->
    encode_chr(Data,<<254>>);
encode_chr(Data) ->
    Length = byte_size(Data),
    <<Length, Data:Length/binary>>.

encode_chr(Data,Acc) when byte_size(Data) > 64 ->
    <<Prefix:64/binary,Rest/bits>> = Data,
    encode_chr(Rest,<<Acc/binary, 64, Prefix/binary>>);
encode_chr(Data,Acc) ->
    Length = byte_size(Data),
    <<Acc/binary, Length, Data:Length/binary, 0>>.

encode_number(0) ->
    <<128>>;
encode_number(Data) when is_integer(Data) ->
    list_to_binary([<<B>> || B <- to_lnxfmt(lnxmin(abs(Data),1,[]), Data)]);
encode_number(Data) when is_float(Data) ->
    list_to_binary([<<B>> || B <- to_lnxfmt(lnxren(abs(Data),0), Data)]).

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

to_lnxfmt([I|L], Data) when Data > 0 ->
    [to_byte(I+192+1)|[ N+1 || N <- L]];
to_lnxfmt([I|L], Data) when Data < 0 ->
    [to_byte(I+192+1 bxor 255)|[ 101-N || N <- L]]++[102].

to_byte(Byte) ->
    [Int] = [B || <<B:1/little-signed-integer-unit:8>> <= <<Byte>>],
    Int.

encode_date({Year,Month,Day}) ->
    encode_date({{Year,Month,Day}, {0,0,0}});
encode_date({{Year,Month,Day}, {Hour,Minute,Second}}) ->
    <<
    (Year div 100 + 100),
    (Year rem 100 + 100),
    (Month),
    (Day),
    (Hour + 1),
    (Minute + 1),
    (Second + 1)
    >>.
