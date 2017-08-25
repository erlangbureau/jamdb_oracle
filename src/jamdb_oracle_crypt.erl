-module(jamdb_oracle_crypt).

-export([o5logon/4]).
-export([validate/2]).

%%====================================================================
%% callbacks
%%====================================================================

o5logon(Sess, User, Pass, Bits) when is_list(Sess), Bits =:= 128 ->
    IVec = <<0:64>>,
    CliPass = norm(User++Pass),
    Rest1 = crypto:block_encrypt(des_cbc, hexstr2bin("0123456789ABCDEF"), IVec, CliPass),
    Rest2 = crypto:block_encrypt(des_cbc, binary:part(Rest1,byte_size(Rest1),-8), IVec, CliPass),
    KeySess = <<(binary:part(Rest2,byte_size(Rest2),-8))/binary,0:64>>,
    o5logon(hexstr2bin(Sess), KeySess, Pass, Bits);
o5logon(Sess, Salt, Pass, Bits) when is_list(Sess), Bits =:= 192 ->
    Data = crypto:hash(sha,<<(list_to_binary(Pass))/binary,(hexstr2bin(Salt))/binary>>),
    KeySess = <<Data/binary,0:32>>,
    o5logon(hexstr2bin(Sess), KeySess, Pass, Bits);
o5logon(Sess, KeySess, Pass, Bits) when is_binary(Sess) ->
    IVec = <<0:128>>,
    SrvSess = jose_jwa_aes:block_decrypt({aes_cbc, Bits}, KeySess, IVec, Sess),
    CliSess = crypto:strong_rand_bytes(Bits div 4),
    AuthSess = jose_jwa_aes:block_encrypt({aes_cbc, Bits}, KeySess, IVec, CliSess),
    CatKey = cat_key(binary:part(SrvSess,16,Bits div 8),binary:part(CliSess,16,Bits div 8),[]),
    KeyConn = conn_key(CatKey, Bits),
    AuthPass = jose_jwa_aes:block_encrypt({aes_cbc, Bits}, KeyConn, IVec, pad(Pass)),
    {bin2hexstr(AuthPass), bin2hexstr(AuthSess), bin2hexstr(KeyConn)}.

validate(Resp, KeyConn) ->
    IVec = <<0:128>>,
    Bits = length(KeyConn) * 4,
    Data = jose_jwa_aes:block_decrypt({aes_cbc, Bits}, hexstr2bin(KeyConn), IVec, hexstr2bin(Resp)),    
    case binary:match(Data,<<"SERVER_TO_CLIENT">>) of
	nomatch -> error;
	_ -> ok
    end.

%%====================================================================
%% Internal misc
%%====================================================================

conn_key(Data, Bits) when Bits =:= 128 ->  
    <<(erlang:md5(Data))/binary>>;
conn_key(Data, Bits) when Bits =:= 192 ->  
    <<(erlang:md5(binary:part(Data,0,16)))/binary,
      (binary:part(erlang:md5(binary:part(Data,16,8)),0,8))/binary>>.

cat_key(<<>>,<<>>,S) ->
    list_to_binary(S);
cat_key(<<H, X/bits>>,<<L, Y/bits>>,S) ->
    cat_key(X,Y,S++[H bxor L]).

norm(Data) ->
    L = length(Data) * 2,
    S = norm(list_to_binary(Data),[]),
    N = case L rem 8 > 0 of
	true -> 1;
	false -> 0	
    end,
    P = (L div 8 + N) * 8 - L,
    <<(list_to_binary(S))/binary, (binary:copy(<<0>>, P))/binary>>.

norm(<<>>,S) ->
    S;
norm(<<U/utf8,R/binary>>,S) ->
    C = case U of
	N when N > 255 -> 63;
	N when N >= 97, N =< 122 -> N-32;
	N -> N
    end,
    norm(R,S++[0,C]).

pad(S) ->
    P = 16 - (length(S) rem 16),
    <<(pad(16,<<>>))/binary, (pad(P,list_to_binary(S)))/binary>>.

pad(P, Bin) -> <<Bin/binary, (binary:copy(<<P>>, P))/binary>>.

hexstr2bin(S) ->
    list_to_binary(hexstr2list(S)).

hexstr2list([X,Y|T]) ->
    [mkint(X)*16 + mkint(Y) | hexstr2list(T)];
hexstr2list([]) ->
    [].
mkint(C) when $0 =< C, C =< $9 ->
    C - $0;
mkint(C) when $A =< C, C =< $F ->
    C - $A + 10;
mkint(C) when $a =< C, C =< $f ->
    C - $a + 10.

bin2hexstr(Bin) when is_binary(Bin) ->
    binary_to_list(bin2hex(Bin)).

bin2hex(Bin) when is_binary(Bin) ->
    << <<(mkhex(H)),(mkhex(L))>> || <<H:4,L:4>> <= Bin >>.
mkhex(C) when C < 10 -> $0 + C;
mkhex(C) -> $A + C - 10.
