-module(jamdb_oracle_crypt).

-export([o5logon/3]).
-export([validate/2]).

%%====================================================================
%% callbacks
%%====================================================================

o5logon(Sess, Salt, Pass) ->
    Data = crypto:hash(sha,<<(list_to_binary(Pass))/binary,(hexstr2bin(Salt))/binary>>),
    KeySess = <<Data/binary,0:32>>,
    IVec = <<0:128>>,
    SrvSess = jose_jwa_aes:block_decrypt({aes_cbc, 192}, KeySess, IVec, hexstr2bin(Sess)),
    CliSess = crypto:rand_bytes(48),
    AuthSess = jose_jwa_aes:block_encrypt({aes_cbc, 192}, KeySess, IVec, CliSess),
    KeyConn = catkeys(SrvSess,CliSess),
    PadPass = 16 * ((16 + length(Pass)) div 16 + 1) - (16 + length(Pass)),
    CliPass = <<(pad(16,<<>>))/binary,(pad(PadPass,list_to_binary(Pass)))/binary>>,
    AuthPass = jose_jwa_aes:block_encrypt({aes_cbc, 192}, KeyConn, IVec, CliPass),
    {bin2hexstr(AuthPass), bin2hexstr(AuthSess), bin2hexstr(KeyConn)}.

validate(Resp,KeyConn) ->
    IVec = <<0:128>>,
    Data = jose_jwa_aes:block_decrypt({aes_cbc, 192}, hexstr2bin(KeyConn), IVec, hexstr2bin(Resp)),
    case binary:match(Data,<<"SERVER_TO_CLIENT">>) of
	nomatch ->
	    {error, validate_failed};
	_ ->
	    ok
    end.

catkeys(Data1,Data2) ->
    catkeys(binary:part(Data1,16,24),binary:part(Data2,16,24),[]).

catkeys(<<>>,<<>>,Acc) ->
    C = list_to_binary([<<B>> || B <- Acc]),
    <<(erlang:md5(binary:part(C,0,16)))/binary,
      (binary:part(erlang:md5(binary:part(C,16,8)),0,8))/binary>>;
catkeys(<<B1,Rest1/bits>>,<<B2,Rest2/bits>>,Acc) ->
    C = [B || <<B:1/little-signed-integer-unit:8>> <= <<(B1 bxor B2)>>],
    catkeys(<<Rest1/binary>>,<<Rest2/binary>>,lists:append(Acc,C)).

pad(P, Bin) -> << Bin/binary, (binary:copy(<<P>>, P))/binary >>.
    
%%====================================================================
%% Internal misc
%%====================================================================

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
