-module(jamdb_oracle_crypt).

%% API
-export([generate/1]).
-export([validate/1]).

-include("jamdb_oracle.hrl").

%% API
%o3logon(#logon{auth=Sess, key=KeySess, password=Pass}) ->
%    IVec = <<0:64>>,
%    SrvSess = block_decrypt(des_cbc, binary:part(KeySess,0,8), IVec, Sess),
%    N = (8 - (length(Pass) rem 8 )) rem 8,
%    CliPass = <<(list_to_binary(Pass))/binary, (binary:copy(<<0>>, N))/binary>>,
%    AuthPass = block_encrypt(des_cbc, binary:part(SrvSess,0,8), IVec, CliPass),
%    #logon{password=hexify(AuthPass)++[N]}.

o5logon(#logon{auth=Sess, user=User, password=Pass, bits=128} = Logon) ->
    IVec = <<0:64>>,
    CliPass = norm(User++Pass),
    B1 = block_encrypt(des_cbc, unhex("0123456789ABCDEF"), IVec, CliPass),
    B2 = block_encrypt(des_cbc, binary:part(B1,byte_size(B1),-8), IVec, CliPass),
    KeySess = <<(binary:part(B2,byte_size(B2),-8))/binary,0:64>>,
    generate(Logon#logon{auth=unhex(Sess), key=KeySess});
o5logon(#logon{auth=Sess, salt=Salt, password=Pass, bits=192} = Logon) ->
    Data = crypto:hash(sha,<<(list_to_binary(Pass))/binary,(unhex(Salt))/binary>>),
    KeySess = <<Data/binary,0:32>>,
    generate(Logon#logon{auth=unhex(Sess), key=KeySess});
o5logon(#logon{auth=Sess, salt=Salt, password=Pass, bits=256} = Logon) ->
    Data = pbkdf2(sha512, 64, 4096, 64, Pass, <<(unhex(Salt))/binary,"AUTH_PBKDF2_SPEEDY_KEY">>),
    KeySess = binary:part(crypto:hash(sha512, <<Data/binary, (unhex(Salt))/binary>>),0,32),
    generate(Logon#logon{auth=unhex(Sess), key=KeySess,
    der_key = <<(crypto:strong_rand_bytes(16))/binary, Data/binary>>}).

generate(#logon{type=Type,bits=undefined} = Logon) ->
    Bits =
    case Type of
        2361 -> 128;
        6949 -> 192;
        18453 -> 256
    end,
    o5logon(Logon#logon{bits=Bits});
generate(#logon{auth=Sess, key=KeySess, der_salt=DerivedSalt, der_key=DerivedKey, 
                password=Pass, newpassword=NewPass, bits=Bits} = Logon) ->
    IVec = <<0:128>>,
    Cipher = cipher(Bits),
    SrvSess = block_decrypt(Cipher, KeySess, IVec, Sess),
    CliSess =
    case binary:match(SrvSess,pad(8, <<>>)) of
        {40,8} -> pad(8, crypto:strong_rand_bytes(40));
        _ -> crypto:strong_rand_bytes(byte_size(SrvSess))
    end,
    AuthSess = block_encrypt(Cipher, KeySess, IVec, CliSess),
    CatKey = cat_key(SrvSess, CliSess, DerivedSalt, Bits),
    KeyConn = conn_key(CatKey, DerivedSalt, Bits),
    AuthPass = block_encrypt(Cipher, KeyConn, IVec, pad(Pass)),
    AuthNewPass =
    case NewPass of
        [] -> <<>>;
        _ -> block_encrypt(Cipher, KeyConn, IVec, pad(NewPass))
    end,
    SpeedyKey =
    case DerivedKey of
        undefined -> <<>>;
        _ -> block_encrypt(Cipher, KeyConn, IVec, DerivedKey)
    end,
    Logon#logon{auth=list_to_binary(hexify(AuthSess)), key=KeyConn, speedy_key=hexify(SpeedyKey),
    password=hexify(AuthPass), newpassword=hexify(AuthNewPass)}.

validate(#logon{auth=Resp, key=KeyConn}) ->
    IVec = <<0:128>>,
    Cipher = cipher(byte_size(KeyConn) * 8),
    Data = block_decrypt(Cipher, KeyConn, IVec, unhex(Resp)),
    case binary:match(Data,<<"SERVER_TO_CLIENT">>) of
        nomatch -> error;
        _ -> ok
    end.

%% internal
cipher(128) -> aes_128_cbc;
cipher(192) -> aes_192_cbc;
cipher(256) -> aes_256_cbc.

conn_key(Key, undefined, 128) ->
    <<(erlang:md5(Key))/binary>>;
conn_key(Key, undefined, 192) ->
    <<(erlang:md5(binary:part(Key,0,16)))/binary,
    (binary:part(erlang:md5(binary:part(Key,16,8)),0,8))/binary>>;
conn_key(Key, DerivedSalt, Bits) ->
    pbkdf2(sha512, 64, 3, Bits div 8, hexify(Key), unhex(DerivedSalt)).

cat_key(Key, Key2, undefined, Bits) ->
    cat_key(binary:part(Key, 16, Bits div 8),binary:part(Key2, 16, Bits div 8),[]);
cat_key(Key, Key2, _DerivedSalt, Bits) ->
    <<(binary:part(Key2, 0, Bits div 8))/binary,(binary:part(Key, 0, Bits div 8))/binary>>.

cat_key(<<>>,<<>>,S) ->
    list_to_binary(S);
cat_key(<<A, Rest/bits>>,<<B, Rest2/bits>>,S) ->
    cat_key(Rest,Rest2,S++[A bxor B]).

norm(Data) ->
    Bin = norm(list_to_binary(Data),[]),
    N = (8 - (byte_size(Bin) rem 8 )) rem 8,
    <<Bin/binary, (binary:copy(<<0>>, N))/binary>>.

norm(<<>>,S) ->
    list_to_binary(S);
norm(<<A/utf8, Rest/bits>>,S) ->
    B = case A of
        N when N > 255 -> 63;
        N when N >= 97, N =< 122 -> N-32;
        N -> N
    end,
    norm(Rest,S++[0,B]).

pad(S) ->
    P = 16 - (length(S) rem 16),
    <<(pad(16,<<>>))/binary, (pad(P,list_to_binary(S)))/binary>>.

pad(P, Bin) -> <<Bin/binary, (binary:copy(<<P>>, P))/binary>>.

unhex(S) ->
    list_to_binary(unhex(S, [])).

unhex([], Acc) ->
    lists:reverse(Acc);
unhex([A, B | S], Acc) ->
    unhex(S, [list_to_integer([A, B], 16) | Acc]).

hexify(Bin) ->
    [hex_byte(B) || B <- binary_to_list(Bin)].

hex_byte(B) when B < 16 -> "0"++integer_to_list(B, 16);
hex_byte(B) -> integer_to_list(B, 16).

block_encrypt(Cipher, Key, Ivec, Data) ->
    crypto:crypto_one_time(Cipher, Key, Ivec, Data, true).

block_decrypt(Cipher, Key, Ivec, Data) ->
    crypto:crypto_one_time(Cipher, Key, Ivec, Data, false).

%pbkdf2(Type, MacLength, Count, Length, Pass, Salt) ->
%    pubkey_pbe:pbdkdf2(Pass, Salt, Count, Length, fun pbdkdf2_hmac/4, Type, MacLength).

%pbdkdf2_hmac(Type, Key, Data, MacLength) ->
%    crypto:macN(hmac, Type, Key, Data, MacLength).

pbkdf2(Type, MacLength, Count, Length, Pass, Salt) ->
    Mac = fun(Key, Data) -> crypto:macN(hmac, Type, Key, Data, MacLength) end,
    pbkdf2(Mac, 1, 1, Count, Length, Pass, Salt, <<>>).

pbkdf2(Mac, Reps, Reps, Count, Length, Pass, Salt, Acc) ->
    DerivedKey = << Acc/binary, (pbkdf2_exor(Mac, Pass, Salt, 1, Count, Reps, <<>>, <<>>))/binary >>,
    binary:part(DerivedKey, 0, Length);
pbkdf2(Mac, Num, Reps, Count, Length, Pass, Salt, Acc) ->
    pbkdf2(Mac, Num + 1, Reps, Count, Length, Pass, Salt,
    << Acc/binary, (pbkdf2_exor(Mac, Pass, Salt, 1, Count, Num, <<>>, <<>>))/binary >>).

pbkdf2_exor(_Mac, _Pass, _Salt, I, Count, _Num, _Prev, Acc) when I > Count ->
    Acc;
pbkdf2_exor(Mac, Pass, Salt, I = 1, Count, Num, <<>>, <<>>) ->
    Next = Mac(Pass, << Salt/binary, Num:1/integer-unit:32 >>),
    pbkdf2_exor(Mac, Pass, Salt, I + 1, Count, Num, Next, Next);
pbkdf2_exor(Mac, Pass, Salt, I, Count, Num, Prev, Acc) ->
    Next = Mac(Pass, Prev),
    pbkdf2_exor(Mac, Pass, Salt, I + 1, Count, Num, Next, crypto:exor(Next, Acc)).
