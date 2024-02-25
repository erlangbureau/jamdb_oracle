-module(jamdb_oracle_binpp).

-export([pprint/1, pprint/2, pprint/3]).

-export_type([opt/0, opts/0]).

-opaque opt()  :: {return, iolist} | {return, binary} | {printer, function()}.
-opaque opts() :: list(opt()).

-define(SPACE,    $ ).
-define(SPECIAL,  $.).
-define(FILL,     $0).

%% API
-spec pprint(binary() | bitstring()) -> ok.
pprint(Bin) ->
    pprint(Bin, []).

-spec pprint(binary() | bitstring(), opts()) -> ok | any().
pprint(Bin, Opts) when is_list(Opts) ->
    {ok, Octets} = convert(Bin, hex),
    Buckets = buckets(16, Octets),
    Printed = print_buckets(Buckets),
    apply_opts(Printed, Opts).

-spec pprint(binary() | bitstring(), {non_neg_integer(), non_neg_integer()},
             opts()) -> ok | any().
pprint(Bin, {Pos, Len}, Opts) when Len =< byte_size(Bin), (Pos+Len) =< byte_size(Bin) ->
    pprint(binary:part(Bin, Pos, Len), Opts);
pprint(Bin, {Pos, _}, Opts) ->
    pprint(binary:part(Bin, Pos, byte_size(Bin)-Pos), Opts).

%% internal
-spec apply_opts(iolist(), opts()) -> ok | iolist() | binary().
apply_opts(IoList, []) ->
    io:format("~s~n", [IoList]);
apply_opts(IoList, [{return, iolist}]) ->
    IoList;
apply_opts(IoList, [{return, binary}]) ->
    iolist_to_binary(IoList);
apply_opts(IoList, [{printer, Fun}]) when is_function(Fun) ->
    Fun(IoList);
apply_opts(_, _) -> erlang:error(badarg).

-spec convert(binary() | bitstring(), hex | bin) -> {ok, list()}.
convert(Bin, hex) when is_binary(Bin) orelse is_bitstring(Bin) ->
    convert(Bin, [], fun byte_to_hexstr/1);
convert(Bin, bin) when is_binary(Bin) orelse is_bitstring(Bin) ->
    convert(Bin, [], fun byte_to_binstr/1).

-spec convert(binary() | bitstring(), list(), function()) -> {ok, string()}.
convert(<<>>, Acc, _) ->
    {ok, lists:reverse(Acc)};
convert(Bin, [], FormatFun) when is_bitstring(Bin), not is_binary(Bin) ->
    %% byte align bistring() to make a complementary binary()
    Align = (8 - (bit_size(Bin) rem 8)),
    convert(<<Bin/bitstring, 0:Align>>, [], FormatFun);
convert(<<Bin:8/integer, Rest/binary>>, SoFar, FormatFun) ->
    convert(Rest, [FormatFun(Bin)|SoFar], FormatFun).

print_buckets(Buckets) ->
    {Printed, _} = lists:mapfoldl(fun(Bucket, Offset) ->
            B = print_bucket(Bucket),
            Annotated = io_lib:format("~4.16.0B ~s", [Offset, B]),
            {Annotated, Offset+1}
        end, 0, Buckets),
    Printed.

print_bucket(Bucket) ->
    OctetLine = string:join(Bucket, [?SPACE]),
    OctetRepr = lists:map(
            fun(B) ->
                case list_to_integer(B, 16) of
                    Code when Code >= ?SPACE -> Code;
                    _ -> ?SPECIAL
                end
            end,
            Bucket),
    io_lib:format("~s ~s~n", [string:left(OctetLine, 16*2 + 16, ?SPACE), OctetRepr]).

-spec byte_to_hexstr(byte()) -> string().
byte_to_hexstr(B) when B >= 0, B =< 255 ->
    to_hexstr(B, 16, 2).

-spec byte_to_binstr(byte()) -> string().
byte_to_binstr(B) when B >= 0, B =< 255 ->
    to_hexstr(B, 2, 8).

-spec to_hexstr(byte(), non_neg_integer(), non_neg_integer()) -> string().
to_hexstr(B, Base, Len) ->
    string:right(integer_to_list(B, Base), Len, ?FILL).

-spec buckets(non_neg_integer(), list()) -> list(list()).
buckets(N, L) ->
    buckets(1, N, length(L) div N, L, [[]]).
buckets(_, _, 0, [], [[]|Acc]) ->
    lists:reverse(Acc);
buckets(_, _, 0, Rest, [[]|Acc]) ->
    lists:reverse([Rest|Acc]);
buckets(N, N, M, [H|T], [A|Acc]) ->
    buckets(1, N, M-1, T, [[], lists:reverse([H|A]) | Acc]);
buckets(X, N, M, [H|T], [A|Acc]) ->
    buckets(X+1, N, M, T, [[H|A]|Acc]).
