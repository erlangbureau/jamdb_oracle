-module(test_debug).
-export([test/0]).

test() ->
    %% Enable debug logging
    Opts = [
        {host, "YOUR_HOST"},
        {port, 1521},
        {user, "YOUR_USER"},
        {password, "YOUR_PASSWORD"},
        {service_name, "YOUR_SERVICE"},
        {debug, true}  % Enable debug logging
    ],

    io:format("~n=== Connecting with debug logging enabled ===~n"),
    case jamdb_oracle:connect(Opts) of
        {ok, _, State} ->
            io:format("~n✓ Connection successful!~n"),
            jamdb_oracle:disconnect(State);
        {error, Type, Reason, _State} ->
            io:format("~n✗ Connection failed:~n"),
            io:format("  Type: ~p~n", [Type]),
            io:format("  Reason: ~p~n", [Reason])
    end.
