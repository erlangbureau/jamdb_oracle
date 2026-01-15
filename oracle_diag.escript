#!/usr/bin/env escript
%% Oracle Connection Diagnostic Test
%% Usage: escript oracle_diag.erl <database>

main([DatabaseName | _]) ->
    io:format("~n=== Oracle Connection Diagnostic Test ===~n", []),
    io:format("Database: ~s~n~n", [DatabaseName]),

    %% Test 1: Native Encryption (TCP port 1521)
    io:format("Test 1: Native Encryption (TCP:1521)~n", []),
    io:format("----------------------------------------~n"),
    Result1 = test_connection(DatabaseName, 1521, []),
    print_result(Result1),

    %% Test 2: SSL/TLS (port 2484)
    io:format("~n~nTest 2: SSL/TLS (port 2484)~n", []),
    io:format("----------------------------------------~n"),
    Result2 = test_connection(DatabaseName, 2484, []),
    print_result(Result2),

    %% Summary
    io:format("~n=== SUMMARY ===~n", []),
    io:format("Native Encryption: ~s~n", [format_result(Result1)]),
    io:format("SSL/TLS: ~s~n", [format_result(Result2)]).

test_connection(Database, Port, Opts) ->
    %% Use credentials from environment or hardcoded for testing
    Username = "your_user",  %% UPDATE THIS
    Password = "your_password",  %% UPDATE THIS
    Host = "your.oracle.host",  %% UPDATE THIS
    Timeout = 30000,

    io:format("Connecting to: ~s:~p~n", [Host, Port]),
    io:format("Database: ~s~n", [Database]),
    io:format("Options: ~p~n", [Opts]),

    case jamdb_oracle:connect([
        host: Host,
        port: Port,
        user: Username,
        password: Password,
        database: Database,
        timeout: Timeout,
        debug: true
        | Opts]) of
        {ok, Conn} ->
            io:format("~n✓ Connection ESTABLISHED~n", []),
            io:format("Testing simple query...~n"),
            case jamdb_oracle:sql_query(Conn, "select 1 from dual", [], 15000) of
                {ok, Result} ->
                    io:format("✓ Query successful: ~p~n", [Result]),
                    jamdb_oracle:disconnect(Conn),
                    success;
                {error, Reason} ->
                    io:format("✗ Query failed: ~p~n", [Reason]),
                    jamdb_oracle:disconnect(Conn),
                    {query_failed, Reason};
                {disconnect, Error} ->
                    io:format("✗ Server disconnected: ~p~n", [Error]),
                    {disconnect, Error}
            end;

        {error, Type, Reason, _State} ->
            io:format("✗ Connection failed: ~p - ~p~n", [Type, Reason]),
            {connection_failed, Type, Reason}
    end.

print_result(success) ->
    io:format("Result: SUCCESS~n", []);
print_result({query_failed, Reason}) ->
    io:format("Result: QUERY_FAILED (~p)~n", [Reason]);
print_result({disconnect, Error}) ->
    io:format("Result: DISCONNECT (~p)~n", [Error]);
print_result({connection_failed, Type, Reason}) ->
    io:format("Result: CONNECTION_FAILED (~p:~p)~n", [Type, Reason]);
print_result(Other) ->
    io:format("Result: ~p~n", [Other]).
