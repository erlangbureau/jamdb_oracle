JamDB Oracle
============
Erlang driver and Ecto adapter for Oracle Database

Features
=====

* Using prepared statement functionality.
* Using bind variables.
* Calling stored procedure.
* Calling stored function.
* Using cursor variable.
* Using returning clause.
* Update batching.
* Row prefetching.

Getting Started
=====

```erl

%% Set connection options
1> Opts = [
    {host, "jamdb-oracle-dev.erlangbureau.dp.ua"},
    {port, 1521},
    {user, "jamdbtest"},
    {password, "jamdbtest"},
    {sid, "JAMDBTEST"},
    %%{service_name, "JAMDBTEST"},
    %%{ssl, [{ciphers,[{rsa,aes_128_cbc,sha}]},
    %%       {signature_algs,[{sha,rsa}]},
    %%       {certfile, "/home/jamdbtest/cert.pem"},
    %%       {keyfile, "/home/jamdbtest/key.pem"},
    %%       {password, "jamdbtest"}]},
    {app_name, "jamdbtest"}
].

%% Connect
2> {ok, Pid} = jamdb_oracle:start_link(Opts).
{ok,<0.37.0>}

%% Simple select
3> {ok, Result} = jamdb_oracle:sql_query(Pid, "select 1 as one, 2 as two, 3 as three from dual").
{ok,[{result_set,[<<"ONE">>,<<"TWO">>,<<"THREE">>],
                 [],
                 [[{1},{2},{3}]]}]}

%% Select with parameters
4> {ok, Result2} = jamdb_oracle:sql_query(Pid, {"select 1 as one, sysdate, rowid from dual where 1=:1 ",[1]}).
{ok,[{result_set,[<<"ONE">>,<<"SYSDATE">>,<<"ROWID">>],
                 [],
                 [[{1},{{2016,8,1},{13,14,15}},"AAAACOAABAAAAWJAAA"]]}]}

```

Running Tests
======
First, supply connection details for your test database in test/jamdb_oracle_test.hrl or config/test.exs. Once the connection configuration is saved, run the test suite with `rebar3 ct` or `mix test`.

SSL
======
When authenticating and downgrading an TLS connection to a transport connection we're NOT sending close alert to peer before releasing the transport socket. See patched [ssl](https://github.com/vstavskyi/ssl) module.

Author
======
Mykhailo Vstavskyi

Contributors
============
Sergiy Kostyushkin
