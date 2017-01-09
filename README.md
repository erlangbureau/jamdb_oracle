JamDB Oracle
============

Erlang driver for Oracle Database

Goals
=====

* No parameterized module.
* No process dictionary.
* No ports.
* No NIF's.
* All code written exclusively in Erlang.

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
First, save `test/test.config.example` as `test/test.config` and supply
connection details for your test database. Once the connection configuration
is saved, run the test suite with `rebar3 ct`.


Author
======
Mykhailo Vstavskyi

Contributors
============
Sergiy Kostyushkin
