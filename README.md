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
    {app_name, jamdbtest}
].

%% Connect
2> {ok, Pid} = jamdb_oracle:start_link(Opts).
{ok,<0.37.0>}

%% Simple select
3> {ok, Result} = jamdb_oracle:sql_query(Pid, "select 1 as one, 2 as two, 3 as three from dual").
{ok,[{result_set,[<<"ONE">>,<<"TWO">>,<<"THREE">>],
                 [],
                 [[{number,1},{number,2},{number,3}]]}]}

%% Select with parameters
4> {ok, Result2} = jamdb_oracle:sql_query(Pid, {"select 1 as one,SYSDATE, ROWID from dual where 1=:1 ",[1]}).
{ok,[{result_set,[<<"ONE">>,<<"SYSDATE">>,<<"ROWID">>],
                 [],
                 [[{number,1},{{2016,3,3},{14,9,57}},{rowid,142,1,1417,0}]]}]}

```

Author
======
Michael Vstavsky

Contributors
============
Sergiy Kostyushkin
