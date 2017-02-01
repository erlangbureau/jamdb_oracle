-module(jamdb_oracle_dba).

-include("jamdb_oracle_test.hrl").

-compile(export_all).

%% To use this module, you must set the DEF_TIMEOUT to infinity.

startdb() ->                     % as sysdba prelim auth
    {ok, ConnRef} = jamdb_oracle:start([{role, 1},{prelim, 1}]++?ConnOpts),

    {ok,[_]} =                   %mode 0 norestrict, 1 restrict, 16 force
    jamdb_oracle:sql_query(ConnRef, {"START", [0]}),
    
    ok = jamdb_oracle:stop(ConnRef).

mountdb() ->                     % as sysdba
    {ok, ConnRef} = jamdb_oracle:start([{role, 1}]++?ConnOpts),

    {ok,[_]} =
    jamdb_oracle:sql_query(ConnRef, "ALTER DATABASE MOUNT"),

    {ok,[_]} =
    jamdb_oracle:sql_query(ConnRef, "ALTER DATABASE OPEN"),

    ok = jamdb_oracle:stop(ConnRef).
    
stopdb() ->                     % as sysdba
    {ok, ConnRef} = jamdb_oracle:start([{role, 1}]++?ConnOpts),

    {ok,[_]} =                  %mode 2 immediate, 4 normal, 8 final, 64 abort, 128 tran
    jamdb_oracle:sql_query(ConnRef, {"STOP", [2]}),

    {ok,[_]} =
    jamdb_oracle:sql_query(ConnRef, "ALTER DATABASE CLOSE NORMAL"),

    {ok,[_]} =
    jamdb_oracle:sql_query(ConnRef, "ALTER DATABASE DISMOUNT"),

    {ok,[_]} =
    jamdb_oracle:sql_query(ConnRef, {"STOP", [8]}),
    
    ok.

