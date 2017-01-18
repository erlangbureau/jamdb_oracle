-module(jamdb_oracle_test).

-include("jamdb_oracle_test.hrl").

-compile(export_all).

-define(query(ConnRef,Query), jamdb_oracle:sql_query(ConnRef,Query)).

%% Test callbacks

all() ->
    {ok, ConnRef} = jamdb_oracle:start(?ConnOpts),
    
    {ok, [{affected_rows,0}]} = 
    ?query(ConnRef, "create table t_number ( C_NUMBER NUMBER )"),

    {ok,[]} =
    ?query(ConnRef, {"FETCH", [1]}),           %FETCH SIZE

    {ok,[]} =
    ?query(ConnRef, "COMOFF;"),                %AUTOCOMMIT OFF

    {ok, [{affected_rows,1}]} = 
    ?query(ConnRef, {"insert into t_number values ( :1)", [1]}),
    {ok,[]} =
    ?query(ConnRef, "ROLLBACK;"),
    {ok,[{result_set,[<<"S">>],[],[[null]]}]} =
    ?query(ConnRef, "select sum(C_NUMBER) S from t_number"),

    {ok, [{affected_rows,1}]} = 
    ?query(ConnRef, {"insert into t_number values ( :1)", [1]}),
    {ok, [{affected_rows,1}]} = 
    ?query(ConnRef, {"insert into t_number values ( :1)", [1]}),
    {ok,[]} =
    ?query(ConnRef, "COMMIT;"),
    {ok,[{result_set,[<<"S">>],[],[[{2}]]}]} =
    ?query(ConnRef, "select sum(C_NUMBER) S from t_number"),

    {ok,[]} =
    ?query(ConnRef, "COMON;"),                 %AUTOCOMMIT ON

    {ok, [{affected_rows,1}]} = 
    ?query(ConnRef, {"insert into t_number values ( :1)", [1]}),
    {ok,[{result_set,[<<"S">>],[],[[{3}]]}]} =
    ?query(ConnRef, "select sum(C_NUMBER) S from t_number"),

    {ok,[]} =
    ?query(ConnRef, "COMOFF"),                 %AUTOCOMMIT OFF

    {ok, [{affected_rows,1}]} = 
    ?query(ConnRef, {"insert into t_number values ( :1)", [1]}),
    {ok, [{affected_rows,0}]} =
    ?query(ConnRef, "SAVEPOINT SVPT"),
    {ok, [{affected_rows,1}]} = 
    ?query(ConnRef, {"insert into t_number values ( :1)", [1]}),
    {ok, [{affected_rows,1}]} = 
    ?query(ConnRef, {"insert into t_number values ( :1)", [1]}),
    {ok, [{affected_rows,0}]} =
    ?query(ConnRef, "ROLLBACK TO SVPT"),
    {ok, [{affected_rows,1}]} = 
    ?query(ConnRef, {"insert into t_number values ( :1)", [1]}),
    {ok,[]} =
    ?query(ConnRef, "COMMIT"),
    {ok,[{result_set,[<<"S">>],[],[[{5}]]}]} =
    ?query(ConnRef, "select sum(C_NUMBER) S from t_number"),
            
    {ok, [{affected_rows,0}]} = 
    ?query(ConnRef, "drop table t_number"),
    
    ok = jamdb_oracle:stop(ConnRef).
