-module(jamdb_oracle_SUITE).

-include_lib("common_test/include/ct.hrl").

-include("jamdb_oracle_test.hrl").

-compile(export_all).

%% Common Test callbacks

all() ->
	[
        {group, basic_operations},
        {group, number_datatypes},
        {group, date_datatypes},
        {group, char_datatypes},
        {group, raw_datatypes},
        {group, lob_datatypes},
        {group, rowid_datatypes},
        {group, procedure_operations}
   ].
   
groups() ->
    [
        {basic_operations, [sequence], [
            select,
            select_with_bind,
            select_with_named_bind
        ]},
        {number_datatypes, [sequence], [
            t_number,
            t_float
        ]},
        {date_datatypes, [sequence], [
            t_date,
            t_timestamp,
            t_timestamp_tz
        ]},
        {char_datatypes, [sequence], [
            t_char,
            t_varchar,
            t_nchar,
            t_nvarchar
        ]},
        {raw_datatypes, [sequence], [
            t_raw,
            t_long_raw,
            t_long
        ]},
        {lob_datatypes, [sequence], [
            t_clob,
            t_blob,
            t_nclob            
        ]},
        {rowid_datatypes, [sequence], [
            t_rowid
        ]},
        {procedure_operations, [sequence], [
            with_input_params,
            with_output_params,
            with_input_and_output_params,
            with_multi_output_params
        ]}
    ].

init_per_suite(Config) ->
    {ok, ConnRef} = jamdb_oracle:start(?ConnOpts),
    [{conn_ref, ConnRef}|Config].

end_per_suite(Config) ->
    ConnRef = ?config(conn_ref, Config),
    ok = jamdb_oracle:stop(ConnRef),
    Config.

init_per_group(Name, Config) ->
    InitType = case Name of
        basic_operations            -> basic;
        number_datatypes            -> datatypes;
        date_datatypes              -> datatypes;
        char_datatypes              -> datatypes;
        raw_datatypes               -> datatypes;
        lob_datatypes               -> datatypes;
        rowid_datatypes             -> datatypes;
        procedure_operations        -> procedure
    end,
    [{init_type, InitType}|Config].

end_per_group(_Name, Config) ->
    lists:keydelete(init_type, 1, Config).

init_per_testcase(Case, Config) ->
    ConnRef = ?config(conn_ref, Config),
    case ?config(init_type, Config) of
        datatypes ->
            Query = lists:concat(["create table ", Case, "( ", table_desc(Case), " )"]),
            {ok, [{affected_rows,0}]} = jamdb_oracle:sql_query(ConnRef, Query);
        procedure ->
            Query = lists:concat(["create or replace procedure ", Case, " ", procedure_desc(Case)]),
            {ok, [{affected_rows,0}]} = jamdb_oracle:sql_query(ConnRef, Query);
        _ ->
            nothing
    end,
    Config.

end_per_testcase(Case, Config) ->
    ConnRef = ?config(conn_ref, Config),
    case ?config(init_type, Config) of
        datatypes ->
            Query = lists:concat(["drop table ", Case]),
            {ok, [{affected_rows,0}]} = jamdb_oracle:sql_query(ConnRef, Query);
        procedure ->
            Query = lists:concat(["drop procedure ", Case]),
            {ok, [{affected_rows,0}]} = jamdb_oracle:sql_query(ConnRef, Query);
        _ ->
            nothing
    end,
    ok.

%% test cases
select(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Query = "select 1 one, 2 two, 3 three from dual",
    Result = [{result_set, [<<"ONE">>, <<"TWO">>, <<"THREE">>], [], [ [{1.0},{2.0},{3.0}] ]}],
    {ok, Result} = jamdb_oracle:sql_query(ConnRef, Query).

select_with_bind(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Query = {"select '1' one, '2' two, '3' three from dual where 1=:1", [1]},
    Result = [{result_set, [<<"ONE">>, <<"TWO">>, <<"THREE">>], [], [ ["1","2","3"] ]}],
    {ok, Result} = jamdb_oracle:sql_query(ConnRef, Query).

select_with_named_bind(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Query = {"select to_date(:str,:fmt) to_date from dual where 1=:one", 
                #{fmt => "'YYYY-MM-DD HH24:MI:SS'", one => 1, str => "'2016-08-01 01:02:03'" }},
    Result = [{result_set, [<<"TO_DATE">>], [], [ [{{2016,8,1},{1,2,3}}] ]}],
    {ok, Result} = jamdb_oracle:sql_query(ConnRef, Query).
    
t_number(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_number,
    Key = <<"C_NUMBER">>,
    TestCases = [
        {null, null},
        {0.0, 0.0},
        {0.18446744073709, 0.18446744073709},
        {65535.0, 65535.0},
        {4294967295.0, 4294967295.0},
        {1844674407.3709551615, 1844674407.3709551615},
        {18446744073709.55, 18446744073709.55},
        {18446744073709551615.0, 18446744073709551615.0},
        {-0.9223372036854, -0.9223372036854},
        {-32768.0, -32768.0},
        {-2147483648.0, -2147483648.0},
        {-9223372036.854775808, -9223372036.854775808},
        {-9223372036854.77, -9223372036854.77},
        {-9223372036854775808.0, -9223372036854775808.0}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).

t_float(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_float,
    Key = <<"C_FLOAT">>,
    TestCases = [
        {null, null},
        {0.0, 0.0},
        {0.184467440737095, 0.184467440737095},
        {-0.9223372036854775808, -0.9223372036854775808}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).

t_date(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_date,
    Key = <<"C_DATE">>,
    TestCases = [
        {null, null},
        {{date, "to_date('2016-08-01 01:02:03','YYYY-MM-DD HH24:MI:SS')"}, {{2016,8,1},{1,2,3}}}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).

t_timestamp(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_timestamp,
    Key = <<"C_TIMESTAMP">>,
    TestCases = [
        {null, null},
        {{date, "to_timestamp('2016-08-01 01:02:03.456','YYYY-MM-DD HH24:MI:SS.FF')"}, {{2016,8,1},{1,2,3.456}}}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).

t_timestamp_tz(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_timestamp_tz,
    Key = <<"C_TIMESTAMP">>,
    TestCases = [
        {null, null},
        {{date, "to_timestamp_tz('2016-08-01 02:02:03.456 +01:00 ','YYYY-MM-DD HH24:MI:SS.FF TZH:TZM')"}, {{2016,8,1},{1,2,3.456},"+01:00"}}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).

t_char(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_char,
    Key = <<"C_CHAR">>,
    TestCases = [
        {null, null},
        {<<"">>, null},
        {<<"a">>, "a         "},
        {<<"abcd">>, "abcd      "}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).

t_varchar(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_varchar,
    Key = <<"C_VARCHAR">>,
    TestCases = [
        {null, null},
        {<<"">>, null},
        {<<"a">>, "a"},
        {<<"abcd">>, "abcd"}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).

t_nchar(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_nchar,
    Key = <<"C_NCHAR">>,
    TestCases = [
        {null, null},
        {<<"">>, null},
        {{utf16, "u'\\56db'"}, [229,155,155,32,32,32,32,32,32,32,32,32]},
        {{utf16, "u'\\56db\\4e94\\516d\\4e03'"}, [229,155,155,228,186,148,229,133,173,228,184,131,32,32,32,32,32,32]}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).

t_nvarchar(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_nvarchar,
    Key = <<"C_NVARCHAR">>,
    TestCases = [
        {null, null},
        {<<"">>, null},
        {{utf16, "u'\\56db'"}, [229,155,155]},
        {{utf16, "u'\\56db\\4e94\\516d\\4e03'"}, [229,155,155,228,186,148,229,133,173,228,184,131]}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).
    
t_raw(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_raw,
    Key = <<"C_RAW">>,
    TestCases = [
        {null, null},
        {{raw, "hextoraw('61626364')"}, "abcd"}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).

t_long_raw(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_long_raw,
    Key = <<"C_RAW">>,
    TestCases = [
        {null, null},
        {{raw, "hextoraw('61626364')"}, "abcd"}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).
    
t_long(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_long,
    Key = <<"C_LONG">>,
    TestCases = [
        {null, null},
        {<<"">>, null},
        {<<"a">>, "a"},
        {<<"abcd">>, "abcd"}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).
    
t_clob(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_clob,
    Key = <<"C_CLOB">>,
    LongValue = << << <<"abcd">> || _ <- lists:seq(1,1000)>>/binary>>,
    LongList = binary_to_list(LongValue),
    TestCases = [
        {null, null},
        {<<"">>, null},
        {<<"a">>, "a"},
        {<<"abcd">>, "abcd"},
	{LongValue, LongList}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).
    
t_blob(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_blob,
    Key = <<"C_BLOB">>,
    TestCases = [
        {null, null},
        {{raw, "hextoraw('61626364')"}, "abcd"}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).

t_nclob(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_nclob,
    Key = <<"C_NCLOB">>,
    TestCases = [
        {null, null},
        {<<"">>, null},
        {{utf16, "u'\\56db'"}, [229,155,155]},
        {{utf16, "u'\\56db\\4e94\\516d\\4e03'"}, [229,155,155,228,186,148,229,133,173,228,184,131]}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).

t_rowid(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Table = t_rowid,
    Key = <<"C_ROWID">>,
    TestCases = [
        {null, null},
        {"AAAWidAAGAAAAD0AAB", "AAAWidAAGAAAAD0AAB"}
    ],
    run_testcases(ConnRef, Table, Key, TestCases).
    
with_input_params(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Query = {"begin with_input_params(:1); end;", [0]},
    Result = [{proc_result,0,[[]]}],
    {ok, Result} = jamdb_oracle:sql_query(ConnRef, Query).

with_output_params(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Query = {"begin with_output_params(:1, :2, :3); end;", [{out,varchar}, {out,number}, {out,date}]},    
    Result = [{proc_result,0,[["1",{2},{{2016,8,1},{1,2,3}}]]}],
    {ok, Result} = jamdb_oracle:sql_query(ConnRef, Query).

with_input_and_output_params(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Query = {"begin with_input_and_output_params(:i1, :o2); end;",
             #{o2 => {out, cursor}, i1 => {in, "select 1 one, 2 two, 3 three from dual"}}},
    Result = [{result_set, [<<"ONE">>, <<"TWO">>, <<"THREE">>], [], [ [{1.0},{2.0},{3.0}] ]}],
    {ok, Result} = jamdb_oracle:sql_query(ConnRef, Query).

with_multi_output_params(Config) ->
    ConnRef = ?config(conn_ref, Config),
    Query = {"begin with_multi_output_params(:i1, :o1, :o2); end;",
             #{o2 => {out, cursor}, i1 => {in, "select 1 one, 2 two, 3 three from dual"}, o1 => {out, "0"}}},
    Result = [{result_set, [<<"ONE">>, <<"TWO">>, <<"THREE">>], [], [ [{1.0},{2.0},{3.0}] ]}],
    {ok, Result} = jamdb_oracle:sql_query(ConnRef, Query).

%% internal
table_desc(t_number) ->
    "C_NUMBER NUMBER";
table_desc(t_float) ->
    "C_FLOAT FLOAT";
table_desc(t_date) ->
    "C_DATE DATE";
table_desc(t_timestamp) ->
    "C_TIMESTAMP TIMESTAMP";
table_desc(t_timestamp_tz) ->
    "C_TIMESTAMP TIMESTAMP WITH TIME ZONE";
table_desc(t_char) ->
    "C_CHAR CHAR (10)";
table_desc(t_varchar) ->
    "C_VARCHAR VARCHAR2 (100)";
table_desc(t_nchar) ->
    "C_NCHAR NCHAR (10)";
table_desc(t_nvarchar) ->
    "C_NVARCHAR NVARCHAR2 (100)";
table_desc(t_raw) ->
    "C_RAW RAW (100)";
table_desc(t_long_raw) ->
    "C_RAW LONG RAW";
table_desc(t_long) ->
    "C_LONG LONG";
table_desc(t_clob) ->
    "C_CLOB CLOB";
table_desc(t_blob) ->
    "C_BLOB BLOB";
table_desc(t_nclob) ->
    "C_NCLOB NCLOB";
table_desc(t_rowid) ->
    "C_ROWID ROWID".

procedure_desc(with_input_params) ->
    "( "
        "i1 number "
    ") is "
    "begin "
        "return; "
    "end;";
procedure_desc(with_output_params) ->
    "( "
        "o1 out varchar2, "
        "o2 out number, "
        "o3 out date "
    ") is "
    "begin "
        "select '1', 2, to_date('2016-08-01 01:02:03','YYYY-MM-DD HH24:MI:SS') into o1, o2, o3 from dual; "
    "end;";
procedure_desc(with_input_and_output_params) ->
    "( "
        "i1 in varchar2, "
        "o1 out sys_refcursor "
    ") is "
    "begin "
        "open o1 for i1; "
    "end;";
procedure_desc(with_multi_output_params) ->
    "( "
        "i1 in varchar2, "
        "o1 out varchar2, "
        "o2 out sys_refcursor "
    ") is "
    "begin "
        "open o2 for i1; "
    "end;".

run_testcases(ConnRef, Table, Key, Cases) ->
    [begin
        {ok, RValue} = run_testcase(ConnRef, Table, Key, SValue)
    end || {SValue, RValue} <- Cases].

run_testcase(ConRef, Table, Key, SrcValue) ->
    {ok, [{affected_rows,1}]}                       = insert(ConRef, Table, Key, SrcValue),
    {ok, [{result_set,[Key],[],[[ResultValue]]}]}   = select(ConRef, Table),
    {ok, [{affected_rows,1}]}                       = delete(ConRef, Table),
    io:format("SourceValue:~p~n", [SrcValue]),
    io:format("ResultValue:~p~n", [decode_data(ResultValue)]),
    {ok, decode_data(ResultValue)}.

insert(ConnRef, Tab, Key, Value) ->
    Table = atom_to_binary(Tab, utf8),
    Query1 = [<<"insert into ", Table/binary, "(", Key/binary, ") "
                                "VALUES( ">>, arg, <<" )">>],
    Query2 = format_query(Query1, [Value]),
    jamdb_oracle:sql_query(ConnRef, binary_to_list(Query2)).

select(ConnRef, Table) ->
    Query = lists:concat(["select * from ", Table]),
    jamdb_oracle:sql_query(ConnRef, Query).

delete(ConnRef, Table) ->
    Query = lists:concat(["delete from ", Table]),
    jamdb_oracle:sql_query(ConnRef, Query).

%% Temporary wrapper
format_query(Query, Args) ->
    format_query(Query, Args, <<>>).

format_query([QueryPart|RestQuery], Args, Result) when is_binary(QueryPart) ->
    Result2 = <<Result/binary, QueryPart/binary>>,
    format_query(RestQuery, Args, Result2);
format_query([arg|RestQuery], [FirstArg|RestArgs], Result)  ->
    IsChar = is_binary(FirstArg) orelse is_list(FirstArg),
    Result2 = case IsChar of
        true ->
            <<Result/binary, "'", (encode_data(FirstArg))/binary, "'">>;
        false ->
            <<Result/binary, (encode_data(FirstArg))/binary>>
    end,
    format_query(RestQuery, RestArgs, Result2);
format_query([], [], Result) ->
    Result.

decode_data({Data}) ->
    Data;
decode_data(Data) ->
 Data.
    
escape(Binary) ->
    case binary:matches(Binary,[<<"to_date">>,<<"to_time">>,<<"hextoraw">>]) of
	nomatch ->
	    escape(Binary, <<>>);
	_ ->
	    Binary
    end.
    
escape(<<"'", Binary/binary>>, Result) ->
    escape(Binary, <<Result/binary, "''">>);
escape(<<X, Binary/binary>>, Result) ->
    escape(Binary, <<Result/binary, X>>);
escape(<<>>, Result) ->
    Result.

encode_data(Data) when is_binary(Data) ->
    escape(Data);
encode_data(Data) when is_list(Data) ->
    Binary = unicode:characters_to_binary(Data),
    encode_data(Binary);
encode_data(Data) when is_atom(Data) ->
    Binary = atom_to_binary(Data, unicode),
    encode_data(Binary);
encode_data(Data) when is_integer(Data) ->
    List = integer_to_list(Data),
    encode_data(List);
encode_data(Data) when is_float(Data) ->
    List = float_to_list(Data),
    encode_data(List);
encode_data({_, List}) when is_list(List) ->
    encode_data(List).
    
