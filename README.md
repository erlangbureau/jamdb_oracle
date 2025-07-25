# Jamdb.Oracle

Erlang driver and Ecto adapter for Oracle Database

## Features

 * Using prepared statement functionality, the SQL statement you want
   to run is precompiled and stored in a database object, and you can run it
   as many times as required without compiling it every time it is run. If the data in the
   statement changes, you can use bind variables as placeholders for the data and then 
   provide literal values at run time.

 * Using bind variables:

    `{"insert into tabl values (:1)", [<<16#E7,16#99,16#BE>>]}`
* Using named parameters:

    `{"insert into tabl values (:id, :dat)", [#{dat => {2023, 1, 1}, id => 1}]}`
 * Calling stored procedure:

    `{"begin proc(:1, :2, :3); end;"`, `[1.0, 2.0, 3.0]}`
 * Calling stored function:

    `{"begin :1 := func(:2); end;"`, `[{:out, :varchar}, "one hundred"]}`
 * Using cursor variable:

    `{"begin open :1 for select * from tabl where dat>:2; end;"`, `[:cursor, {2016, 8, 1}]}`
 * Using returning clause:

    `{"insert into tabl values (tablid.nextval, sysdate) return id into :1"`, `[{:out, :number}]}`
 * Update batching:

    `{:batch, "insert into tabl values (:1, :2, :3)"`, `[[1, 2, 3],[4, 5, 6],[7, 8, 9]]}`
 * Row prefetching:

    `{:fetch, "select * from tabl where id>:1"`, `[1]}`

    `{:fetch, cursor, row_format, last_row}`

## Options

Adapter options split in different categories described
below. All options can be given via the repository
configuration:

    config :your_app, YourApp.Repo,
      ...

### Connection options

  * `:hostname` - Server hostname (Name or IP address of the database server)
  * `:port` - Server port (Number of the port where the server listens for requests)
  * `:database` - Database (Database service name or SID with colon as prefix)
  * `:username` - Username (Name for the connecting user)
  * `:password` - User password (Password for the connecting user)
  * `:parameters` - Keyword list of connection parameters
  * `:socket_options` - Options to be given to the underlying socket
  * `:timeout` - The default timeout to use on queries, defaults to `15000`

### Pool options

  * `:pool` - The connection pool module, defaults to `DBConnection.ConnectionPool`
  * `:pool_size` - The size of the pool, defaults to `1`
  * `:idle_interval` - The ping interval to validate an idle connection, defaults to `5000`	

### Connection parameters

  * `:autocommit` - Mode that issued an automatic COMMIT operation
  * `:fetch` - Number of rows to fetch from the server
  * `:sdu` - Size of session data unit
  * `:read_timeout` - Read timeout while reading from the socket, defaults to `500`
  * `:role` - Mode that is used in an internal logon
  * `:prelim` - Mode that is permitted when the database is down
  * `:newpassword` - User new password (Change password for the connecting user)
  * `:proxy_user` - User name for proxy authentication
  * `:description` - Connect descriptor
  * `:charset` - Client character set, defaults to UTF-8

### Output parameters

* Calling stored procedure or function: `[{:out, :number}, {:out, :varchar}]`
* Using returning clause: `[{:out, :number}, {:out, :date}]`

Oracle types                     | Literal syntax in params
:------------------------------- | :-----------------------
`NUMBER`,`FLOAT`,`BINARY_FLOAT`  | `:number`, `:integer`, `:float`, `:decimal`
`CHAR`, `VARCHAR2`, `CLOB`       | `:varchar`, `:char`, `:clob`, `:string`
`NCHAR`, `NVARCHAR2`, `NCLOB`    | `:nvarchar`, `:nchar`, `:nclob`
`RAW`, `BLOB`                    | `:raw`, `:blob`, `:binary`, `:hexstring`
`DATE`                           | `:date`
`TIMESTAMP`                      | `:timestamp`
`TIMESTAMP WITH TIME ZONE`       | `:timestamptz`
`SYS_REFCURSOR`                  | `:cursor`

### Input parameters

Using query options: `[in: [:number, :binary]]`

### Primitive types

The primitive types are:

Ecto types              | Oracle types                     | Literal syntax in params
:---------------------- | :------------------------------- | :-----------------------
`:id`, `:integer`       | `NUMBER (*,0)`, `INTEGER`        | 1, 2, 3
`:float`                | `NUMBER`,`FLOAT`,`BINARY_FLOAT`  | 1.0, 2.0, 3.0
`:decimal`              | `NUMBER`,`FLOAT`,`BINARY_FLOAT`  | [`Decimal`](https://hexdocs.pm/decimal)
`:string`               | `CHAR`, `VARCHAR2`, `CLOB`       | "one hundred"
`:string`               | `NCHAR`, `NVARCHAR2`, `NCLOB`    | "百元", "万円"
`:binary`               | `RAW`, `BLOB`                    | "E799BE" (base 16 encoded)
`:binary`               | `RAW`, `BLOB`                    | <<0xE7,0x99,0xBE>> (option [in: [:binary])
`:binary_id`            | `RAW`, `BLOB`                    | <<231,153,190, ...>> (option [in: [:binary_id])
`:boolean`              | `CHAR`, `VARCHAR2`, `NUMBER`     | true, false
`:map`                  | `CLOB`, `NCLOB`                  | %{"one" => 1, "hundred" => "百"}
`:naive_datetime`       | `DATE`, `TIMESTAMP`              | [`NaiveDateTime`](https://hexdocs.pm/elixir)
`:utc_datetime`         | `TIMESTAMP WITH TIME ZONE`       | [`DateTime`](https://hexdocs.pm/elixir)

### Character sets

[`String`](https://hexdocs.pm/elixir) in Elixir is UTF-8 encoded binary.

`:us7ascii`, `:we8iso8859p1`, `:ee8iso8859p2`, `:nee8iso8859p4`, `:cl8iso8859p5`, `:ar8iso8859p6`,
`:el8iso8859p7`,`:iw8iso8859p8`, `:we8iso8859p9`, `:ne8iso8859p10`, `:th8tisascii`, `:vn8mswin1258`,
`:we8iso8859p15`,`:blt8iso8859p13`, `:ee8mswin1250`, `:cl8mswin1251`, `:el8mswin1253`, `:iw8mswin1255`,
`:tr8mswin1254`,`:we8mswin1252`, `:blt8mswin1257`, `:ar8mswin1256`

`:ja16euc`, `:ja16sjis`, `:ja16euctilde`,`:ja16sjistilde`,`:ko16mswin949`,
`:zhs16gbk`, `:zht32euc`, `:zht16big5`, `:zht16mswin950`, `:zht16hkscs`

#### Examples

    iex> Ecto.Adapters.SQL.query(YourApp.Repo, "select 1+:1,sysdate,rowid from dual where 1=:1 ", [1])
    {:ok, %{num_rows: 1, rows: [[2, ~N[2016-08-01 13:14:15], "AAAACOAABAAAAWJAAA"]]}}

    iex> row = [%Ecto.Query.Tagged{value: <<0xE7,0x99,0xBE>>, type: :binary}]
    iex> Ecto.Adapters.SQL.query(YourApp.Repo, "insert into tabl values (:1)", row)

    iex> row = [%Ecto.Query.Tagged{value: %{dat: {2023, 1, 1}, id: 1}, type: :map}]
    iex> Ecto.Adapters.SQL.query(YourApp.Repo, "insert into tabl values (:id, :dat)", row)
        
    iex> opts = [batch: true, in: [Ecto.UUID, :number]]
    iex> row = [Ecto.UUID.bingenerate, 1]
    iex> Ecto.Adapters.SQL.query(YourApp.Repo, "insert into tabl values (:1, :2)",
    ...> [row, row], opts)
        
    iex> opts = [returning: false, out: [:integer]]
    iex> row = [Date.utc_today]
    iex> Ecto.Adapters.SQL.query(YourApp.Repo, "insert into tabl (dat) values (:1) return id into :2",
    ...> row, opts)

Using quoted identifiers:

    defmodule YourApp.Users do
      use Ecto.Schema

      schema "\\"USERS\\"" do
        field :id, :integer
        field :uuid, :binary_id
        field :name, :string, source: :'"NAME"'
        field :namae, :string, source: :'"名まえ"'
      end

    end

    iex> YourApp.Repo.all(from(u in "\\"USERS\\"", select: u.'"NAME"', where: u.id == 1))

    iex> YourApp.Repo.all(from(u in YourApp.Users, select: u.namae, where: u.id == 1))

    iex> uuid = "601d74e4-a8d3-4b6e-8365-eddb4c893327"
    iex> YourApp.Repo.all(from(u in YourApp.Users, select: u.name,
    iex> where: u.uuid == type(^uuid, :binary_id)), [in: [:binary_id]])

Imagine you have this migration:

    defmodule YourApp.Repo.Migrations.Users do
      use Ecto.Migration

      def change do
        create table(:users, comment: "users table") do
          add :name, :string, comment: "name column"
          add :namae, :string, national: true
          add :custom_id, :uuid
          timestamps()
        end
      end

    end

To migrate you'd do it normally:

    $ mix ecto.migrate
