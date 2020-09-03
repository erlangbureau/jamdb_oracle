defmodule Ecto.Adapters.Jamdb.Oracle do
  @moduledoc """
  Adapter module for Oracle. `Ecto.Adapters.SQL` callbacks implementation.

  It uses `jamdb_oracle` for communicating to the database.

  ## Features

   * Using prepared statement functionality, the SQL statement you want
     to run is precompiled and stored in a database object, and you can run it
     as many times as required without compiling it every time it is run. If the data in the
     statement changes, you can use bind variables as placeholders for the data and then 
     provide literal values at run time.

   * Using bind variables:

      `{"insert into tabl values (:1)", [<<16#E7,16#99,16#BE>>]}`
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
    * `:idle_interval` - The ping interval to validate an idle connection, defaults to `1000`	

  ### Connection parameters

    * `:charset` - Client character set, defaults to UTF8
    * `:autocommit` - Mode that issued an automatic COMMIT operation
    * `:fetch` - Number of rows to fetch from the server
    * `:sdu` - Size of session data unit
    * `:read_timeout` - Read timeout while reading from the socket, defaults to `500`
    * `:role` - Mode that is used in an internal logon
    * `:prelim` - Mode that is permitted when the database is down

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
  `:binary`               | `RAW`, `BLOB`                    | <<0xE7,0x99,0xBE>>, 'E799BE'
  `:binary`               | `RAW`, `BLOB`                    | [`Ecto.Query.Tagged`](https://hexdocs.pm/ecto)
  `:binary_id`,`Ecto.UUID`| `RAW`, `BLOB`                    | [`Ecto.UUID`](https://hexdocs.pm/ecto)
  `:boolean`              | `CHAR`, `VARCHAR2`, `NUMBER`     | true, false
  `:map`                  | `CLOB`, `NCLOB`                  | %{"one" => 1, "hundred" => "百"}
  `:naive_datetime`       | `DATE`, `TIMESTAMP`              | [`NaiveDateTime`](https://hexdocs.pm/elixir)
  `:utc_datetime`         | `TIMESTAMP WITH TIME ZONE`       | [`DateTime`](https://hexdocs.pm/elixir)

  ### Character sets

  `:us7ascii`, `:we8iso8859p1`, `:ee8iso8859p2`, `:nee8iso8859p4`, `:cl8iso8859p5`, `:ar8iso8859p6`,
  `:el8iso8859p7`,`:iw8iso8859p8`, `:we8iso8859p9`, `:ne8iso8859p10`, `:th8tisascii`, `:vn8mswin1258`,
  `:we8iso8859p15`,`:blt8iso8859p13`, `:ee8mswin1250`, `:cl8mswin1251`, `:el8mswin1253`, `:iw8mswin1255`,
  `:tr8mswin1254`,`:we8mswin1252`, `:blt8mswin1257`, `:ar8mswin1256`

  `:ja16euc`, `:ja16sjis`, `:ja16euctilde`,`:ja16sjistilde`,`:ko16mswin949`,
  `:zhs16gbk`, `:zht32euc`, `:zht16big5`, `:zht16mswin950`, `:zht16hkscs`

  #### Examples

      iex> Ecto.Adapters.SQL.query(YourApp.Repo, "select 1+:1,sysdate,rowid from dual where 1=:1 ", [1])
      {:ok, %{num_rows: 1, rows: [[2, ~N[2016-08-01 13:14:15], "AAAACOAABAAAAWJAAA"]]}}

      iex> bin = %Ecto.Query.Tagged{value: <<0xE7,0x99,0xBE>>, type: :binary}
      iex> Ecto.Adapters.SQL.query(YourApp.Repo, "insert into tabl values (:1)", [bin])
      
      iex> bin = <<0xE7,0x99,0xBE>>
      iex> Ecto.Adapters.SQL.query(YourApp.Repo, "insert into tabl values (:1)", [bin]], [in: [:binary]])

      iex> YourApp.Repo.insert_all(YourSchema,[[id: 100]], [returning: [:created_at], out: [:date]])

  Imagine you have this migration:

      defmodule YourApp.Migration do
        use Ecto.Migration

        def up do
          create table(:users, comment: "users table") do
            add :name, :string, comment: "name column"
            add :namae, :string, national: true
            add :custom_id, :uuid
            timestamps()
          end
        end

      end

  You can execute it manually with:

      Ecto.Migrator.up(YourApp.Repo, 20160801131415, YourApp.Migration)

  """

  use Ecto.Adapters.SQL, driver: Jamdb.Oracle, migration_lock: nil

  @behaviour Ecto.Adapter.Storage
  @behaviour Ecto.Adapter.Structure

  @impl true
  def loaders({:array, _}, type), do: [&array_decode/1, type]
  def loaders({:embed, _}, type), do: [&json_decode/1, &Ecto.Type.embedded_load(type, &1, :json)]
  def loaders({:map, _}, type),   do: [&json_decode/1, &Ecto.Type.embedded_load(type, &1, :json)]
  def loaders(:map, type),        do: [&json_decode/1, type]
  def loaders(:float, type),      do: [&float_decode/1, type]
  def loaders(:boolean, type),    do: [&bool_decode/1, type]
  def loaders(:binary_id, type),  do: [Ecto.UUID, type]
  def loaders(_, type),           do: [type]

  defp bool_decode("0"), do: {:ok, false}
  defp bool_decode("1"), do: {:ok, true}
  defp bool_decode(0), do: {:ok, false}
  defp bool_decode(1), do: {:ok, true}
  defp bool_decode(x), do: {:ok, x}

  defp float_decode(%Decimal{} = decimal), do: {:ok, Decimal.to_float(decimal)}
  defp float_decode(x), do: {:ok, x}

  defp json_decode(x) when is_binary(x), do: {:ok, Jamdb.Oracle.json_library().decode!(x)}
  defp json_decode(x), do: {:ok, x}

  defp array_decode(x) when is_binary(x), do: {:ok, :binary.bin_to_list(x)}
  defp array_decode(x), do: {:ok, x}

  @impl true
  def storage_up(_opts), do: err()

  @impl true
  def storage_down(_opts), do: err()

  @impl true
  def storage_status(_opts), do: err()

  @impl true
  def structure_dump(_default, _config), do: err()

  @impl true
  def structure_load(_default, _config), do: err()

  @impl true
  def supports_ddl_transaction? do
    false
  end

  defp err, do: {:error, false}

end

defmodule Ecto.Adapters.Jamdb.Oracle.Connection do
  @moduledoc false

  @behaviour Ecto.Adapters.SQL.Connection

  @impl true
  def child_spec(opts) do
    DBConnection.child_spec(Jamdb.Oracle, opts)
  end

  @impl true
  def execute(conn, query, params, opts) do
    DBConnection.execute(conn, query!(query, ""), params, opts)
  end

  @impl true
  def prepare_execute(conn, name, query, params, opts) do
    DBConnection.prepare_execute(conn, query!(query, name), params, opts)
  end

  @impl true
  def stream(conn, query, params, opts) do
    DBConnection.stream(conn, query!(query, ""), params, opts)
  end

  @impl true
  def query(conn, query, params, opts) do
    case DBConnection.prepare_execute(conn, query!(query, ""), params, opts) do
      {:ok, _, result}  -> {:ok, result}
      {:error, err} -> {:error, err}
    end
  end

  @impl false
  def explain_query(conn, query, params, opts) do
    case query(conn, IO.iodata_to_binary(["EXPLAIN PLAN FOR ", query]), params, opts) do
      {:ok, _result} -> query(conn, "SELECT * FROM table(DBMS_XPLAN.DISPLAY())", params, opts)
      {:error, err} -> {:error, err}
    end
  end

  defp query!(sql, name) when is_binary(sql) or is_list(sql) do
    %Jamdb.Oracle.Query{statement: IO.iodata_to_binary(sql), name: name}
  end
  defp query!(%{} = query, _name) do
    query
  end

  defdelegate all(query), to: Jamdb.Oracle.Query
  defdelegate update_all(query), to: Jamdb.Oracle.Query
  defdelegate delete_all(query), to: Jamdb.Oracle.Query
  defdelegate insert(prefix, table, header, rows, on_conflict, returning), to: Jamdb.Oracle.Query
  defdelegate update(prefix, table, fields, filters, returning), to: Jamdb.Oracle.Query
  defdelegate delete(prefix, table, filters, returning), to: Jamdb.Oracle.Query
  defdelegate table_exists_query(table), to: Jamdb.Oracle.Query
  defdelegate execute_ddl(command), to: Jamdb.Oracle.Query
  defdelegate ddl_logs(result), to: Jamdb.Oracle.Query
  defdelegate to_constraints(err), to: Jamdb.Oracle.Query
  defdelegate to_constraints(err, opts), to: Jamdb.Oracle.Query

end
