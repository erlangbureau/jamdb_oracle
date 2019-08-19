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

      `{"select 1+:1, sysdate, rowid from dual where 1=:1"`, `[1]}`
   * Calling stored procedure:

      `{"begin proc(:1, :2, :3); end;"`, `[1.0, 2.0, 3.0]}`
   * Calling stored function:

      `{"begin :1 := func(:2); end;"`, `[{:out, :varchar}, "one hundred"]}`
   * Using cursor variable:

      `{"begin open :1 for select * from tabl where dat>:2; end;"`, `[:cursor, {2016, 8, 1}]}`
   * Using returning clause:

      `{"insert into tabl values (tablid.nextval, sysdate) return id into :1"`, `[{:out, :number}]}`

      `YourApp.Repo.insert_all(Post,[[id: 100]], [returning: [:created_at], out: [:date]])`
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
    * `:charset` - Name that is used in multibyte encoding

  ### Pool options
	
    * `:pool` - The connection pool module, defaults to `DBConnection.ConnectionPool`
    * `:pool_size` - The size of the pool, defaults to `1`
    * `:idle_interval` - The ping interval to validate an idle connection, defaults to `1000`	

  ### Connection parameters

    * `:autocommit` - Mode that issued an automatic COMMIT operation
    * `:fetch` - Number of rows to fetch from the server
    * `:sdu` - Size of session data unit
    * `:read_timeout` - Read timeout while reading from the socket, defaults to `500`
    * `:role` - Mode that is used in an internal logon
    * `:prelim` - Mode that is permitted when the database is down

  ### Output parameters
  
  Using syntax for keyword lists: `[{:out, :cursor}]`, `[out: :cursor]`

  Oracle types                     | Literal syntax in params
  :------------------------------- | :-----------------------
  `NUMBER`,`FLOAT`,`BINARY_FLOAT`  | `:number`, `:integer`, `:float`, `:decimal`
  `CHAR`, `VARCHAR2`               | `:varchar`, `:char`, `:string`
  `NCHAR`, `NVARCHAR2`             | `:nvarchar`, `:nchar`, `:binary`
  `DATE`                           | `:date`
  `TIMESTAMP`                      | `:timestamp`
  `TIMESTAMP WITH TIME ZONE`       | `:timestamptz`
  `SYS_REFCURSOR`                  | `:cursor`
  
  ### Primitive types

  The primitive types are:

  Ecto types              | Oracle types                     | Literal syntax in params
  :---------------------- | :------------------------------- | :-----------------------
  `:id`, `:integer`       | `NUMBER (*,0)`                   | 1, 2, 3
  `:float`                 | `NUMBER`,`FLOAT`,`BINARY_FLOAT`  | 1.0, 2.0, 3.0
  `:decimal`              | `NUMBER`,`FLOAT`,`BINARY_FLOAT`  | [`Decimal`](https://hexdocs.pm/decimal)
  `:string`, `:binary`    | `CHAR`, `VARCHAR2`, `CLOB`       | "one hundred"
  `:string`, `:binary`    | `NCHAR`, `NVARCHAR2`, `NCLOB`    | "百元", "万円"
  `{:array, :integer}`    | `RAW`, `BLOB`                    | 'E799BE'
  `:naive_datetime`       | `DATE`, `TIMESTAMP`              | [`NaiveDateTime`](https://hexdocs.pm/elixir)
  `:utc_datetime`         | `TIMESTAMP WITH TIME ZONE`       | [`DateTime`](https://hexdocs.pm/elixir)

  #### Examples

      iex> Ecto.Adapters.SQL.query(YourApp.Repo, "select 1+:1, sysdate, rowid from dual where 1=:1 ", [1])
      {:ok, %{num_rows: 1, rows: [[2, ~N[2016-08-01 13:14:15], "AAAACOAABAAAAWJAAA"]]}}

  """

  use Ecto.Adapters.SQL, driver: Jamdb.Oracle, migration_lock: nil

  @behaviour Ecto.Adapter.Storage
  @behaviour Ecto.Adapter.Structure

  @impl true
  def storage_up(_opts), do: err()

  @impl true
  def storage_down(_opts), do: err()

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
      {:error, err} -> err
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

  @impl true
  def to_constraints(_err), do: []

  @impl true
  def execute_ddl(err), do: error!(err)

  @impl true
  def ddl_logs(err), do: error!(err)

  defp error!(msg) do
    raise DBConnection.ConnectionError, "#{inspect msg}"
  end  

end
