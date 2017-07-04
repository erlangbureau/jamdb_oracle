defmodule Ecto.Adapters.Jamdb.Oracle do
  @moduledoc """
  Ecto adapter for Oracle.

  It uses `Jamdb.Oracle` for communicating to the database
  and a connection pool, such as `poolboy`.

  ## Features

   * Using bind variables:     `"select 1+:1, sysdate, rowid from dual where 1=:1"`, `[1]`
   * Calling stored procedure: `"begin proc(:1, :2, :3); end;"`, `[1.0, 2.0, 3.0]`
   * Calling stored function:  `"begin :1 := func(:2); end;"`, `["", "one hundred"]`
   * Using cursor variable:    `"begin :1 := func(:2); end;"`, `[:cursor, {2016, 8, 1}]`
   * Using returning clause:   `"insert into tabl (id) values (:1) return id into :2"`, `[1, {:out, 0}]`

  ## Options

  Adapter options split in different categories described
  below. All options should be given via the repository
  configuration. These options are also passed to the module
  specified in the `:pool` option, so check that module's
  documentation for more options.

  ### Compile time options

  Those options should be set in the config file and require
  recompilation in order to make an effect.

    * `:adapter` - The adapter name, in this case, `Ecto.Adapters.Jamdb.Oracle`
    * `:name`- The name of the Repo supervisor process
    * `:pool` - The connection pool module, defaults to `DBConnection.Poolboy`
    * `:pool_timeout` - The default timeout to use on pool calls, defaults to `5000`

  ### Connection options

    * `:hostname` - Server hostname (Name or IP address of the database server)
    * `:port` - Server port (Number of the port where the server listens for requests)
    * `:database` - Database (Database service name or SID with colon as prefix)
    * `:username` - Username (Name for the connecting user)
    * `:password` - User password (Password for the connecting user)

  ### Primitive types

  The primitive types are:

  Ecto types              | Oracle types                     | Literal syntax in params
  :---------------------- | :------------------------------- | :-----------------------
  `:id`, `:integer`       | `NUMBER (*,0)`                   | 1, 2, 3
  `:float`                | `NUMBER`,`FLOAT`,`BINARY_FLOAT`  | 1.0, 2.0, 3.0
  `:decimal`              | `NUMBER`,`FLOAT`,`BINARY_FLOAT`  | [`Decimal`](https://hexdocs.pm/decimal)
  `:string`               | `CHAR`, `VARCHAR2`, `CLOB`       | "one hundred"
  `:string`               | `NCHAR`, `NVARCHAR2`, `NCLOB`    | "百元", "五百円"
  `:binary`               | `RAW`, `BLOB`                    | "E799BE"
  `:naive_datetime`       | `DATE`, `TIMESTAMP`              | {2016, 8, 1}, {{2016, 8, 1}, {13, 14, 15}}

  #### Examples

      iex> Ecto.Adapters.SQL.query(Repo, "select 1+:1, sysdate, rowid from dual where 1=:1 ", [1])
      {:ok, %{num_rows: 1, rows: [[2, {{2016, 8, 1}, {13, 14, 15}}, "AAAACOAABAAAAWJAAA"]]}}

  """

  use Ecto.Adapters.SQL, Jamdb.Oracle
  
  @behaviour Ecto.Adapter.Storage
  @behaviour Ecto.Adapter.Structure

  @doc false
  def storage_up(_opts), do: err
  
  @doc false
  def storage_down(_opts), do: err
  
  @doc false
  def structure_dump(_default, _config), do: err
  
  @doc false
  def structure_load(_default, _config), do: err
  
  @doc false
  def supports_ddl_transaction? do
    false
  end
  
  defp err, do: {:error, false}

end

defmodule Ecto.Adapters.Jamdb.Oracle.Connection do
  @moduledoc false

  @behaviour Ecto.Adapters.SQL.Connection
  
  def child_spec(opts) do
    DBConnection.child_spec(Jamdb.Oracle, opts)
  end
  
  def execute(conn, statement, params, opts) do
    query = %Jamdb.Oracle.Query{statement: statement}
    case DBConnection.prepare_execute(conn, query, params, opts) do
      {:ok, _, result} -> {:ok, result}
      {:error, err} -> error!(err)
    end
  end

  def prepare_execute(conn, _name, statement, params, opts) do
    query = %Jamdb.Oracle.Query{statement: statement}
    case DBConnection.prepare_execute(conn, query, params, opts) do
      {:ok, _, _} = ok -> ok
      {:error, err} -> error!(err)
    end
  end
    
  def stream(conn, statement, params, opts) do
    query = %Jamdb.Oracle.Query{statement: statement}
    DBConnection.stream(conn, query, params, opts)
  end
  
  defdelegate all(query), to: Jamdb.Oracle.Query
  defdelegate update_all(query), to: Jamdb.Oracle.Query
  defdelegate delete_all(query), to: Jamdb.Oracle.Query
  defdelegate insert(prefix, table, header, rows, on_conflict, returning), to: Jamdb.Oracle.Query
  defdelegate update(prefix, table, fields, filters, returning), to: Jamdb.Oracle.Query
  defdelegate delete(prefix, table, filters, returning), to: Jamdb.Oracle.Query

  def to_constraints(_err), do: []
  
  def execute_ddl(err), do: error!(err)

  defp error!(msg) do
    raise DBConnection.ConnectionError, "#{inspect msg}"
  end
  
end
