defmodule Ecto.Adapters.Jamdb.Oracle do
  @moduledoc """
  Adapter module for Oracle. `Ecto.Adapters.SQL` callbacks implementation.

  It uses `jamdb_oracle` for communicating to the database.

  """

  use Ecto.Adapters.SQL, driver: Jamdb.Oracle, migration_lock: nil

  @impl true
  def ensure_all_started(config, type) do
    Ecto.Adapters.SQL.ensure_all_started(:jamdb_oracle, config, type)
  end

  @impl true
  def loaders({:array, _}, type), do: [&array_decode/1, type]
  def loaders({:embed, _}, type), do: [&json_decode/1, &Ecto.Type.embedded_load(type, &1, :json)]
  def loaders({:map, _}, type),   do: [&json_decode/1, &Ecto.Type.embedded_load(type, &1, :json)]
  def loaders(:map, type),        do: [&json_decode/1, type]
  def loaders(:float, type),      do: [&float_decode/1, type]
  def loaders(:boolean, type),    do: [&bool_decode/1, type]
  def loaders(:binary_id, type),  do: [Ecto.UUID, type]
  def loaders(_, type),           do: [type]

  @impl true
  def dumpers({:map, _}, type),   do: [&Ecto.Type.embedded_dump(type, &1, :json)]
  def dumpers(:binary_id, type),  do: [type, Ecto.UUID]
  def dumpers(_, type),           do: [type]

  defp bool_decode("0"), do: {:ok, false}
  defp bool_decode("1"), do: {:ok, true}
  defp bool_decode(0), do: {:ok, false}
  defp bool_decode(1), do: {:ok, true}
  defp bool_decode(x), do: {:ok, x}

  defp float_decode(%Decimal{} = decimal), do: {:ok, Decimal.to_float(decimal)}
  defp float_decode(x), do: {:ok, x}

  defp json_decode(x) when is_binary(x), do: {:ok, Jamdb.Oracle.json_library().decode!(x)}
  defp json_decode(x), do: {:ok, x}

  defp array_decode(x) when is_binary(x), do: {:ok, Jamdb.Oracle.to_list(x)}
  defp array_decode(x), do: {:ok, x}

  @impl true
  def lock_for_migrations(_meta, _opts, fun), do: fun.()

  @impl true
  def supports_ddl_transaction? do
    false
  end

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
    DBConnection.execute(conn, query!(query, "", opts), params, opts)
  end

  @impl true
  def prepare_execute(conn, name, query, params, opts) do
    DBConnection.prepare_execute(conn, query!(query, name, opts), params, opts)
  end

  @impl true
  def stream(conn, query, params, opts) do
    DBConnection.stream(conn, query!(query, "", opts), params, opts)
  end

  @impl true
  def query(conn, query, params, opts) do
    case DBConnection.prepare_execute(conn, query!(query, "", opts), params, opts) do
      {:ok, _, result}  -> {:ok, result}
      {:error, err} -> {:error, err}
    end
  end

  @impl true
  def query_many(_conn, _query, _params, _opts) do
    error!(nil, "query_many is not supported")
  end

  @impl true
  def explain_query(conn, query, params, opts) do
    case query(conn, IO.iodata_to_binary(["EXPLAIN PLAN FOR ", query]), params, opts) do
      {:ok, _result} -> query(conn, "SELECT * FROM table(DBMS_XPLAN.DISPLAY())", params, opts)
      {:error, err} -> {:error, err}
    end
  end

  defp query!(sql, name, opts) when is_binary(sql) or is_list(sql) do
    %Jamdb.Oracle.Query{statement: IO.iodata_to_binary(sql), name: name, batch: opts[:batch]}
  end
  defp query!(%{} = query, _name, _opts) do
    query
  end

  defp error!(nil, msg) do
    raise ArgumentError, msg
  end

  @impl true
  defdelegate all(query), to: Jamdb.Oracle.Query
  @impl true
  defdelegate update_all(query), to: Jamdb.Oracle.Query
  @impl true
  defdelegate delete_all(query), to: Jamdb.Oracle.Query
  @impl true
  defdelegate insert(prefix, table, header, rows, on_conflict, returning, placeholders), to: Jamdb.Oracle.Query
  @impl true
  defdelegate update(prefix, table, fields, filters, returning), to: Jamdb.Oracle.Query
  @impl true
  defdelegate delete(prefix, table, filters, returning), to: Jamdb.Oracle.Query
  @impl true
  defdelegate table_exists_query(table), to: Jamdb.Oracle.Query
  @impl true
  defdelegate execute_ddl(command), to: Jamdb.Oracle.Query
  @impl true
  defdelegate ddl_logs(result), to: Jamdb.Oracle.Query
  @impl true
  defdelegate to_constraints(err, opts), to: Jamdb.Oracle.Query

end
