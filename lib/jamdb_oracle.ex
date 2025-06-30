defmodule Jamdb.Oracle do
  @vsn "0.5.12"
  @moduledoc """
  Adapter module for Oracle. `DBConnection` behaviour implementation.

  It uses `jamdb_oracle` for communicating to the database.

  """

  use DBConnection

  @timeout 15_000
  @idle_interval 5_000

  defstruct [:pid, :mode, :cursors, :timeout, :idle_interval]

  @doc """
  Starts and links to a database connection process.

  See [`Ecto.Adapters.Jamdb.Oracle`](Ecto.Adapters.Jamdb.Oracle.html#module-connection-options).

  By default the `DBConnection` starts a pool with a single connection.
  The size of the pool can be increased with `:pool_size`. The ping interval 
  to validate an idle connection can be given with the `:idle_interval` option.
  """
  @spec start_link(opts :: Keyword.t) :: 
    {:ok, pid()} | {:error, any()}
  def start_link(opts) do
    DBConnection.start_link(Jamdb.Oracle, opts)
  end

  @doc """
  Runs the SQL statement.

  See `DBConnection.prepare_execute/4`.

  In case of success, it must return an `:ok` tuple containing
  a map with at least two keys:

    * `:num_rows` - the number of rows affected
    * `:rows` - the result set as a list  
  """
  @spec query(conn :: any(), sql :: any(), params :: any()) ::
    {:ok | :cont, any()} | {:error | :disconnect, any()}
  def query(conn, sql, params \\ [])
  def query(%{pid: pid, timeout: timeout}, sql, params) do
    case sql_query(pid, stmt(sql, params), timeout) do
      {:ok, [{:result_set, columns, _, rows}]} ->
        {:ok, %{num_rows: length(rows), rows: rows, columns: columns}}
      {:ok, [{:fetched_rows, _, _, _} = result]} -> {:cont, result}
      {:ok, [{:proc_result, 0, rows}]} -> {:ok, %{num_rows: length(rows), rows: rows}}
      {:ok, [{:proc_result, _, msg}]} -> {:error, msg}
      {:ok, [{:affected_rows, num_rows}]} -> {:ok, %{num_rows: num_rows, rows: nil}}
      {:ok, result} -> {:ok, result}
      {:error, err} -> {:disconnect, err}
    end
  end
  def query(pid, sql, params) when is_pid(pid) do
    query(%{pid: pid, timeout: @timeout}, sql, params)
  end

  defp sql_query(pid, query, timeout) do
    try do
      case :jamdb_oracle.sql_query(pid, query, timeout) do
        {:ok, result} -> {:ok, result}
        {:error, _, err} -> {:error, err}
      end
    catch
      _, err -> {:error, err}
    end
  end

  defp stmt({:fetch, sql, params}, _), do: {:fetch, sql, params}
  defp stmt({:fetch, cursor, row_format, last_row}, _), do: {:fetch, cursor, row_format, last_row}
  defp stmt({:batch, sql, params}, _), do: {:batch, sql, params}
  defp stmt(sql, params), do: {sql, params}
  
  @impl true
  def connect(opts) do
    host = opts[:hostname] |> Jamdb.Oracle.to_list
    port = opts[:port]
    timeout = opts[:timeout] || @timeout
    idle_interval = opts[:idle_interval] || @idle_interval
    user = opts[:username] |> Jamdb.Oracle.to_list
    password = opts[:password] |> Jamdb.Oracle.to_list
    database = opts[:database] |> Jamdb.Oracle.to_list
    env = [host: host, port: port, user: user, password: password, timeout: timeout, idle_interval: idle_interval]
	  ++ if( hd(database) == ?:, do: [sid: tl(database)], else: [service_name: database] )
    params = opts[:parameters] || []
    sock_opts = opts[:socket_options] || []
    case :jamdb_oracle.start_link(sock_opts ++ params ++ env) do
      {:ok, pid} -> {:ok, %Jamdb.Oracle{pid: pid, mode: :idle, timeout: timeout, idle_interval: idle_interval}}
      {:error, err} -> {:error, error!(err)}
    end
  end

  @impl true
  def disconnect(_err, %{pid: pid}) do
    try do
      :jamdb_oracle.stop(pid)
    catch
      _, _ -> :error
    end
    :ok
  end

  @impl true
  def handle_execute(%{batch: true} = query, params, _opts, s) do
    %Jamdb.Oracle.Query{statement: statement} = query
    case query(s, {:batch, statement |> Jamdb.Oracle.to_list, params}, []) do
      {:ok, result} -> {:ok, query, result, s}
      {:error, err} -> {:error, error!(err), s}
      {:disconnect, err} -> {:disconnect, error!(err), s}
    end
  end
  def handle_execute(query, params, opts, s) do
    %Jamdb.Oracle.Query{statement: statement} = query
    returning = Enum.map(Keyword.get(opts, :out, []), fn elem -> {:out, elem} end)
    case query(s, statement |> Jamdb.Oracle.to_list, Enum.concat(params, returning)) do
      {:ok, result} -> {:ok, query, result, s}
      {:error, err} -> {:error, error!(err), s}
      {:disconnect, err} -> {:disconnect, error!(err), s}
    end
  end

  @impl true
  def handle_prepare(query, opts, s) do
    timeout = opts[:timeout] || @timeout
    {:ok, query, %{s | timeout: timeout}}
  end

  @impl true
  def handle_begin(opts, %{mode: mode} = s) do
    case Keyword.get(opts, :mode, :transaction) do
      :transaction when mode == :idle ->
        statement = "SAVEPOINT tran"
        handle_transaction(statement, opts, %{s | mode: :transaction})
      :savepoint when mode == :transaction ->
        statement = "SAVEPOINT " <> Keyword.get(opts, :name, "svpt")
        handle_transaction(statement, opts, %{s | mode: :transaction})
      status when status in [:transaction, :savepoint] ->
        {status, s}
    end
  end

  @impl true
  def handle_commit(opts, %{mode: mode} = s) do
    case Keyword.get(opts, :mode, :transaction) do
      :transaction when mode == :transaction ->
        statement = "COMMIT"
        handle_transaction(statement, opts, %{s | mode: :idle})
      :savepoint when mode == :transaction ->
        {:ok, [], %{s | mode: :transaction}}
      status when status in [:transaction, :savepoint] ->
        {status, s}
    end
  end

  @impl true
  def handle_rollback(opts, %{mode: mode} = s) do
    case Keyword.get(opts, :mode, :transaction) do
      :transaction when mode in [:transaction, :error] ->
        statement = "ROLLBACK TO tran"
        handle_transaction(statement, opts, %{s | mode: :idle})
      :savepoint when mode in [:transaction, :error] ->
        statement = "ROLLBACK TO " <> Keyword.get(opts, :name, "svpt")
        handle_transaction(statement, opts, %{s | mode: :transaction})
      status when status in [:transaction, :savepoint] ->
        {status, s}
    end
  end

  defp handle_transaction(statement, _opts, s) do
    case query(s, statement |> Jamdb.Oracle.to_list) do
      {:ok, result} -> {:ok, result, s}
      {:error, err} -> {:error, error!(err), s}
      {:disconnect, err} -> {:disconnect, error!(err), s}
    end
  end

  @impl true
  def handle_declare(query, params, _opts, s) do
    {:ok, query, %{params: params}, s}
  end

  @impl true
  def handle_fetch(query, %{params: params}, _opts, %{cursors: nil} = s) do
    %Jamdb.Oracle.Query{statement: statement} = query
    case query(s, {:fetch, statement |> Jamdb.Oracle.to_list, params}) do
      {:cont, {_, cursor, row_format, rows}} ->
        cursors = %{cursor: cursor, row_format: row_format, last_row: List.last(rows)}
        {:cont,  %{num_rows: length(rows), rows: rows}, %{s | cursors: cursors}}
      {:ok, result} -> 
        {:halt, result, s}
      {:error, err} -> {:error, error!(err), s}
      {:disconnect, err} -> {:disconnect, error!(err), s}
    end
  end
  def handle_fetch(_query, _cursor, _opts, %{cursors: cursors} = s) do
    %{cursor: cursor, row_format: row_format, last_row: last_row} = cursors
    case query(s, {:fetch, cursor, row_format, last_row}) do
      {:cont, {_, _, _, rows}} ->
        rows = tl(rows)
        {:cont,  %{num_rows: length(rows), rows: rows}, 
        %{s | cursors: %{cursors | last_row: List.last(rows)}}}
      {:ok, %{rows: rows} = result} -> 
        rows = tl(rows)
        {:halt, %{result | num_rows: length(rows), rows: rows}, s}
      {:error, err} -> {:error, error!(err), s}
      {:disconnect, err} -> {:disconnect, error!(err), s}
    end
  end

  @impl true
  def handle_deallocate(_query, _cursor, _opts, s) do
    {:ok, nil, %{s | cursors: nil}}
  end

  @impl true
  def handle_close(_query, _opts, s) do
    {:ok, nil, s}
  end

  @impl true
  def handle_status(_opts, %{mode: mode} = s) do
    {mode, s}
  end

  @doc false
  def checkin(s) do
    {:ok, s}
  end

  @impl true
  def checkout(%{pid: pid, timeout: timeout} = s) do
    case sql_query(pid, ~c'SESSION', timeout) do
      {:ok, _} -> {:ok, s}
      {:error, err} -> {:disconnect, error!(err), s}
    end
  end

  @impl true
  def ping(%{pid: pid, timeout: timeout, idle_interval: idle_interval} = s) do
    case sql_query(pid, ~c'PING', min(timeout, idle_interval)) do
      {:ok, _} -> {:ok, s}
      {:error, err} -> {:disconnect, error!(err), s}
    end
  end

  defp error!(msg) do
    DBConnection.ConnectionError.exception("#{inspect msg}")
  end

  @doc """
  Returns the configured JSON library.

  To customize the JSON library, include the following in your `config/config.exs`:

      config :jamdb_oracle, :json_library, SomeJSONModule

  Defaults to [`Jason`](https://hexdocs.pm/jason)
  """
  @spec json_library() :: module()
  def json_library() do
    Application.get_env(:jamdb_oracle, :json_library, Jason)
  end

  @doc """
  Strip single/multiline comments
  """
  @spec strip(sql :: String.t) :: String.t
  def strip(sql) do
    sql = Regex.replace(~r"--.*", sql, "")
    sql = Regex.replace(~r"(?s)/\*.*?\*/", sql, "")
    sql
  end

  @doc false
  def to_list(string) when is_binary(string) do
    :binary.bin_to_list(string)
  end

  @doc false
  defdelegate loaders(t, type), to: Ecto.Adapters.Jamdb.Oracle
  @doc false
  defdelegate dumpers(t, type), to: Ecto.Adapters.Jamdb.Oracle

end

defimpl DBConnection.Query, for: Jamdb.Oracle.Query do

  def parse(query, _), do: query
  def describe(query, _), do: query

  def decode(_, %{rows: []} = result, _), do: result
  def decode(_, %{rows: rows} = result, opts) when rows != nil, 
    do: %{result | rows: Enum.map(rows, fn row -> decode(row, opts[:decode_mapper]) end)}
  def decode(_, result, _), do: result

  defp decode(row, nil), do: Enum.map(row, fn elem -> decode(elem) end)
  defp decode(row, mapper), do: mapper.(decode(row, nil))

  defp decode(:null), do: nil
  defp decode({elem}) when is_number(elem), do: elem
  defp decode({date, time}) when is_tuple(date), do: to_naive({date, time})
  defp decode({date, time, tz}) when is_tuple(date), do: to_date({date, time, tz})
  defp decode(elem) when is_list(elem), do: to_binary(elem)
  defp decode(elem), do: elem

  def encode(_, [], _), do: []
  def encode(_, [%Ecto.Query.Tagged{value: params, type: :map}], _), do: [params]
  def encode(_, params, opts) do
    types = Keyword.get(opts, :in, [])
    case Keyword.get(opts, :batch) do
      true -> Enum.map(params, fn row -> Enum.map(encode(row, types), fn elem -> encode(elem) end) end)
      _ -> Enum.map(encode(params, types), fn elem -> encode(elem) end)
    end
  end

  defp encode(params, []), do: params
  defp encode([%Ecto.Query.Tagged{type: :binary} = elem | next1], [_type | next2]),
    do: [ elem | encode(next1, next2)]
  defp encode([elem | next1], [type | next2]) when type in [:binary, :binary_id, Ecto.UUID],
    do: [ %Ecto.Query.Tagged{value: elem, type: :binary} | encode(next1, next2)]
  defp encode([elem | next1], [_type | next2]), do: [ elem | encode(next1, next2)]

  defp encode(nil), do: :null
  defp encode(true), do: [49]
  defp encode(false), do: [48]
  defp encode(%Decimal{} = decimal), do: Decimal.to_float(decimal)
  defp encode(%DateTime{microsecond: {0, 0}, utc_offset: utc_offset, zone_abbr: "UTC"} = datetime) do
    {date, {hour, min, sec}} = NaiveDateTime.to_erl(DateTime.to_naive(datetime))
    {date, {hour, min, sec, 0}, utc_offset}
  end
  defp encode(%DateTime{microsecond: {ms, _}, utc_offset: utc_offset, zone_abbr: "UTC"} = datetime) do
    {date, {hour, min, sec}} = NaiveDateTime.to_erl(DateTime.to_naive(datetime))
    {date, {hour, min, sec, ms}, utc_offset}
  end
  defp encode(%NaiveDateTime{microsecond: {0, 0}} = naive),
    do: NaiveDateTime.to_erl(naive)
  defp encode(%NaiveDateTime{microsecond: {ms, _}} = naive) do
    {date, {hour, min, sec}} = NaiveDateTime.to_erl(naive)
    {date, {hour, min, sec, ms}}
  end
  defp encode(%Date{} = date), do: Date.to_erl(date)
  defp encode(%Ecto.Query.Tagged{value: elem, type: :binary}) when is_binary(elem), do: elem
  defp encode(elem) when is_binary(elem), do: Jamdb.Oracle.to_list(elem)
  defp encode(elem) when is_map(elem),
    do: encode(Jamdb.Oracle.json_library().encode!(elem))
  defp encode(elem), do: elem

  defp expr(list) when is_list(list) do
    Enum.map(list, fn 
      :null -> nil
      elem  -> elem
    end)
  end

  defp to_binary(list) when is_list(list) do
    try do
      :binary.list_to_bin(list)
    rescue
      ArgumentError ->
        Enum.map(expr(list), fn
          elem when is_list(elem) -> expr(elem)
          other -> other
        end) |> Enum.join
    end
  end

  defp to_naive({date, {hour, min, sec}}) when is_integer(sec),
    do: NaiveDateTime.from_erl!({date, {hour, min, sec}})
  defp to_naive({date, {hour, min, sec}}),
    do: NaiveDateTime.from_erl!({date, {hour, min, trunc(sec)}}, parse_sec(sec))

  defp to_date({{year, month, day}, {hour, min, sec}, tz}),
    do: %DateTime{year: year, month: month, day: day, hour: hour, minute: min,
    second: trunc(sec), microsecond: parse_sec(sec), time_zone: "Etc/UTC",
    zone_abbr: "UTC", utc_offset: parse_offset(IO.iodata_to_binary(tz)), std_offset: 0}

  defp parse_offset("Etc/UTC"), do: 0
  defp parse_offset(<<?+, hour::2-bytes, ?:, min::2-bytes, _rest::binary>>),
    do: parse_offset(1, hour, min)
  defp parse_offset(<<?-, hour::2-bytes, ?:, min::2-bytes, _rest::binary>>),
    do: parse_offset(-1, hour, min)
  defp parse_offset(_tz), do: 0

  defp parse_offset(sign, hour, min) do
    with {hour, ""} when hour < 24 <- Integer.parse(hour),
         {min, ""} when min < 60 <- Integer.parse(min) do
      (hour * 60 + min) * 60 * sign
    else
      _ -> :error
    end
  end

  defp parse_sec(sec),
    do: {trunc((sec - trunc(sec)) * 1000000) , 6}

end
