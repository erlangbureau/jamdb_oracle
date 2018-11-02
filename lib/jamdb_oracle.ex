defmodule Jamdb.Oracle do
  @moduledoc """
  Oracle driver for Elixir.

  It relies on `DBConnection` to provide pooling, prepare, execute and more.

  """
  
  @behaviour DBConnection
  
  @doc """
  Connect to the database. Return `{:ok, pid}` on success or
  `{:error, term}` on failure.

  ## Options

    * `:hostname` - Server hostname (Name or IP address of the database server)
    * `:port` - Server port (Number of the port where the server listens for requests)
    * `:database` - Database (Database service name or SID with colon as prefix)
    * `:username` - Username (Name for the connecting user)
    * `:password` - User password (Password for the connecting user)
    * `:parameters` - Keyword list of connection parameters
    * `:socket_options` - Options to be given to the underlying socket
    * `:timeout` - The default timeout to use on queries, defaults to `15000`
    * `:charset` - Name that is used in multibyte encoding

  This callback is called in the connection process.
  """  
  @callback connect(opts :: Keyword.t) :: 
    {:ok, pid} | {:error, term}
  def connect(opts) do
    database = Keyword.fetch!(opts, :database) |> to_charlist
    env = if( hd(database) == ?:, do: [sid: tl(database)], else: [service_name: database] )
    |> Keyword.put_new(:host, Keyword.fetch!(opts, :hostname) |> to_charlist)
    |> Keyword.put_new(:port, Keyword.fetch!(opts, :port))
    |> Keyword.put_new(:user, Keyword.fetch!(opts, :username) |> to_charlist)
    |> Keyword.put_new(:password, Keyword.fetch!(opts, :password) |> to_charlist)
    |> Keyword.put_new(:timeout, Keyword.fetch!(opts, :timeout))
    params = if( Keyword.has_key?(opts, :parameters) == true,
      do: opts[:parameters], else: [] )
    sock_opts = if( Keyword.has_key?(opts, :socket_options) == true,
      do: [socket_options: opts[:socket_options]], else: [] )
    :jamdb_oracle.start_link(sock_opts ++ params ++ env) 
  end

  @doc """
  Disconnect from the database. Return `:ok`.

  This callback is called in the connection process.
  """
  @callback disconnect(err :: term, s :: pid) :: :ok
  def disconnect(_err, s) do
    :jamdb_oracle.stop(s) 
  end

  @doc """
  Runs custom SQL query on given pid.

  In case of success, it must return an `:ok` tuple containing result struct. Its fields are:

    * `:columns` - The column names
    * `:num_rows` - The number of fetched or affected rows
    * `:rows` - The result set as list

  ## Examples

      iex> Jamdb.Oracle.query(s, 'select 1+:1, sysdate, rowid from dual where 1=:1 ',[1])
      {:ok, %{num_rows: 1, rows: [[{2}, {{2016, 8, 1}, {13, 14, 15}}, 'AAAACOAABAAAAWJAAA']]}}

  """
  @callback query(s :: pid, sql :: String.t, params :: [term] | map) :: 
    {:ok, term} | {:error, term}  
  def query(s, sql, params \\ []) do
    case :jamdb_oracle.sql_query(s, {sql, params}) do
      {:ok, [{_, columns, _, rows}]} ->
        {:ok, %{num_rows: length(rows), rows: rows, columns: columns}, s}
      {:ok, [{_, 0, rows}]} -> {:ok, %{num_rows: length(rows), rows: rows}, s}
      {:ok, [{_, code, msg}]} -> {:error, %{code: code, message: msg}, s}
      {:ok, [{_, num_rows}]} -> {:ok, %{num_rows: num_rows, rows: nil}, s}
      {:ok, result} -> {:ok, result, s}
      {:error, _, err} -> {:error, err, s}
    end
  end

  @doc false
  def handle_execute(query, params, opts, s) do
    %Jamdb.Oracle.Query{statement: statement} = query
    returning = Keyword.get(opts, :returning, []) |> Enum.filter(& is_tuple(&1))
    query(s, statement |> to_charlist, Enum.concat(params, returning))
  end

  @doc false
  def handle_prepare(%Jamdb.Oracle.Query{statement: %Jamdb.Oracle.Query{} = query}, opts, s) do
    {:ok, query, s}
  end
  def handle_prepare(query, opts, s) do
    {:ok, query, s}
  end

  @doc false
  def handle_begin(opts, s) do
    case Keyword.get(opts, :mode, :transaction) do
      :transaction -> query(s, 'SAVEPOINT tran')
      :savepoint   -> query(s, 'SAVEPOINT '++(Keyword.get(opts, :name, :svpt) |> to_charlist))
    end
  end

  @doc false
  def handle_commit(opts, s) do
    query(s, 'COMMIT')
  end

  @doc false
  def handle_rollback(opts, s) do
    case Keyword.get(opts, :mode, :transaction) do
      :transaction -> query(s, 'ROLLBACK TO tran')
      :savepoint   -> query(s, 'ROLLBACK TO '++(Keyword.get(opts, :name, :svpt) |> to_charlist))
    end
  end

  @doc false
  def handle_declare(query, params, opts, s) do
    {:ok, params, s}
  end

  @doc false
  def handle_first(query, params, opts, s) do
    case handle_execute(query, params, opts, s) do
      {:ok, result, s} -> {:deallocate, result, s}
      {:error, err, s} -> {:error, error!(err), s}
    end
  end

  @doc false
  def handle_next(query, cursor, opts, s) do
    {:deallocate, nil, s}
  end

  @doc false
  def handle_deallocate(query, cursor, opts, s) do
    {:ok, nil, s}
  end

  @doc false
  def handle_close(query, opts, s) do
    {:ok, nil, s}
  end

  @doc false
  def handle_info(msg, s) do
    {:ok, s}
  end

  @doc false
  def checkin(s) do
    {:ok, s}
  end

  @doc false
  def checkout(s) do
    case query(s, 'SESSION') do
      {:ok, _, s} -> {:ok, s}
      disconnect -> disconnect
    end
  end

  @doc false
  def ping(s) do
    case query(s, 'PING') do
      {:ok, _, s} -> {:ok, s}
      disconnect -> disconnect
    end
  end

  defp error!(msg) do
    DBConnection.ConnectionError.exception("#{inspect msg}")
  end

  ## Functions

  @typedoc false
  @type conn :: DBConnection.conn

  @doc """
  Connect to the database.
  """
  @spec start_link(Keyword.t) :: {:ok, pid}
  def start_link(opts) do
    DBConnection.start_link(Jamdb.Oracle, opts)
  end

  @doc """
  Execute a query with a database connection and return the result.
  """
  @spec query!(conn, String.t, [term] | map, Keyword.t) ::
    {:ok, term} | {:error, term}
  def query!(conn, statement, params \\ [], opts \\ []) do
    DBConnection.prepare_execute!(
      conn, %Jamdb.Oracle.Query{statement: statement}, params, opts)
  end

  @doc """
  Acquire a lock on a connection and run a series of requests inside a
  transaction.

  To use the locked connection call the request with the connection
  reference passed as the single argument to the `fun`.
  """
  @spec transaction(conn, ((DBConnection.t) -> result), Keyword.t) ::
    {:ok, result} | {:error, any} when result: var
  def transaction(conn, fun, opts \\ []) do
    DBConnection.transaction(conn, fun, opts)
  end

  @doc """
  Rollback a transaction, does not return.

  Aborts the current transaction fun.
  """
  @spec rollback(DBConnection.t, any) :: no_return()
  defdelegate rollback(conn, any), to: DBConnection

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
  defp decode({date, time, tz}) when is_tuple(date) and is_list(tz), do: to_utc({date, time, tz})
  defp decode({date, time, _}) when is_tuple(date), do: to_naive({date, time})
  defp decode(elem) when is_list(elem), do: to_binary(elem)
  defp decode(elem), do: elem

  def encode(_, [], _), do: []
  def encode(_, params, opts) do 
    charset = if( Keyword.has_key?(opts, :charset) == true, 
      do: Enum.member?(["al16utf16","ja16euc","zhs16gbk","zht16big5","zht16mswin950"],
        opts[:charset]), else: false )
    Enum.map(params, fn elem -> encode(elem, charset) end)
  end

  defp encode(nil, _), do: :null
  defp encode(%Decimal{} = decimal, _), do: Decimal.to_float(decimal)
  defp encode(%Ecto.Query.Tagged{value: elem}, _), do: elem
  defp encode(elem, false) when is_binary(elem), do: elem |> to_charlist
  defp encode(elem, _), do: elem

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

  defp to_naive({{year, mon, day}, {hour, min, sec}}) when is_integer(sec),
    do: {{year, mon, day}, {hour, min, sec}}
  defp to_naive({{year, mon, day}, {hour, min, sec}}),
    do: {{year, mon, day}, parse_time({hour, min, sec})}

  defp to_utc({date, time, tz}) do
    {hour, min, sec, usec} = parse_time(time)
    offset = parse_offset(to_string(tz))
    seconds = :calendar.datetime_to_gregorian_seconds({date, {hour, min, sec}})
    {{year, mon, day}, {hour, min, sec}} = :calendar.gregorian_seconds_to_datetime(seconds + offset)

    %DateTime{year: year, month: mon, day: day, hour: hour, minute: min, second: sec,
     microsecond: {usec, 6}, std_offset: 0, utc_offset: 0, zone_abbr: "UTC", time_zone: to_string(tz)}
  end

  defp parse_time({hour, min, sec}),
    do: {hour, min, trunc(sec), trunc((sec - trunc(sec)) * 1000000)}

  defp parse_offset(tz) do
    case Calendar.ISO.parse_offset(tz) do
      {offset, ""} when is_integer(offset) -> offset
      _ -> 0
    end
  end

end
