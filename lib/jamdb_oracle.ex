defmodule Jamdb.Oracle do
  @moduledoc """
  Adapter module for Oracle. `DBConnection` behaviour implementation.

  It uses `jamdb_oracle` for communicating to the database.

  """

  use DBConnection

  defstruct [:pid, :mode, :cursors]  

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
    {:ok, any()} | {:error | :disconnect, any()}
  def query(conn, sql, params \\ [])
  def query(pid, sql, params) when is_pid(pid), do: query(%{pid: pid}, sql, params)
  def query(%{pid: pid}, sql, params) do
    case :jamdb_oracle.sql_query(pid, stmt(sql, params)) do
      {:ok, [{:result_set, columns, _, rows}]} ->
        {:ok, %{num_rows: length(rows), rows: rows, columns: columns}}
      {:ok, [{:fetched_rows, _, _, _} = result]} -> {:cont, result}
      {:ok, [{:proc_result, 0, rows}]} -> {:ok, %{num_rows: length(rows), rows: rows}}
      {:ok, [{:proc_result, _, _}] = result} -> {:error, result}
      {:ok, [{:affected_rows, num_rows}]} -> {:ok, %{num_rows: num_rows, rows: nil}}
      {:ok, result} -> {:ok, result}
      {:error, _, err} -> {:disconnect, err}
    end
  end

  defp stmt({:fetch, sql, params}, _), do: {:fetch, sql, params}
  defp stmt({:fetch, cursor, row_format, last_row}, _), do: {:fetch, cursor, row_format, last_row}
  defp stmt(sql, params), do: {sql, params}
  
  @impl true
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
    case :jamdb_oracle.start_link(sock_opts ++ params ++ env) do
      {:ok, pid} -> {:ok, %Jamdb.Oracle{pid: pid, mode: :idle}}
      {:error, [{:proc_result, _, msg}]} -> {:error, error!(msg)}
      {:error, err} -> {:error, error!(err)}
    end
  end

  @impl true
  def disconnect(_err, %{pid: pid}) do
    :jamdb_oracle.stop(pid) 
  end

  @impl true
  def handle_execute(query, params, opts, s) do
    %Jamdb.Oracle.Query{statement: statement} = query
    returning = Keyword.get(opts, :returning, []) |> Enum.filter(& is_tuple(&1))
	case query(s, statement |> to_charlist, Enum.concat(params, returning)) do
      {:ok, result} -> {:ok, query, result, s}
      {:error, [{:proc_result, _, msg}]} -> {:error, error!(msg), s}
	  {:error, err} -> {:error, error!(err), s}
	  {:disconnect, err} -> {:disconnect, error!(err), s}
    end
  end

  @impl true
  def handle_prepare(query, _opts, s) do
    {:ok, query, s}
  end

  @impl true
  def handle_begin(opts, %{mode: mode} = s) do
    case Keyword.get(opts, :mode, :transaction) do
      :transaction when mode == :idle ->
        statement = "SAVEPOINT tran"
	    handle_transaction(statement, opts, %{s | mode: :transaction})
      :savepoint when mode == :transaction ->
        statement = "SAVEPOINT " ++ Keyword.get(opts, :name, :svpt)
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
        statement = "COMMIT"
	    handle_transaction(statement, opts, %{s | mode: :idle})
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
        statement = "ROLLBACK TO " ++ Keyword.get(opts, :name, :svpt)
	    handle_transaction(statement, opts, %{s | mode: :transaction})
      status when status in [:transaction, :savepoint] ->
        {status, s}
    end
  end

  defp handle_transaction(statement, _opts, s) do
	case query(s, statement |> to_charlist) do
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
	case query(s, {:fetch, statement |> to_charlist, params}) do
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

  @impl true
  def checkin(s) do
    {:ok, s}
  end

  @impl true
  def checkout(s) do
    case query(s, 'SESSION') do
      {:ok, _} -> {:ok, s}
	  {:error, err} ->  {:disconnect, error!(err), s}
    end
  end

  @impl true
  def ping(%{mode: :idle} = s) do
    case query(s, 'PING') do
      {:ok, _} -> {:ok, s}
	  {:error, err} -> {:disconnect, error!(err), s}
    end
  end
  def ping(%{mode: :transaction} = s) do
    {:ok, s}
  end

  defp error!(msg) do
    DBConnection.ConnectionError.exception("#{inspect msg}")
  end

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
  defp decode({date, time, _}) when is_tuple(date), do: to_utc({date, time})
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
  defp encode(%DateTime{} = datetime, _), do: NaiveDateTime.to_erl(DateTime.to_naive(datetime))
  defp encode(%NaiveDateTime{} = naive, _), do: NaiveDateTime.to_erl(naive)
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

  defp to_naive({date, {hour, min, sec}}) when is_integer(sec),
    do: NaiveDateTime.from_erl!({date, {hour, min, sec}})
  defp to_naive({date, {hour, min, sec}}),
    do: NaiveDateTime.from_erl!({date, {hour, min, trunc(sec)}}, parse_sec(sec))

  defp to_utc({date, time}),
    do: DateTime.from_naive!(to_naive({date, time}), "Etc/UTC")

  defp parse_sec(sec),
    do: {trunc((sec - trunc(sec)) * 1000000) , 6}

end
