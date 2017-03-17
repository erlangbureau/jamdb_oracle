defmodule Jamdb.Oracle do
  @moduledoc """
  Oracle driver for Elixir.
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
    :jamdb_oracle.start(env) 
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
  
  Terms with colon as prefix in the statement are bind variables, 
  acting as placeholders for the parameters: `:1`, `:2`, `:3`, `:one`, `:two`, `:three`.
  Stored procedure calls are supported inside a block.
  Result parameter must be registered as an `out` parameter: `{:out, term}`.
  Other parameters can be either `out` or `in`: `{:in, term}` or just `term`.
  The returning clause retrieves `out` parameters affected by a statement. 
  String parameter that uses the national character set must be UTF-16 binary.
  Binary LOB and RAW parameters can be a base 16 encoded string.
  
  The following literals are supported in the parameters:

    * Integers: `1`, `2`, `3`
    * Floats: `1.0`, `2.0`, `3.0`
    * Strings: `"one two three"`, `"ett två tre"`
    * Binaries: `<<0x56, 0xdb, 0x4e, 0x94, 0x51, 0x6d>>`
    * Tuples: `{2016, 8, 1}`, `{{2016, 8, 1}, {13, 14, 15, 160000}}`
    * Atoms: `:cursor`, `:null`

  In case of success, it must return an `:ok` tuple containing result struct. Its fields are:

    * `:columns` - The column names
    * `:num_rows` - The number of fetched or affected rows
    * `:rows` - The result set as list
    
  ## Examples

      iex> Jamdb.Oracle.query(s, 'select 1, sysdate, rowid from dual where 1=:1 ',[1])
      {:ok, %{num_rows: 1, rows: [[{1}, {{2016, 8, 1}, {13, 14, 15}}, 'AAAACOAABAAAAWJAAA']]}}

  """
  @callback query(s :: pid, sql :: String.t, params :: list | map) :: 
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
    query(s, statement |> to_charlist, params)
  end

  @doc false
  def handle_begin(opts, s) do
    case Keyword.get(opts, :mode, :transaction) do
      :transaction -> query(s, 'COMOFF')
      :savepoint   -> query(s, 'SAVEPOINT SVPT')
    end  
  end

  @doc false
  def handle_commit(opts, s) do
    case Keyword.get(opts, :mode, :transaction) do
      :transaction -> query(s, 'COMMIT')
                      query(s, 'COMON')
      :savepoint   -> query(s, 'COMMIT')
    end
  end

  @doc false
  def handle_rollback(opts, s) do
    case Keyword.get(opts, :mode, :transaction) do
      :transaction -> query(s, 'ROLLBACK')
                      query(s, 'COMON')
      :savepoint   -> query(s, 'ROLLBACK TO SVPT')
    end
  end
    
  @doc false
  def handle_prepare(query, opts, s) do 
    {:ok, query, s}
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
    {:ok, s}
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
  
end

defimpl DBConnection.Query, for: Jamdb.Oracle.Query do

  def parse(query, _), do: query
  def describe(query, _), do: query

  def decode(_, %{rows: nil} = result, _), do: result
  def decode(_, %{rows: []} = result, _), do: result
  def decode(_, %{num_rows: num_rows, rows: rows}, _), do: %{num_rows: num_rows, rows: decode!(rows, 0, [])}
  def decode(_, result, _), do: result
    
  defp decode!([], _op, acc), do: :lists.reverse(acc)
  defp decode!([row | rest], 0, acc), do: decode!(rest, 0, [for(elem <- decode!(row, 1, []), do: elem) | acc])        
  defp decode!([elem | rest], 1, acc), do: decode!(rest, 1, [decode(elem) | acc])

  defp decode(:null), do: nil
  defp decode({elem}) when is_number(elem), do: elem
  defp decode(elem), do: elem
  
  def encode(_, [], _), do: []
  def encode(_, params, _), do: encode!(params,[])
  
  defp encode!([], acc), do: :lists.reverse(acc)
  defp encode!([elem | rest], acc), do: encode!(rest, [encode(elem) | acc])

  defp encode(nil), do: :null
  defp encode(%Decimal{} = decimal), do: Decimal.to_float(decimal)
  defp encode(%Ecto.Query.Tagged{value: binary, type: :binary}), 
    do: :binary.bin_to_list(Base.encode16(binary, case: :lower))
  defp encode(%Ecto.Query.Tagged{value: elem}), do: elem
  defp encode(elem) when is_binary(elem) , do: :binary.bin_to_list(elem)
  defp encode(elem), do: elem
  
end
