defmodule Jamdb.Oracle.Query do
  @moduledoc false

  defstruct [:statement]  
  
  alias Ecto.Query
  alias Ecto.Query.{BooleanExpr, JoinExpr, QueryExpr}

  def all(query) do
    sources = create_names(query)

    from     = from(query, sources)
    select   = select(query, sources)
    join     = join(query, sources)
    where    = where(query, sources)
    group_by = group_by(query, sources)
    having   = having(query, sources)
    order_by = order_by(query, sources)
    limit    = limit(query, sources)
    offset   = offset(query, sources)
    lock     = lock(query.lock)

    IO.iodata_to_binary([select, from, join, where, group_by, having, order_by, offset, limit | lock])
  end

  def update_all(%{from: from} = query, prefix \\ nil) do
    sources = create_names(query)
    {from, name} = get_source(query, sources, 0, from)

    prefix = prefix || ["UPDATE ", from, ?\s, name | " SET "]
    fields = update_fields(query, sources)
    where = where(%{query | wheres: query.wheres}, sources)

    IO.iodata_to_binary([prefix, fields, where | returning(query, sources)])
  end

  def delete_all(%{from: from} = query) do
    sources = create_names(query)
    {from, name} = get_source(query, sources, 0, from)

    where = where(%{query | wheres: query.wheres}, sources)
    
    IO.iodata_to_binary(["DELETE FROM ", from, ?\s, name, where | returning(query, sources)])
  end

  def insert(prefix, table, header, rows, _on_conflict, returning) do
    {fields, values} = cond do
      header == [] ->
        {returning, [" VALUES ", ?(, intersperse_map(returning, ?,, fn _ -> "DEFAULT" end), ?)]}
      length(rows) == 1 ->
        {header, [" VALUES " | insert_all(rows, 1)]}
      true ->
        {header, [?\s, ?(, insert_union(rows, 1), ?)]}
    end 

    IO.iodata_to_binary(["INSERT INTO ", quote_table(prefix, table), ?\s, ?(, 
                         intersperse_map(fields, ?,, &quote_name/1), ?), values | returning(returning)])
  end

  defp insert_union(rows, counter) do
    intersperse_reduce(rows, "UNION ALL ", counter, fn row, counter ->
      {row, counter} = insert_each(row, counter)
      {["SELECT ", row, " FROM DUAL "], counter}
    end)
    |> elem(0)
  end
  
  defp insert_all(rows, counter) do
    intersperse_reduce(rows, ?,, counter, fn row, counter ->
      {row, counter} = insert_each(row, counter)
      {[?(, row, ?)], counter}
    end)
    |> elem(0)
  end

  defp insert_each(values, counter) do
    intersperse_reduce(values, ?,, counter, fn
      nil, counter ->
        {"DEFAULT", counter}
      _, counter ->
        {[?: | Integer.to_string(counter)], counter + 1}
    end)
  end

  def update(prefix, table, fields, filters, returning) do
    {fields, count} = intersperse_reduce(fields, ", ", 1, fn field, acc ->
      {[quote_name(field), " = :" | Integer.to_string(acc)], acc + 1}
    end)

    {filters, _count} = intersperse_reduce(filters, " AND ", count, fn field, acc ->
      {[quote_name(field), " = :" | Integer.to_string(acc)], acc + 1}
    end)

    IO.iodata_to_binary(["UPDATE ", quote_table(prefix, table), " SET ",
                         fields, " WHERE ", filters | returning(returning)])
  end

  def delete(prefix, table, filters, returning) do
    {filters, _} = intersperse_reduce(filters, " AND ", 1, fn field, acc ->
      {[quote_name(field), " = :" | Integer.to_string(acc)], acc + 1}
    end)

    IO.iodata_to_binary(["DELETE FROM ", quote_table(prefix, table), " WHERE ",
                         filters | returning(returning)])
  end

  ## Query generation

  binary_ops =
    [==: " = ", !=: " != ", <=: " <= ", >=: " >= ", <: " < ", >: " > ",
     and: " AND ", or: " OR ", like: " LIKE "]

  @binary_ops Keyword.keys(binary_ops)

  Enum.map(binary_ops, fn {op, str} ->
    defp handle_call(unquote(op), 2), do: {:binary_op, unquote(str)}
  end)

  defp handle_call(fun, _arity), do: {:fun, Atom.to_string(fun)}

  defp select(%Query{select: %{fields: fields}, distinct: distinct} = query, sources) do
    ["SELECT ", distinct(distinct, sources, query) | select_fields(fields, sources, query)]
  end

  defp distinct(nil, _, _), do: []
  defp distinct(%QueryExpr{expr: true}, _, _), do: "DISTINCT "
  defp distinct(%QueryExpr{expr: false}, _, _), do: []
  defp distinct(%QueryExpr{expr: exprs}, _, _) when is_list(exprs), do: "DISTINCT "

  defp select_fields([], _sources, _query),
    do: "NULL"
  defp select_fields(fields, sources, query) do
    intersperse_map(fields, ", ", fn
      {key, value} ->
        [expr(value, sources, query), ?\s | quote_name(key)]
      value ->
        expr(value, sources, query)
    end)
  end

  defp from(%{from: from} = query, sources) do
    {from, name} = get_source(query, sources, 0, from)
    [" FROM ", from, ?\s | name]
  end

  defp update_fields(%Query{updates: updates} = query, sources) do
    for(%{expr: expr} <- updates,
        {op, kw} <- expr,
        {key, value} <- kw,
        do: update_op(op, key, value, sources, query)) |> Enum.intersperse(", ")
  end

  defp update_op(:set, key, value, sources, query) do
    [quote_name(key), " = " | expr(value, sources, query)]
  end

  defp update_op(:inc, key, value, sources, query) do
    [quote_name(key), " = ", quote_qualified_name(key, sources, 0), " + " |
     expr(value, sources, query)]
  end

  defp update_op(command, _key, _value, _sources, query) do
    error!(query, "Unknown update operation #{inspect command}")
  end

  defp join(%Query{joins: []}, _sources), do: []
  defp join(%Query{joins: joins} = query, sources) do
    [?\s | intersperse_map(joins, ?\s, fn
      %JoinExpr{on: %QueryExpr{expr: expr}, qual: qual, ix: ix, source: source} ->
        {join, name} = get_source(query, sources, ix, source)
        [join_qual(qual), join, ?\s, name, " ON " | expr(expr, sources, query)]
    end)]
  end

  defp join_qual(:inner), do: "JOIN "
  defp join_qual(:left),  do: "LEFT JOIN "
  defp join_qual(:right), do: "RIGHT JOIN "
  defp join_qual(:full),  do: "FULL JOIN "

  defp where(%Query{wheres: wheres} = query, sources) do
    boolean(" WHERE ", wheres, sources, query)
  end

  defp having(%Query{havings: havings} = query, sources) do
    boolean(" HAVING ", havings, sources, query)
  end

  defp group_by(%Query{group_bys: []}, _sources), do: []
  defp group_by(%Query{group_bys: group_bys} = query, sources) do
    [" GROUP BY " |
     intersperse_map(group_bys, ", ", fn
       %QueryExpr{expr: expr} ->
         intersperse_map(expr, ", ", &expr(&1, sources, query))
     end)]
  end

  defp order_by(%Query{order_bys: []}, _sources), do: []
  defp order_by(%Query{order_bys: order_bys} = query, sources) do
    [" ORDER BY " |
     intersperse_map(order_bys, ", ", fn
       %QueryExpr{expr: expr} ->
         intersperse_map(expr, ", ", &order_by_expr(&1, sources, query))
     end)]
  end

  defp order_by_expr({dir, expr}, sources, query) do
    str = expr(expr, sources, query)
    case dir do
      :asc  -> str
      :desc -> [str | " DESC"]
    end
  end

  defp limit(%Query{limit: nil}, _sources), do: []
  defp limit(%Query{limit: %QueryExpr{expr: expr}} = query, sources) do
    [" FETCH NEXT ", expr(expr, sources, query), " ROWS ONLY"]
  end
  
  defp offset(%Query{offset: nil}, _sources), do: []
  defp offset(%Query{offset: %QueryExpr{expr: expr}} = query, sources) do
    [" OFFSET ", expr(expr, sources, query), " ROWS"]
  end

  defp lock(nil), do: []
  defp lock(lock_clause), do: [?\s | lock_clause]

  defp boolean(_name, [], _sources, _query), do: []
  defp boolean(name, [%{expr: expr, op: op} | query_exprs], sources, query) do
    [name |
     Enum.reduce(query_exprs, {op, paren_expr(expr, sources, query)}, fn
       %BooleanExpr{expr: expr, op: op}, {op, acc} ->
         {op, [acc, operator_to_boolean(op), paren_expr(expr, sources, query)]}
       %BooleanExpr{expr: expr, op: op}, {_, acc} ->
         {op, [?(, acc, ?), operator_to_boolean(op), paren_expr(expr, sources, query)]}
     end) |> elem(1)]
  end

  defp operator_to_boolean(:and), do: " AND "
  defp operator_to_boolean(:or), do: " OR "

  defp paren_expr(expr, sources, query) do
    [?(, expr(expr, sources, query), ?)]
  end

  defp expr({:^, [], [ix]}, _sources, _query) do
    [?: | Integer.to_string(ix + 1)]
  end

  defp expr({{:., _, [{:&, _, [idx]}, field]}, _, []}, sources, _query) when is_atom(field) do
    quote_qualified_name(field, sources, idx)
  end

  defp expr({:&, _, [idx, fields, _counter]}, sources, query) do
    {_, name, schema} = elem(sources, idx)
    if is_nil(schema) and is_nil(fields) do
      error!(query, "Requires a schema module when using selector " <>
        "#{inspect name} but none was given. " <>
        "Please specify a schema or specify exactly which fields from " <>
        "#{inspect name} you desire")
    end
    intersperse_map(fields, ", ", &[name, ?. | quote_name(&1)])
  end
  
  defp expr({:in, _, [_left, []]}, _sources, _query), do: "1=2"
  
  defp expr({:in, _, [left, right]}, sources, query) when is_list(right) do
    args = intersperse_map(right, ?,, &expr(&1, sources, query))
    [expr(left, sources, query), " IN (", args, ?)]
  end

  defp expr({:in, _, [left, {:^, _, [ix, _]}]}, sources, query) do
    [expr(left, sources, query), " = ANY(:", Integer.to_string(ix + 1), ?)]
  end

  defp expr({:in, _, [left, right]}, sources, query) do
    [expr(left, sources, query), " = ANY(", expr(right, sources, query), ?)]
  end

  defp expr({:is_nil, _, [arg]}, sources, query) do
    [expr(arg, sources, query) | " IS NULL"]
  end

  defp expr({:not, _, [expr]}, sources, query) do
    ["NOT (", expr(expr, sources, query), ?)]
  end

  defp expr(%Ecto.SubQuery{query: query, fields: fields}, _sources, _query) do
    query.select.fields |> put_in(fields) |> all()
  end
  
  defp expr({:fragment, _, parts}, sources, query) do
    Enum.map(parts, fn
      {:raw, part}  -> part
      {:expr, expr} -> expr(expr, sources, query)
    end)
  end

  defp expr({:date_add, _, [date, count, interval]}, sources, query) do
    interval(date, " + ", count, interval, sources, query)
  end

  defp expr({:datetime_add, _, [datetime, count, interval]}, sources, query) do
    interval(datetime, " + ", count, interval, sources, query)
  end

  defp expr({:from_now, _, [count, interval]}, sources, query) do
    interval(Ecto.DateTime.utc, " + ", count, interval, sources, query)
  end

  defp expr({:ago, _, [count, interval]}, sources, query) do
    interval(Ecto.DateTime.utc, " - ", count, interval, sources, query)
  end

  defp expr({fun, _, args}, sources, query) when is_atom(fun) and is_list(args) do
    case handle_call(fun, length(args)) do
      {:binary_op, op} ->
        [left, right] = args
        [op_to_binary(left, sources, query), op | op_to_binary(right, sources, query)]
      {:fun, fun} ->
        [fun, ?(, [], intersperse_map(args, ", ", &expr(&1, sources, query)), ?)]
    end
  end

  defp expr(%Ecto.Query.Tagged{value: literal}, sources, query) do
    expr(literal, sources, query)
  end

  defp expr(literal, _sources, _query) when is_binary(literal) or is_list(literal) do
     ["'", escape_string(literal), "'"]
  end

  defp expr(literal, _sources, _query) when is_integer(literal) do
    Integer.to_string(literal)
  end

  defp expr(literal, _sources, _query) when is_float(literal) do
    Float.to_string(literal)
  end

  defp interval(datetime, literal, count, interval, sources, query) do
    [?(, expr(datetime, sources, query), literal, " INTERVAL '", 
         expr(count, sources, query), "' ", interval, ?)]
  end

  defp op_to_binary({op, _, [_, _]} = expr, sources, query) when op in @binary_ops do
    paren_expr(expr, sources, query)
  end

  defp op_to_binary(expr, sources, query) do
    expr(expr, sources, query)
  end

  defp returning(%Query{select: nil}, _sources),
    do: []
  defp returning(%Query{select: %{fields: fields}} = query, sources) do
    [{:&, _, [_idx, returning, _counter]}] = fields
    [" RETURN ", select_fields(fields, sources, query),
     " INTO ", intersperse_map(returning, ", ", &[?: | quote_name(&1)])]
  end
  
  defp returning([]),
    do: []
  defp returning(fields) do
    returning = fields |> Enum.filter(& is_tuple(&1) == false)
    [" RETURN ", intersperse_map(returning, ", ", &quote_name/1),
     " INTO ", intersperse_map(returning, ", ", &[?: | quote_name(&1)])]
  end   
         
  defp create_names(%{prefix: prefix, sources: sources}) do
    create_names(prefix, sources, 0, tuple_size(sources)) |> List.to_tuple()
  end

  defp create_names(prefix, sources, pos, limit) when pos < limit do
    current =
      case elem(sources, pos) do
        {table, schema} ->
          name = [String.first(table) | Integer.to_string(pos)]
          {quote_table(prefix, table), name, schema}
        {:fragment, _, _} ->
          {nil, [?f | Integer.to_string(pos)], nil}
        %Ecto.SubQuery{} ->
          {nil, [?s | Integer.to_string(pos)], nil}
      end
    [current | create_names(prefix, sources, pos + 1, limit)]
  end

  defp create_names(_prefix, _sources, pos, pos) do
    []
  end

  ## Helpers

  defp get_source(query, sources, ix, source) do
    {expr, name, _schema} = elem(sources, ix)
    {expr || paren_expr(source, sources, query), name}
  end

  defp quote_qualified_name(name, sources, ix) do
    {_, source, _} = elem(sources, ix)
    [source, ?. | quote_name(name)]
  end

  defp quote_name(name) when is_atom(name) do
    quote_name(Atom.to_string(name))
  end
  defp quote_name(name) do
    if String.contains?(name, "\"") do
      error!(nil, "bad field name #{inspect name}")
    end
    [name]
  end

  defp quote_table(nil, name),    do: quote_table(name)
  defp quote_table(prefix, name), do: [quote_table(prefix), ?., quote_table(name)]

  defp quote_table(name) when is_atom(name),
    do: quote_table(Atom.to_string(name))
  defp quote_table(name) do
    if String.contains?(name, "\"") do
      error!(nil, "bad table name #{inspect name}")
    end
    [name]
  end

  defp intersperse_map(list, separator, mapper, acc \\ [])
  defp intersperse_map([], _separator, _mapper, acc),
    do: acc
  defp intersperse_map([elem], _separator, mapper, acc),
    do: [acc | mapper.(elem)]
  defp intersperse_map([elem | rest], separator, mapper, acc),
    do: intersperse_map(rest, separator, mapper, [acc, mapper.(elem), separator])

  defp intersperse_reduce(list, separator, user_acc, reducer, acc \\ [])
  defp intersperse_reduce([], _separator, user_acc, _reducer, acc),
    do: {acc, user_acc}
  defp intersperse_reduce([elem], _separator, user_acc, reducer, acc) do
    {elem, user_acc} = reducer.(elem, user_acc)
    {[acc | elem], user_acc}
  end
  defp intersperse_reduce([elem | rest], separator, user_acc, reducer, acc) do
    {elem, user_acc} = reducer.(elem, user_acc)
    intersperse_reduce(rest, separator, user_acc, reducer, [acc, elem, separator])
  end

  defp escape_string(value) when is_list(value) do
    escape_string(:binary.list_to_bin(value))
  end
  defp escape_string(value) when is_binary(value) do
    :binary.replace(value, "'", "''", [:global])
  end

  defp error!(nil, msg) do
    raise ArgumentError, msg
  end
  defp error!(query, msg) do
    raise Ecto.QueryError, query: query, message: msg
  end
  
end

defimpl List.Chars, for: Jamdb.Oracle.Query do
  def to_charlist(%Jamdb.Oracle.Query{statement: statement}) do
    String.to_charlist(statement)
  end
end

defimpl String.Chars, for: Jamdb.Oracle.Query do
  def to_string(%Jamdb.Oracle.Query{statement: statement}) do
    statement
  end
end
