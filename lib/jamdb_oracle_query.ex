defmodule Jamdb.Oracle.Query do
  @moduledoc """
  Adapter module for Oracle. `DBConnection.Query` protocol implementation.

  See `DBConnection.prepare_execute/4`.

  """

  defstruct [:statement, :name, :batch]  

  @parent_as __MODULE__
  alias Ecto.Query.{BooleanExpr, JoinExpr, QueryExpr, WithExpr}

  @doc false
  def all(query, as_prefix \\ []) do
    sources = create_names(query, as_prefix)

    cte      = cte(query, sources)
    {from, hints} = from(query, sources)
    {select, fields} = select(query, sources)
    window   = window(query, sources)
    join     = join(query, sources)
    where    = where(query, sources)
    group_by = group_by(query, sources)
    having   = having(query, sources)
    combinations = combinations(query)
    order_by = order_by(query, sources)
    limit    = limit(query, sources)
    offset   = offset(query, sources)
    lock     = lock(query.lock)

    [cte, select, hints, fields, window, from, join, where,
     group_by, having, combinations, order_by, offset, limit | lock]
  end

  @doc false
  def update_all(%{from: %{source: source}, select: select} = query) do
    sources = create_names(query, [])

    {rows, where} =
      if select do
        {[insert_all(query, 0)], []}
      else
        {from, name} = get_source(query, sources, 0, source)
        {[from, ?\s, name], where(%{query | wheres: query.wheres}, sources)}
      end
    fields = update_fields(query, sources)

    ["UPDATE ", rows, " SET ", fields, where]
  end

  @doc false
  def delete_all(%{from: from, select: select} = query) do
    sources = create_names(query, [])

    {rows, where} =
      if select do
        {[insert_all(query, 0)], []}
      else
        {from, name} = get_source(query, sources, 0, from)
        {[from, ?\s, name], where(%{query | wheres: query.wheres}, sources)}
      end

    ["DELETE FROM ", rows, where]
  end

  @doc false
  def insert(prefix, table, header, rows, _on_conflict, returning, placeholders \\ []) do
    counter_offset = length(placeholders) + 1
	from = insert_all(rows, counter_offset)
    values =
      if header == [] do
        [?\s | from]
      else
        [?\s, ?(, intersperse_map(header, ?,, &quote_name/1), ?), ?\s | from]
      end

    ["INSERT INTO ", quote_table(prefix, table), values | returning(returning)]
  end

  defp insert_all(query = %Ecto.Query{}, _counter) do
    [?(, all(query), ?)]
  end

  defp insert_all(rows, counter) do
    ["VALUES ", intersperse_reduce(rows, ?,, counter, fn row, counter ->
      {row, counter} = insert_each(row, counter)
      {[?(, row, ?)], counter}
    end)
    |> elem(0)]
  end

  defp insert_each(values, counter) do
    intersperse_reduce(values, ?,, counter, fn
      nil, counter ->
        {"DEFAULT", counter}

      {%Ecto.Query{} = query, params_counter}, counter ->
        {[?(, all(query), ?)], counter + params_counter}

      {:placeholder, placeholder_index}, counter ->
        {[?: | placeholder_index], counter}

      _, counter ->
        {[?: | Integer.to_string(counter)], counter + 1}
    end)
  end

  @doc false
  def update(prefix, table, fields, filters, returning) do
    {fields, count} = intersperse_reduce(fields, ", ", 1, fn field, acc ->
      {[quote_name(field), " = :" | Integer.to_string(acc)], acc + 1}
    end)

    {filters, _count} = intersperse_reduce(filters, " AND ", count, fn
      {field, nil}, acc ->
        {[quote_name(field), " IS NULL"], acc}

      {field, _value}, acc ->
        {[quote_name(field), " = :" | Integer.to_string(acc)], acc + 1}
    end)

    ["UPDATE ", quote_table(prefix, table), " SET ",
     fields, " WHERE ", filters | returning(returning)]
  end

  @doc false
  def delete(prefix, table, filters, returning) do
    {filters, _} = intersperse_reduce(filters, " AND ", 1, fn
      {field, nil}, acc ->
        {[quote_name(field), " IS NULL"], acc}

      {field, _value}, acc ->
        {[quote_name(field), " = :" | Integer.to_string(acc)], acc + 1}
    end)

    ["DELETE FROM ", quote_table(prefix, table), " WHERE ", filters | returning(returning)]
  end

  @doc false
  def table_exists_query(table) do
    {"SELECT count(*) FROM user_tables WHERE table_name = :1 ", [table]}
  end

  @doc false
  def ddl_logs(_result), do: []

  @doc false
  def to_constraints(_err, _opts \\ []), do: []

  ## Query generation

  binary_ops =
    [==: " = ", !=: " != ", <=: " <= ", >=: " >= ", <: " < ", >: " > ",
     +: " + ", -: " - ", *: " * ", /: " / ",
     and: " AND ", or: " OR ", like: " LIKE "]

  @binary_ops Keyword.keys(binary_ops)

  Enum.map(binary_ops, fn {op, str} ->
    defp handle_call(unquote(op), 2), do: {:binary_op, unquote(str)}
  end)

  defp handle_call(fun, _arity), do: {:fun, Atom.to_string(fun)}

  defp select(%{select: %{fields: fields}, distinct: distinct} = query, sources) do
    {["SELECT "], [distinct(distinct, sources, query) | select_fields(fields, sources, query)]}
  end

  defp select_fields([], _sources, _query),
    do: "1"
  defp select_fields(fields, sources, query) do
    intersperse_map(fields, ", ", fn
      {:&, _, [idx]} ->
        case elem(sources, idx) do
          {_, source, nil} -> [source, ?. | "*"]
          {_, source, _} -> source
        end
      {key, value} ->
        [expr(value, sources, query), ?\s | quote_name(key)]
      value ->
        expr(value, sources, query)
    end)
  end

  defp hints([_ | _] = hints), do: ["/*+ ", Enum.intersperse(hints, " "), " */ "]
  defp hints([]), do: []

  defp distinct(nil, _, _), do: []
  defp distinct(%QueryExpr{expr: []}, _, _), do: {[], []}
  defp distinct(%QueryExpr{expr: true}, _, _), do: "DISTINCT "
  defp distinct(%QueryExpr{expr: false}, _, _), do: []
  defp distinct(%QueryExpr{expr: exprs}, _, _) when is_list(exprs), do: "DISTINCT "

  defp from(%{from: %{source: source, hints: hints}} = query, sources) do
    {from, name} = get_source(query, sources, 0, source)
    {[" FROM ", from, ?\s | name], hints(hints)}
  end

  defp cte(%{with_ctes: %WithExpr{queries: [_ | _] = queries}} = query, sources) do
    ctes = intersperse_map(queries, ", ", &cte_expr(&1, sources, query))
    ["WITH ", ctes, " "]
  end

  defp cte(%{with_ctes: _}, _), do: []

  defp cte_expr({name, cte}, sources, query) do
    [quote_name(name), " AS ", cte_query(cte, sources, query)]
  end
  defp cte_expr({name, _opts, cte}, sources, query) do
    [quote_name(name), " AS ", cte_query(cte, sources, query)]
  end

  defp cte_query(%Ecto.Query{} = query, sources, parent_query) do
    query = put_in(query.aliases[@parent_as], {parent_query, sources})
    ["(", all(query, subquery_as_prefix(sources)), ")"]
  end

  defp cte_query(%QueryExpr{expr: expr}, sources, query) do
    expr(expr, sources, query)
  end

  defp update_fields(%{updates: updates} = query, sources) do
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
    error!(query, "unknown update operation #{inspect command}")
  end

  defp join(%{joins: []}, _sources), do: []
  defp join(%{joins: joins} = query, sources) do
    [?\s | intersperse_map(joins, ?\s, fn
      %JoinExpr{on: %QueryExpr{expr: expr}, qual: qual, ix: ix, source: source} ->
        {join, name} = get_source(query, sources, ix, source)
        [join_qual(qual), join, ?\s, name | join_on(qual, expr, sources, query)]
    end)]
  end

  defp join_on(:cross, true, _sources, _query), do: []
  defp join_on(_qual, true, _sources, _query), do: [" ON 1 = 1"]
  defp join_on(_qual, expr, sources, query), do: [" ON " | expr(expr, sources, query)]

  defp join_qual(:inner), do: "INNER JOIN "
  defp join_qual(:left),  do: "LEFT OUTER JOIN "
  defp join_qual(:right), do: "RIGHT OUTER JOIN "
  defp join_qual(:full),  do: "FULL OUTER JOIN "
  defp join_qual(:cross), do: "CROSS JOIN "

  defp where(%{wheres: wheres} = query, sources) do
    boolean(" WHERE ", wheres, sources, query)
  end

  defp having(%{havings: havings} = query, sources) do
    boolean(" HAVING ", havings, sources, query)
  end

  defp group_by(%{group_bys: []}, _sources), do: []
  defp group_by(%{group_bys: group_bys} = query, sources) do
    [" GROUP BY " |
     intersperse_map(group_bys, ", ", fn
       %QueryExpr{expr: expr} ->
         intersperse_map(expr, ", ", &expr(&1, sources, query))
     end)]
  end

  defp window(%{windows: []}, _sources), do: []
  defp window(%{windows: windows} = query, sources) do
    intersperse_map(windows, ", ", fn
      {_, %{expr: kw}} ->
        window_exprs(kw, sources, query)
    end)
  end

  defp window_exprs(kw, sources, query) do
    [?(, intersperse_map(kw, ?\s, &window_expr(&1, sources, query)), ?)]
  end

  defp window_expr({:partition_by, fields}, sources, query) do
    ["PARTITION BY " | intersperse_map(fields, ", ", &expr(&1, sources, query))]
  end

  defp window_expr({:order_by, fields}, sources, query) do
    ["ORDER BY " | intersperse_map(fields, ", ", &order_by_expr(&1, sources, query))]
  end

  defp window_expr({:frame, {:fragment, _, _} = fragment}, sources, query) do
    expr(fragment, sources, query)
  end

  defp order_by(%{order_bys: []}, _sources), do: []
  defp order_by(%{order_bys: order_bys} = query, sources) do
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
      :asc_nulls_last -> [str | " ASC NULLS LAST"]
      :asc_nulls_first -> [str | " ASC NULLS FIRST"]
      :desc -> [str | " DESC"]
      :desc_nulls_last -> [str | " DESC NULLS LAST"]
      :desc_nulls_first -> [str | " DESC NULLS FIRST"]
    end
  end

  defp limit(%{limit: nil}, _sources), do: []
  defp limit(%{limit: %{expr: expr}} = query, sources) do
    [" FETCH NEXT ", expr(expr, sources, query), " ROWS ONLY"]
  end
  
  defp offset(%{offset: nil}, _sources), do: []
  defp offset(%{offset: %{expr: expr}} = query, sources) do
    [" OFFSET ", expr(expr, sources, query), " ROWS"]
  end

  defp combinations(%{combinations: combinations}) do
    Enum.map(combinations, fn
      {:union, query} -> [" UNION (", all(query), ")"]
      {:union_all, query} -> [" UNION ALL (", all(query), ")"]
      {:except, query} -> [" MINUS (", all(query), ")"]
      {:intersect, query} -> [" INTERSECT (", all(query), ")"]
    end)
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

  defp parens_for_select([first_expr | _] = expr) do
    if is_binary(first_expr) and String.starts_with?(first_expr, ["SELECT", "select"]) do
      [?(, expr, ?)]
    else
      expr
    end
  end

  defp paren_expr(expr, sources, query) do
    [?(, expr(expr, sources, query), ?)]
  end

  defp expr({:^, [], [ix]}, _sources, _query) do
    [?: | Integer.to_string(ix + 1)]
  end

  defp expr({{:., _, [{:parent_as, _, [as]}, field]}, _, []}, _sources, query)
       when is_atom(field) do
    {ix, sources} = get_parent_sources_ix(query, as)
    quote_qualified_name(field, sources, ix)
  end

  defp expr({{:., _, [{:&, _, [idx]}, field]}, _, []}, sources, _query) when is_atom(field) do
    quote_qualified_name(field, sources, idx)
  end

  defp expr({:&, _, [idx]}, sources, _query) do
    {_, source, _} = elem(sources, idx)
    source
  end

  defp expr({:in, _, [_left, []]}, _sources, _query) do
    "0"
  end

  defp expr({:in, _, [left, right]}, sources, query) when is_list(right) do
    args =
      intersperse_map(right, ?,, fn
        elem when is_list(elem) -> [?(, intersperse_map(elem, ?,, &expr(&1, sources, query)), ?)]
        elem -> expr(elem, sources, query)
      end)
    [expr(left, sources, query), " IN (", args, ?)]
  end

  defp expr({:in, _, [left, {:^, _, [_, length]}]}, sources, query) do
    right = for ix <- 1..length, do: {:^, [], [ix]}
    expr({:in, [], [left, right]}, sources, query)
  end

  defp expr({:in, _, [left, %Ecto.SubQuery{} = subquery]}, sources, query) do
    [expr(left, sources, query), " IN ", expr(subquery, sources, query)]
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

  defp expr(%Ecto.SubQuery{query: query}, sources, parent_query) do
    query = put_in(query.aliases[@parent_as], {parent_query, sources})
    [?(, all(query, subquery_as_prefix(sources)), ?)]
  end

  defp expr({:fragment, _, [kw]}, _sources, query) when is_list(kw) or tuple_size(kw) == 3 do
    error!(query, "keyword or interpolated fragments are not supported")
  end

  defp expr({:fragment, _, parts}, sources, query) do
    Enum.map(parts, fn
      {:raw, part}  -> part
      {:expr, expr} -> expr(expr, sources, query)
    end)
    |> parens_for_select
  end

  defp expr({:literal, _, [literal]}, _sources, _query) do
    quote_name(literal)
  end

  defp expr({:date_add, _, [date, count, interval]}, sources, query) do
    interval(date, " + ", count, interval, sources, query)
  end

  defp expr({:datetime_add, _, [datetime, count, interval]}, sources, query) do
    interval(datetime, " + ", count, interval, sources, query)
  end

  defp expr({:from_now, _, [count, interval]}, sources, query) do
    interval(DateTime.utc_now, " + ", count, interval, sources, query)
  end

  defp expr({:ago, _, [count, interval]}, sources, query) do
    interval(DateTime.utc_now, " - ", count, interval, sources, query)
  end

  defp expr({:filter, _, _}, _sources, query) do
    error!(query, "aggregate filters are not supported")
  end

  defp expr({:over, _, [agg, name]}, sources, query) when is_atom(name) do
    aggregate = expr(agg, sources, query)
    [aggregate, " OVER "]
  end

  defp expr({:over, _, [agg, kw]}, sources, query) do
    aggregate = expr(agg, sources, query)
    [aggregate, " OVER ", window_exprs(kw, sources, query)]
  end

  defp expr({:{}, _, elems}, sources, query) do
    [?(, intersperse_map(elems, ?,, &expr(&1, sources, query)), ?)]
  end

  defp expr({:count, _, []}, _sources, _query), do: "count(*)"

  defp expr({fun, _, args}, sources, query) when is_atom(fun) and is_list(args) do
    {modifier, args} =
      case args do
        [rest, :distinct] -> {"DISTINCT ", [rest]}
        _ -> {[], args}
      end

    case handle_call(fun, length(args)) do
      {:binary_op, op} ->
        [left, right] = args
        [maybe_paren(left, sources, query), op | maybe_paren(right, sources, query)]
      {:fun, fun} ->
        [fun, ?(, modifier, intersperse_map(args, ", ", &expr(&1, sources, query)), ?)]
    end
  end

  defp expr(%Ecto.Query.Tagged{value: {:^, [], [ix]}, type: :binary}, _sources, _query) do
    [?: | Integer.to_string(ix + 1)]
  end
  defp expr(%Ecto.Query.Tagged{value: binary, type: :binary}, _sources, _query) do
    ["'", Base.encode16(binary, case: :upper), "'"]
  end
  defp expr(%Ecto.Query.Tagged{value: literal, type: type}, sources, query)
    when type in ~w(binary_id uuid)a  do
    ["HEXTORAW(", expr(literal, sources, query), ?)]
  end
  defp expr(%Ecto.Query.Tagged{value: literal, type: type}, sources, query) do
    ["CAST(", expr(literal, sources, query), " AS ", column_type(type, []), ?)]
  end

  defp expr(nil, _sources, _query),   do: "NULL"
  defp expr(true, _sources, _query),  do: "1"
  defp expr(false, _sources, _query), do: "0"

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

  defp maybe_paren({op, _, [_, _]} = expr, sources, query) when op in @binary_ops,
    do: paren_expr(expr, sources, query)

  defp maybe_paren({:is_nil, _, [_]} = expr, sources, query),
    do: paren_expr(expr, sources, query)

  defp maybe_paren(expr, sources, query),
    do: expr(expr, sources, query)

  defp returning([]),
    do: []
  defp returning(fields) do
    returning = fields |> Enum.filter(& is_tuple(&1) == false)
    [" RETURN ", intersperse_map(returning, ", ", &quote_name/1),
     " INTO ", intersperse_map(returning, ", ", &[?: | quote_name(&1)])]
  end   

  defp create_names(%{sources: sources}, as_prefix) do
    create_names(sources, 0, tuple_size(sources), as_prefix) |> List.to_tuple()
  end

  defp create_names(sources, pos, limit, as_prefix) when pos < limit do
    [create_name(sources, pos, as_prefix) | create_names(sources, pos + 1, limit, as_prefix)]
  end

  defp create_names(_sources, pos, pos, as_prefix) do
    [as_prefix]
  end

  defp subquery_as_prefix(sources) do
    [?s | :erlang.element(tuple_size(sources), sources)]
  end

  defp create_name(sources, pos, as_prefix) do
    case elem(sources, pos) do
      {:fragment, _, _} ->
        {nil, as_prefix ++ [?f | Integer.to_string(pos)], nil}

      {table, schema, prefix} ->
        name = as_prefix ++ [create_alias(table) | Integer.to_string(pos)]
        {quote_table(prefix, table), name, schema}

      %Ecto.SubQuery{} ->
        {nil, as_prefix ++ [?s | Integer.to_string(pos)], nil}
    end
  end

  defp create_alias(<<first, _rest::binary>>) when first in ?a..?z when first in ?A..?Z do
    <<first>>
  end
  defp create_alias(_) do
    "t"
  end

  # DDL

  alias Ecto.Migration.{Table, Index, Reference, Constraint}

  def execute_ddl({command, %Table{} = table, columns}) when command in [:create, :create_if_not_exists] do
    table_name = quote_table(table.prefix, table.name)
    [[if_do(command == :create_if_not_exists, :begin),
      "CREATE TABLE ", table_name, ?\s,
      ?(, column_definitions(table, columns), pk_definition(table, columns, ", "), ?),
      options_expr(table.options),
      if_do(command == :create_if_not_exists, :end)]]
  end

  def execute_ddl({command, %Table{} = table}) when command in [:drop, :drop_if_exists] do
    [[if_do(command == :drop_if_exists, :begin),
      "DROP TABLE ", quote_table(table.prefix, table.name),
      if_do(command == :drop_if_exists, :end)]]
  end

  def execute_ddl({:alter, %Table{} = table, changes}) do
    table_name = quote_table(table.prefix, table.name)
    if_do = length(changes) > 1
    query =
      for change <- changes,
        do: if_do(if_do, :execute, [["ALTER TABLE ", table_name, ?\s], column_change(table, change)])

    [[if_do(if_do, :begin, []), query, if_do(if_do, :end, [])]]
  end

  def execute_ddl({command, %Index{} = index}) when command in [:create, :create_if_not_exists] do
    [[if_do(command == :create_if_not_exists, :begin),
      "CREATE", if_do(index.unique, " UNIQUE"), " INDEX ", quote_name(index.name),
      " ON ", quote_table(index.prefix, index.table), ?\s,
      ?(, intersperse_map(index.columns, ", ", &index_expr/1), ?),
      if_do(index.concurrently, " ONLINE"), options_expr(index.options),
      if_do(command == :create_if_not_exists, :end)]]
  end

  def execute_ddl({command, %Index{} = index}) when command in [:drop, :drop_if_exists] do
    [[if_do(command == :drop_if_exists, :begin),
      "DROP INDEX ", quote_table(index.prefix, index.name),
      if_do(command == :drop_if_exists, :end)]]
  end

  def execute_ddl({:rename, %Table{} = current_table, %Table{} = new_table}) do
    [["RENAME ", quote_table(nil, current_table.name), " TO ", quote_table(nil, new_table.name)]]
  end

  def execute_ddl({:rename, %Table{} = table, current_column, new_column}) do
    [["ALTER TABLE ", quote_table(table.prefix, table.name), " RENAME COLUMN ",
      quote_name(current_column), " TO ", quote_name(new_column)]]
  end

  def execute_ddl({:rename, %Index{} = current_index, new_name}) do
    [["ALTER INDEX ", quote_name(current_index.name), " RENAME TO ", quote_name(new_name)]]
  end

  def execute_ddl({command, %Constraint{} = constraint}) when command in [:create, :create_if_not_exists] do
    [[if_do(command == :create_if_not_exists, :begin),
      "ALTER TABLE ", quote_table(constraint.prefix, constraint.table),
      " ADD CONSTRAINT ", quote_name(constraint.name), constraint_expr(constraint),
      if_do(command == :create_if_not_exists, :end)]]
  end

  def execute_ddl({command, %Constraint{} = constraint}) when command in [:drop, :drop_if_exists] do
    [[if_do(command == :drop_if_exists, :begin),
      "ALTER TABLE ", quote_table(constraint.prefix, constraint.table),
      " DROP CONSTRAINT ", quote_name(constraint.name),
      if_do(command == :drop_if_exists, :end)]]
  end

  def execute_ddl(string) when is_binary(string), do: [string]

  def execute_ddl(keyword) when is_list(keyword),
    do: error!(nil, "keyword lists in execute are not supported")

  defp pk_definition(table, columns, prefix) do
    constraint_name = quote_name("#{table.name}_pkey")
    pks =
      for {_, name, _, opts} <- columns,
          opts[:primary_key],
          do: name

    case pks do
      [] -> []
      _  -> [prefix, "CONSTRAINT ", constraint_name, ?\s, "PRIMARY KEY (", quote_names(pks), ")"]
    end
  end

  defp reference_expr(%Reference{} = ref, table, name) do
    {current_columns, reference_columns} = Enum.unzip([{name, ref.column}])

    ["CONSTRAINT ", reference_name(ref, table, name), ?\s,
     "FOREIGN KEY (", quote_names(current_columns), ") REFERENCES ",
     quote_table(ref.prefix || table.prefix, ref.table), ?(, quote_names(reference_columns), ?),
     reference_on_delete(ref.on_delete), validate(ref.validate)]
  end

  defp reference_name(%Reference{name: nil}, table, column),
    do: quote_name("#{table.name}_#{column}_fkey")
  defp reference_name(%Reference{name: name}, _table, _column),
    do: quote_name(name)

  defp reference_on_delete(:nilify_all), do: " ON DELETE SET NULL"
  defp reference_on_delete(:delete_all), do: " ON DELETE CASCADE"
  defp reference_on_delete(_), do: []

  defp validate(false), do: " NOVALIDATE"
  defp validate(_), do: []

  defp constraint_expr(%Reference{} = ref, table, name) do
    ["CONSTRAINT ", reference_name(ref, table, name), " REFERENCES ",
     quote_table(ref.prefix || table.prefix, ref.table), ?(, quote_names([ref.column]), ?),
     reference_on_delete(ref.on_delete), validate(ref.validate)]
  end

  defp constraint_expr(%Constraint{check: check}) when is_binary(check), 
    do: [" CHECK ", ?(, check, ?)]
  defp constraint_expr(_),
    do: []

  defp index_expr(literal) when is_binary(literal),
    do: literal
  defp index_expr(literal),
    do: quote_name(literal)

  defp options_expr(nil),
    do: []
  defp options_expr(options),
    do: [?\s, options]

  defp column_definitions(table, columns) do
    intersperse_map(columns, ", ", &column_definition(table, &1))
  end

  defp column_definition(table, {:add, name, %Reference{} = ref, opts}) do
    [column_source(name, opts), ?\s, column_type(ref.type, opts),
     column_options(ref.type, opts), ", ", reference_expr(ref, table, name)]
  end

  defp column_definition(_table, {:add, name, type, opts}) do
    [column_source(name, opts), ?\s, column_type(type, opts),
    column_options(type, opts)]
  end

  defp column_change(table, {:add, name, %Reference{} = ref, opts}) do
    ["ADD ", column_source(name, opts), ?\s, column_type(ref.type, opts),
    column_options(ref.type, opts), ?\s, constraint_expr(ref, table, name)]
  end

  defp column_change(_table, {:add, name, type, opts}) do
    ["ADD ", column_source(name, opts), ?\s, column_type(type, opts),
    column_options(type, opts)]
  end

  defp column_change(_table, {:modify, name, type, opts}) do
    ["MODIFY ", ?(, column_source(name, opts), ?\s, column_type(type, opts),
     column_options(type, opts), ?)]
  end

  defp column_change(_table, {:remove, name}),
    do: ["DROP COLUMN ", quote_name(name)]
  defp column_change(_table, {:remove, name, _type, opts}),
    do: ["DROP COLUMN ", column_source(name, opts)]

  defp column_options(type, opts) do
    default = Keyword.fetch(opts, :default)
    null    = Keyword.get(opts, :null)

    [default_expr(default, type), null_expr(null)]
  end

  defp column_source(name, opts) do
    case Keyword.fetch(opts, :source) do
      {:ok, source} -> quote_name(source)
      :error -> quote_name(name)
    end
  end

  defp null_expr(false), do: " NOT NULL"
  defp null_expr(true), do: " NULL"
  defp null_expr(_), do: []

  defp default_expr({:ok, nil}, _type),    do: " DEFAULT NULL"
  defp default_expr({:ok, literal}, type), do: [" DEFAULT ", default_type(literal, type)]
  defp default_expr(:error, _),            do: []

  defp default_type(true, _type),  do: [?', "1", ?']
  defp default_type(false, _type),  do: [?', "0", ?']
  defp default_type(literal, _type) when is_binary(literal), do: [?', escape_string(literal), ?']
  defp default_type(literal, _type) when is_number(literal),do: to_string(literal)
  defp default_type({:fragment, expr}, _type), do: [expr]
  defp default_type(expr, type),
    do: error!(nil, "unknown default `#{inspect expr}` for type `#{inspect type}`")

  defp column_type(type, _opts) when type in ~w(utc_datetime naive_datetime)a do
    type_name = [ecto_to_db(type), "(0)"]

    cond do
      type == :utc_datetime -> [type_name, " with time zone"]
      true                  -> type_name
    end
  end

  defp column_type(type, opts) when type in ~w(utc_datetime_usec naive_datetime_usec)a do
    precision = Keyword.get(opts, :precision)
    type_name = [ecto_to_db(type), if_do(precision, [?(, to_string(precision), ?)])]

    cond do
      type == :utc_datetime_usec -> [type_name, " with time zone"]
      true                       -> type_name
    end
  end

  defp column_type(type, opts) do
    size      = Keyword.get(opts, :size)
    precision = Keyword.get(opts, :precision)
    scale     = Keyword.get(opts, :scale)
    national  = Keyword.get(opts, :national, false)
    type_name = [if_do(national and type in [:string, :binary], "n"), ecto_to_db(type)]

    cond do
      size               -> [type_name, ?(, to_string(size), ?)]
      precision          -> [type_name, ?(, to_string(precision), ?,, to_string(scale || 0), ?)]
      type == :boolean   -> [type_name, "(1)"]
      type == :binary    -> [type_name, "(2000)"]
      type == :string    -> [type_name, "(2000)"]
      true               -> type_name
    end
  end

  defp ecto_to_db(:id),                  do: "integer"
  defp ecto_to_db(:serial),              do: "int"
  defp ecto_to_db(:bigserial),           do: "int"
  defp ecto_to_db(:identity),            do: "number generated by default as identity"
  defp ecto_to_db(:float),               do: "number"
  defp ecto_to_db(:boolean),             do: "char"
  defp ecto_to_db(:binary),              do: "raw"
  defp ecto_to_db(:binary_id),           do: "raw(16)"
  defp ecto_to_db(:uuid),                do: "raw(16)"
  defp ecto_to_db({:map, _}),            do: "json"
  defp ecto_to_db(:map),                 do: "json"
  defp ecto_to_db(:string),              do: "varchar2"
  defp ecto_to_db(:time),                do: "date"
  defp ecto_to_db(:time_usec),           do: "date"
  defp ecto_to_db(:naive_datetime),      do: "timestamp"
  defp ecto_to_db(:naive_datetime_usec), do: "timestamp"
  defp ecto_to_db(:utc_datetime),        do: "timestamp"
  defp ecto_to_db(:utc_datetime_usec),   do: "timestamp"
  defp ecto_to_db(atom) when is_atom(atom),
    do: Atom.to_string(atom)
  defp ecto_to_db(type),
    do: error!(nil, "unsupported type `#{inspect(type)}`")

  defp if_do(condition, :begin) do
    if condition, do: "BEGIN EXECUTE IMMEDIATE '", else: []
  end
  defp if_do(condition, :end) do
    if condition, do: "'; EXCEPTION WHEN OTHERS THEN NULL; END;", else: []
  end
  defp if_do(condition, value) do
    if condition, do: value, else: []
  end

  defp if_do(condition, :begin, expr) do
    if condition, do: ["BEGIN", expr], else: expr
  end
  defp if_do(condition, :end, expr) do
    if condition, do: [expr, " END;"], else: expr
  end
  defp if_do(condition, :execute, expr) do
    if condition, do: [" EXECUTE IMMEDIATE '", expr, "';"], else: expr
  end

  ## Helpers

  defp get_source(query, sources, ix, source) do
    {expr, name, _schema} = elem(sources, ix)
    {expr || paren_expr(source, sources, query), name}
  end

  defp get_parent_sources_ix(query, as) do
    case query.aliases[@parent_as] do
      {%{aliases: %{^as => ix}}, sources} -> {ix, sources}
      {%{} = parent, _sources} -> get_parent_sources_ix(parent, as)
    end
  end

  defp quote_qualified_name(name, sources, ix) do
    {_, source, _} = elem(sources, ix)
    [source, ?. | quote_name(name)]
  end

  defp quote_names(names) do
    intersperse_map(names, ?,, &quote_name/1)
  end

  defp quote_name(name) when is_atom(name) do
    quote_name(Atom.to_string(name))
  end
  defp quote_name(name) do
    [name]
  end

  defp quote_table(nil, name),    do: quote_table(name)
  defp quote_table(prefix, name), do: [quote_table(prefix), ?., quote_table(name)]

  defp quote_table(name) when is_atom(name),
    do: quote_table(Atom.to_string(name))
  defp quote_table(name) do
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

defimpl String.Chars, for: Jamdb.Oracle.Query do
  def to_string(%Jamdb.Oracle.Query{statement: statement}) do
    IO.iodata_to_binary(statement)
  end
end
