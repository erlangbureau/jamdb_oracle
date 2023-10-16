defmodule Jamdb.Oracle.SQL do
  @moduledoc """
  Adapter module for Oracle. `Ecto.Adapters.SQL.Connection` callbacks implementation.

  """

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

  def execute_ddl({command, %Table{} = table, _}) when command in [:drop, :drop_if_exists] do
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

  def execute_ddl({command, %Index{} = index, _}) when command in [:drop, :drop_if_exists] do
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

  def execute_ddl({command, %Constraint{} = constraint, _}) when command in [:drop, :drop_if_exists] do
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
    type_name = [if_do(national and type in [:string, :binary], "n"), ecto_to_db(strip_type(type))]

    cond do
      size               -> [type_name, ?(, to_string(size), ?)]
      precision          -> [type_name, ?(, to_string(precision), ?,, to_string(scale || 0), ?)]
      type == :boolean   -> [type_name, "(1)"]
      type == :binary    -> [type_name, "(2000)"]
      type == :string    -> [type_name, "(2000)"]
      true               -> type_name
    end
  end

  defp strip_type(type) when is_atom(type) do
    Atom.to_string(type)
    |> String.replace_prefix("small", "")
    |> String.replace_prefix("big", "")
    |> String.replace("int unsigned", "int")
    |> String.to_atom
  end
  defp strip_type(type) do
    type
  end

  defp ecto_to_db(:id),                  do: "integer"
  defp ecto_to_db(:serial),              do: "int"
  defp ecto_to_db(:identity),            do: "integer generated by default as identity"
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

  @doc false
  def table_exists_query(table) do
    {"SELECT count(*) FROM user_tables WHERE table_name = :1 ", [table]}
  end

  @doc false
  def ddl_logs(_result), do: []

  defp match_or_nil(regex, s, f) do
    case Regex.run(regex, s) do
      [_, m] -> f.(m)
      nil -> nil
    end
  end

  defp unique_constraint?(err) do
    match_or_nil(~r/'ORA-00001: unique constraint \((.*)\) violated\\n'/, err.message, fn name ->
      [unique: name]
    end)
  end

  defp integrity_child_constraint?(err) do
    match_or_nil(
      ~r/'ORA-02292: integrity constraint \((.*)\) violated - child record found\\n'/,
      err.message,
      fn name -> [foreign_key: name] end
    )
  end

  defp integrity_parent_constraint?(err) do
    match_or_nil(
      ~r/'ORA-02291: integrity constraint \((.*)\) violated - parent key not found\\n'/,
      err.message,
      fn name -> [foreign_key: name] end
    )
  end

  defp check_constraint?(err) do
    match_or_nil(~r/'ORA-02290: check constraint \((.*)\) violated\\n'/, err.message, fn name ->
      [check: name]
    end)
  end

  @doc false
  def to_constraints(err, _opts) do
    # Note: afaik there are no 'exclusion constraints' in Oracle.
    unique_constraint?(err) ||
      integrity_child_constraint?(err) ||
      integrity_parent_constraint?(err) ||
      check_constraint?(err) ||
      []
  end

  @doc false
  def to_db_type(type) do
    column_type(type, [])
  end

  ## Helpers

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
