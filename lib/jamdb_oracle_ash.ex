defmodule AshJamdbOracle.Repo do
  @moduledoc false

  defmacro __using__(opts) do
    quote bind_quoted: [opts: opts] do
      otp_app = opts[:otp_app] || raise("Must configure OTP app")

      use Ecto.Repo,
        adapter: Ecto.Adapters.Jamdb.Oracle,
        otp_app: otp_app

      @behaviour AshJamdbOracle.Repo

      def init(_, config) do
        {:ok, config}
      end

      defoverridable init: 2
    end
  end
end

defmodule AshJamdbOracle.Statement do
  @moduledoc false

  @fields [
    :name,
    :up,
    :down,
    :code?
  ]

  defstruct @fields ++ [:__spark_metadata__]

  def fields, do: @fields

  @schema [
    name: [
      type: :atom,
      required: true,
      doc: """
      The name of the statement, must be unique within the resource
      """
    ],
    code?: [
      type: :boolean,
      default: false,
      doc: """
      By default, we place the strings inside of ecto migration's `execute/1` function and assume they are Oracle SQL. Use this option if you want to provide custom Elixir code to be placed directly in the migrations.
      """
    ],
    up: [
      type: :string,
      doc: """
      How to create the structure of the statement (Oracle SQL)
      """,
      required: true
    ],
    down: [
      type: :string,
      doc: "How to tear down the structure of the statement (Oracle SQL)",
      required: true
    ]
  ]

  def schema, do: @schema
end

defmodule AshJamdbOracle.DataLayer do
  @moduledoc false

  @behaviour Ash.DataLayer

  require Ecto.Query

  @impl true
  def prefer_transaction?(_resource), do: true

  @impl true
  def prefer_transaction_for_atomic_updates?(_resource), do: true

  @impl true
  def can?(_, _), do: false

  @impl true
  def in_transaction?(_resource), do: false

  @impl true
  def limit(query, nil, _), do: {:ok, query}
  def limit(query, limit, _resource), do: {:ok, Ecto.Query.from(row in query, limit: ^limit)}

  @impl true
  def source(resource), do: resource.__schema__(:source) || ""

  @impl true
  def set_context(resource, data_layer_query, context) do
    AshSql.Query.set_context(resource, data_layer_query, AshJamdbOracle.SqlImplementation, context)
  end

  @impl true
  def offset(query, nil, _), do: query
  def offset(%{offset: old_offset} = query, 0, _resource) when old_offset in [0, nil], do: {:ok, query}
  def offset(query, offset, _resource), do: {:ok, Ecto.Query.from(row in query, offset: ^offset)}

  @impl true
  def return_query(query, resource) do
    query
    |> AshSql.Bindings.default_bindings(resource, AshJamdbOracle.SqlImplementation)
    |> AshSql.Query.return_query(resource)
  end

  @impl true
  def run_query(query, resource) do
    query = AshSql.Bindings.default_bindings(query, resource, AshJamdbOracle.SqlImplementation)
    repo = AshSql.dynamic_repo(resource, AshJamdbOracle.SqlImplementation, query)
    {:ok, repo.all(query)}
  end

  @impl true
  def functions(_resource) do
    [AshJamdbOracle.Functions.Binding, AshJamdbOracle.Functions.Like]
  end

  @impl true
  def combination_acc(query), do: AshSql.Query.combination_acc(query)

  @impl true
  def run_aggregate_query(original_query, aggregates, resource) do
    AshSql.AggregateQuery.run_aggregate_query(
      original_query,
      aggregates,
      resource,
      AshJamdbOracle.SqlImplementation
    )
  end

  @impl true
  def set_tenant(_resource, query, _tenant), do: {:ok, query}

  @impl true
  def resource_to_query(resource, domain) do
    AshSql.Query.resource_to_query(resource, AshJamdbOracle.SqlImplementation, domain)
  end

  @impl true
  def combination_of(combination_of, resource, domain) do
    AshSql.Query.combination_of(combination_of, resource, domain, AshJamdbOracle.SqlImplementation)
  end

  @impl true
  def update_query(_query, _changeset, _resource, _options), do: {:error, :not_implemented}

  @impl true
  def destroy_query(_query, _changeset, _resource, _options), do: {:error, :not_implemented}

  @impl true
  def calculate(_resource, _expressions, _context), do: {:error, :not_implemented}

  @impl true
  def bulk_create(_resource, _stream, _options), do: {:error, :not_implemented}
end

defmodule AshJamdbOracle.Functions.Binding do
  @moduledoc false

  use Ash.Query.Function, name: :binding

  def args, do: [[]]
end

defmodule AshJamdbOracle.Functions.Like do
  @moduledoc false

  use Ash.Query.Function, name: :like, predicate?: true

  def args, do: [[:string, :string]]
end

defmodule AshJamdbOracle.SqlImplementation do
  @moduledoc false

  use AshSql.Implementation

  require Ecto.Query

  @impl true
  def manual_relationship_function, do: :ash_oracle_join

  @impl true
  def manual_relationship_subquery_function, do: :ash_oracle_subquery

  @impl true
  def require_ash_functions_for_or_and_and?, do: true

  @impl true
  def require_extension_for_citext, do: false

  @impl true
  def storage_type(_resource, _field) do
    # Implement Oracle-specific storage type logic here
    nil
  end

  @impl true
  def expr(_query, [], _bindings, _embedded?, acc, type) when type in [:map, :jsonb] do
    # Oracle does not have native JSONB, use CLOB or VARCHAR2 as needed
    {:ok, Ecto.Query.dynamic(fragment("empty_clob()")), acc}
  end

  def expr(
        _query,
        %Ash.Query.UpsertConflict{attribute: attribute},
        _bindings,
        _embedded?,
        acc,
        _type
      ) do
    # Oracle upsert conflict handling (MERGE statement)
    {:ok, Ecto.Query.dynamic(fragment(":attribute = ?", ^attribute)), acc}
  end

  def expr(query, %AshJamdbOracle.Functions.Binding{}, _bindings, _embedded?, acc, _type) do
    binding =
      AshSql.Bindings.get_binding(
        query.__ash_bindings__.resource,
        [],
        query,
        [:left, :inner, :root]
      )

    if is_nil(binding) do
      raise "Error while constructing explicit `binding()` reference."
    end

    {:ok, Ecto.Query.dynamic([{^binding, row}], row), acc}
  end

  def expr(
        query,
        %like{arguments: [arg1, arg2], embedded?: pred_embedded?},
        bindings,
        embedded?,
        acc,
        type
      )
      when like == AshJamdbOracle.Functions.Like do
    {arg1, acc} =
      AshSql.Expr.dynamic_expr(query, arg1, bindings, pred_embedded? || embedded?, :string, acc)

    {arg2, acc} =
      AshSql.Expr.dynamic_expr(query, arg2, bindings, pred_embedded? || embedded?, :string, acc)

    inner_dyn =
      Ecto.Query.dynamic(fragment("LOWER(?) LIKE LOWER(?)", ^arg1, ^arg2))

    if type != Ash.Type.Boolean do
      {:ok, inner_dyn, acc}
    else
      {:ok, Ecto.Query.dynamic(type(^inner_dyn, ^type)), acc}
    end
  end

  def expr(
        _query,
        _expr,
        _bindings,
        _embedded?,
        _acc,
        _type
      ) do
    :error
  end

  @impl true
  def table(resource) do
    # Implement Oracle-specific table name logic here
    resource.__schema__(:source)
  end

  @impl true
  def schema(_resource) do
    # Implement Oracle-specific schema logic here
    nil
  end

  @impl true
  def repo(_resource, _kind) do
    # Implement Oracle-specific repo logic here
    Application.get_env(:jamdb_oracle, :repo)
  end

  @impl true
  def simple_join_first_aggregates(_resource) do
    []
  end

  @impl true
  def list_aggregate(_resource) do
    # Oracle equivalent for array_agg is LISTAGG or COLLECT
    "COLLECT"
  end

  @impl true
  def parameterized_type(type, _constraints) do
    # Implement Oracle-specific parameterized type logic here
    type
  end

  @impl true
  def determine_types(mod, args, returns \\ nil) do
    {types, new_returns} = Ash.Expr.determine_types(mod, args, returns)
    {types, new_returns || returns}
  end
end

defmodule AshJamdbOracle.DataLayer do
  @moduledoc false

  @behaviour Ash.DataLayer

  require Ecto.Query

  @impl true
  def prefer_transaction?(_resource), do: true

  @impl true
  def prefer_transaction_for_atomic_updates?(_resource), do: true

  @impl true
  def can?(_, _), do: false

  @impl true
  def in_transaction?(_resource), do: false

  @impl true
  def limit(query, nil, _), do: {:ok, query}
  def limit(query, limit, _resource), do: {:ok, Ecto.Query.from(row in query, limit: ^limit)}

  @impl true
  def source(resource), do: resource.__schema__(:source) || ""

  @impl true
  def set_context(resource, data_layer_query, context) do
    AshSql.Query.set_context(resource, data_layer_query, AshJamdbOracle.SqlImplementation, context)
  end

  @impl true
  def offset(query, nil, _), do: query
  def offset(%{offset: old_offset} = query, 0, _resource) when old_offset in [0, nil], do: {:ok, query}
  def offset(query, offset, _resource), do: {:ok, Ecto.Query.from(row in query, offset: ^offset)}

  @impl true
  def return_query(query, resource) do
    query
    |> AshSql.Bindings.default_bindings(resource, AshJamdbOracle.SqlImplementation)
    |> AshSql.Query.return_query(resource)
  end

  @impl true
  def run_query(query, resource) do
    query = AshSql.Bindings.default_bindings(query, resource, AshJamdbOracle.SqlImplementation)
    repo = AshSql.dynamic_repo(resource, AshJamdbOracle.SqlImplementation, query)
    {:ok, repo.all(query)}
  end

  @impl true
  def functions(_resource) do
    [AshJamdbOracle.Functions.Binding, AshJamdbOracle.Functions.Like]
  end

  @impl true
  def combination_acc(query), do: AshSql.Query.combination_acc(query)

  @impl true
  def run_aggregate_query(original_query, aggregates, resource) do
    AshSql.AggregateQuery.run_aggregate_query(
      original_query,
      aggregates,
      resource,
      AshJamdbOracle.SqlImplementation
    )
  end

  @impl true
  def set_tenant(_resource, query, _tenant), do: {:ok, query}

  @impl true
  def resource_to_query(resource, domain) do
    AshSql.Query.resource_to_query(resource, AshJamdbOracle.SqlImplementation, domain)
  end

  @impl true
  def combination_of(combination_of, resource, domain) do
    AshSql.Query.combination_of(combination_of, resource, domain, AshJamdbOracle.SqlImplementation)
  end

  @impl true
  def update_query(_query, _changeset, _resource, _options), do: {:error, :not_implemented}

  @impl true
  def destroy_query(_query, _changeset, _resource, _options), do: {:error, :not_implemented}

  @impl true
  def calculate(_resource, _expressions, _context), do: {:error, :not_implemented}

  @impl true
  def bulk_create(_resource, _stream, _options), do: {:error, :not_implemented}
end
