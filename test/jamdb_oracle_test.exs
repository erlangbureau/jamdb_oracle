defmodule Jamdb.OracleTest do
  use ExUnit.Case, async: true

  import Ecto.Query

  alias Ecto.Queryable
  alias Ecto.Adapters.Jamdb.Oracle.Connection, as: SQL

  defmodule Schema do
    use Ecto.Schema

    schema "schema" do
      field :x, :integer
      field :y, :integer
      field :z, :integer
      field :w, :decimal

      has_many :comments, Jamdb.OracleTest.Schema2,
        references: :x,
        foreign_key: :z

      has_one :permalink, Jamdb.OracleTest.Schema3,
        references: :y,
        foreign_key: :id
    end
  end

  defmodule Schema2 do
    use Ecto.Schema

    import Ecto.Query

    schema "schema2" do
      belongs_to :post, Jamdb.OracleTest.Schema,
        references: :x,
        foreign_key: :z
    end
  end

  defmodule Schema3 do
    use Ecto.Schema

    import Ecto.Query

    @schema_prefix "foo"
    schema "schema3" do
      field :binary, :binary
    end
  end

  defp plan(query, operation \\ :all) do
    {query, _} = Ecto.Adapter.Queryable.plan_query(operation, Jamdb.Oracle, query)
    query
  end

  defp all(query), do: query |> SQL.all() |> IO.iodata_to_binary()
  defp update_all(query), do: query |> SQL.update_all() |> IO.iodata_to_binary()
  defp delete_all(query), do: query |> SQL.delete_all() |> IO.iodata_to_binary()
  defp execute_ddl(query), do: query |> SQL.execute_ddl() |> Enum.map(&IO.iodata_to_binary/1)

  defp insert(prefx, table, header, rows, on_conflict, returning, placeholders \\ []) do
    IO.iodata_to_binary(
      SQL.insert(prefx, table, header, rows, on_conflict, returning, placeholders)
    )
  end

  defp update(prefx, table, fields, filter, returning) do
    IO.iodata_to_binary(SQL.update(prefx, table, fields, filter, returning))
  end

  defp delete(prefx, table, filter, returning) do
    IO.iodata_to_binary(SQL.delete(prefx, table, filter, returning))
  end

  test "from" do
    query = Schema |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0}
  end

  test "from with hints" do
    query =
      Schema |> from(hints: ["ALL_ROWS"]) |> select([r], r.x) |> plan()

    assert all(query) ==
             ~s{SELECT /*+ ALL_ROWS */ s0.x FROM schema s0}
  end

  test "from with schema prefix" do
    query = Schema3 |> select([r], r.binary) |> plan()
    assert all(query) == ~s{SELECT s0.binary FROM foo.schema3 s0}
  end

  test "from without schema" do
    query = "schema" |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0}

    query = "schema" |> select([r], fragment("?", r)) |> plan()
    assert all(query) == ~s{SELECT s0 FROM schema s0}

    query = "Schema" |> select([:x]) |> plan()
    assert all(query) == ~s{SELECT S0.x FROM Schema S0}

    query = "0odel" |> select([:x]) |> plan()
    assert all(query) == ~s{SELECT t0.x FROM 0odel t0}

    query = from(m in "schema", select: [m]) |> plan()
    assert all(query) == ~s{SELECT s0.* FROM schema s0}
  end

  test "from with subquery" do
    query = subquery("posts" |> select([r], %{x: r.x, y: r.y})) |> select([r], r.x) |> plan()

    assert all(query) ==
             ~s{SELECT s0.x FROM ((SELECT sp0.x x, sp0.y y FROM posts sp0)) s0}

    query = subquery("posts" |> select([r], %{x: r.x, z: r.y})) |> select([r], r) |> plan()

    assert all(query) ==
             ~s{SELECT s0.x, s0.z FROM ((SELECT sp0.x x, sp0.y z FROM posts sp0)) s0}

    query =
      subquery(subquery("posts" |> select([r], %{x: r.x, z: r.y})) |> select([r], r))
      |> select([r], r)
      |> plan()

    assert all(query) ==
             ~s{SELECT s0.x, s0.z FROM ((SELECT ss0.x x, ss0.z z FROM ((SELECT ssp0.x x, ssp0.y z FROM posts ssp0)) ss0)) s0}
  end

  test "join with subquery" do
    posts = subquery("posts" |> where(title: ^"hello") |> select([r], %{x: r.x, y: r.y}))

    query =
      "comments"
      |> join(:inner, [c], p in subquery(posts), on: true)
      |> select([_, p], p.x)
      |> plan()

    assert all(query) ==
             "SELECT s1.x FROM comments c0 " <>
               "INNER JOIN ((SELECT sp0.x x, sp0.y y FROM posts sp0 WHERE (sp0.title = :1))) s1 ON 1 = 1"

    posts = subquery("posts" |> where(title: ^"hello") |> select([r], %{x: r.x, z: r.y}))

    query =
      "comments"
      |> join(:inner, [c], p in subquery(posts), on: true)
      |> select([_, p], p)
      |> plan()

    assert all(query) ==
             "SELECT s1.x, s1.z FROM comments c0 " <>
               "INNER JOIN ((SELECT sp0.x x, sp0.y z FROM posts sp0 WHERE (sp0.title = :1))) s1 ON 1 = 1"

    posts =
      subquery("posts" |> where(title: parent_as(:comment).subtitle) |> select([r], r.title))

    query =
      "comments"
      |> from(as: :comment)
      |> join(:inner, [c], p in subquery(posts))
      |> select([_, p], p)
      |> plan()

    assert all(query) ==
             "SELECT s1.title FROM comments c0 " <>
               "INNER JOIN ((SELECT sp0.title title FROM posts sp0 WHERE (sp0.title = c0.subtitle))) s1 ON 1 = 1"
  end

  test "CTE" do
    initial_query =
      "categories"
      |> where([c], is_nil(c.parent_id))
      |> select([c], %{id: c.id, depth: fragment("1")})

    iteration_query =
      "categories"
      |> join(:inner, [c], t in "tree", on: t.id == c.parent_id)
      |> select([c, t], %{id: c.id, depth: fragment("? + 1", t.depth)})

    cte_query = initial_query |> union_all(^iteration_query)

    query =
      Schema
      |> recursive_ctes(true)
      |> with_cte("tree", as: ^cte_query)
      |> join(:inner, [r], t in "tree", on: t.id == r.category_id)
      |> select([r, t], %{x: r.x, category_id: t.id, depth: type(t.depth, :integer)})
      |> plan()

    assert all(query) ==
             ~s{WITH tree AS (} <>
               ~s{SELECT c0.id id, 1 depth FROM categories c0 WHERE (c0.parent_id IS NULL) } <>
               ~s{UNION ALL } <>
               ~s{(SELECT c0.id, t1.depth + 1 FROM categories c0 } <>
               ~s{INNER JOIN tree t1 ON t1.id = c0.parent_id)) } <>
               ~s{SELECT s0.x, t1.id, CAST(t1.depth AS integer) } <>
               ~s{FROM schema s0 } <>
               ~s{INNER JOIN tree t1 ON t1.id = s0.category_id}
  end

  @raw_sql_cte """
  SELECT * FROM categories WHERE c.parent_id IS NULL
  UNION ALL
  SELECT * FROM categories c, category_tree ct WHERE ct.id = c.parent_id
  """

  test "reference CTE in union" do
    comments_scope_query =
      "comments"
      |> where([c], is_nil(c.deleted_at))
      |> select([c], %{entity_id: c.entity_id, text: c.text})

    posts_query =
      "posts"
      |> join(:inner, [p], c in "comments_scope", on: c.entity_id == p.guid)
      |> select([p, c], [p.title, c.text])

    videos_query =
      "videos"
      |> join(:inner, [v], c in "comments_scope", on: c.entity_id == v.guid)
      |> select([v, c], [v.title, c.text])

    query =
      posts_query
      |> union_all(^videos_query)
      |> with_cte("comments_scope", as: ^comments_scope_query)
      |> plan()

    assert all(query) ==
             ~s{WITH comments_scope AS (} <>
               ~s{SELECT c0.entity_id entity_id, c0.text text } <>
               ~s{FROM comments c0 WHERE (c0.deleted_at IS NULL)) } <>
               ~s{SELECT p0.title, c1.text } <>
               ~s{FROM posts p0 } <>
               ~s{INNER JOIN comments_scope c1 ON c1.entity_id = p0.guid } <>
               ~s{UNION ALL } <>
               ~s{(SELECT v0.title, c1.text } <>
               ~s{FROM videos v0 } <>
               ~s{INNER JOIN comments_scope c1 ON c1.entity_id = v0.guid)}
  end

  test "fragment CTE" do
    query =
      Schema
      |> recursive_ctes(true)
      |> with_cte("tree", as: fragment(@raw_sql_cte))
      |> join(:inner, [p], c in "tree", on: c.id == p.category_id)
      |> select([r], r.x)
      |> plan()

    assert all(query) ==
             ~s{WITH tree AS (#{@raw_sql_cte}) } <>
               ~s{SELECT s0.x } <>
               ~s{FROM schema s0 } <>
               ~s{INNER JOIN tree t1 ON t1.id = s0.category_id}
  end

  test "select" do
    query = Schema |> select([r], {r.x, r.y}) |> plan()
    assert all(query) == ~s{SELECT s0.x, s0.y FROM schema s0}

    query = Schema |> select([r], struct(r, [:x, :y])) |> plan()
    assert all(query) == ~s{SELECT s0.x, s0.y FROM schema s0}
  end

  test "aggregates" do
    query = Schema |> select([r], count(r.x)) |> plan()
    assert all(query) == ~s{SELECT count(s0.x) FROM schema s0}

    query = Schema |> select([r], count(r.x, :distinct)) |> plan()
    assert all(query) == ~s{SELECT count(DISTINCT s0.x) FROM schema s0}

    query = Schema |> select([r], count()) |> plan()
    assert all(query) == ~s{SELECT count(*) FROM schema s0}
  end

  test "distinct" do
    query = Schema |> distinct([r], true) |> select([r], {r.x, r.y}) |> plan()
    assert all(query) == ~s{SELECT DISTINCT s0.x, s0.y FROM schema s0}

    query = Schema |> distinct([r], false) |> select([r], {r.x, r.y}) |> plan()
    assert all(query) == ~s{SELECT s0.x, s0.y FROM schema s0}

    query = Schema |> distinct(true) |> select([r], {r.x, r.y}) |> plan()
    assert all(query) == ~s{SELECT DISTINCT s0.x, s0.y FROM schema s0}

    query = Schema |> distinct(false) |> select([r], {r.x, r.y}) |> plan()
    assert all(query) == ~s{SELECT s0.x, s0.y FROM schema s0}

    query = Schema |> distinct([r], [r.x, r.y]) |> select([r], {r.x, r.y}) |> plan()
    assert all(query) == ~s{SELECT DISTINCT s0.x, s0.y FROM schema s0}
  end

  test "distinct with order by" do
    query = Schema |> order_by([r], desc: r.x) |> distinct([r], desc: r.x) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT DISTINCT s0.x FROM schema s0 ORDER BY s0.x DESC}

    query = Schema |> order_by([r], desc: r.y)  |> distinct([r], [r.x, r.y]) |> select([r], {r.x, r.y}) |> plan()
    assert all(query) == ~s{SELECT DISTINCT s0.x, s0.y FROM schema s0 ORDER BY s0.y DESC}
  end

  test "coalesce" do
    query = Schema |> select([s], coalesce(s.x, 5)) |> plan()
    assert all(query) == ~s{SELECT coalesce(s0.x, 5) FROM schema s0}
  end

  test "select with operation" do
    query = Schema |> select([r], r.x * 2) |> plan()
    assert all(query) == ~s{SELECT s0.x * 2 FROM schema s0}

    query = Schema |> select([r], r.x / 2) |> plan()
    assert all(query) == ~s{SELECT s0.x / 2 FROM schema s0}

    query = Schema |> select([r], r.x + 2) |> plan()
    assert all(query) == ~s{SELECT s0.x + 2 FROM schema s0}

    query = Schema |> select([r], r.x - 2) |> plan()
    assert all(query) == ~s{SELECT s0.x - 2 FROM schema s0}
  end

  test "where" do
    query = Schema |> where([r], r.x == 42) |> where([r], r.y != 43) |> select([r], r.x) |> plan()

    assert all(query) ==
             ~s{SELECT s0.x FROM schema s0 WHERE (s0.x = 42) AND (s0.y != 43)}
  end

  test "or_where" do
    query = Schema |> or_where([r], r.x == 42) |> or_where([r], r.y != 43) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 WHERE (s0.x = 42) OR (s0.y != 43)}

    query = Schema |> or_where([r], r.x == 42) |> or_where([r], r.y != 43) |> where([r], r.z == 44) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 WHERE ((s0.x = 42) OR (s0.y != 43)) AND (s0.z = 44)}
  end

  test "order by" do
    query = Schema |> order_by([r], r.x) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 ORDER BY s0.x}

    query = Schema |> order_by([r], [r.x, r.y]) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 ORDER BY s0.x, s0.y}

    query = Schema |> order_by([r], asc: r.x, desc: r.y) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 ORDER BY s0.x, s0.y DESC}

    query = Schema |> order_by([r], [asc_nulls_first: r.x, desc_nulls_first: r.y]) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 ORDER BY s0.x ASC NULLS FIRST, s0.y DESC NULLS FIRST}

    query = Schema |> order_by([r], [asc_nulls_last: r.x, desc_nulls_last: r.y]) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 ORDER BY s0.x ASC NULLS LAST, s0.y DESC NULLS LAST}

    query = Schema |> order_by([r], []) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0}
  end

  test "union and union all" do
    base_query =
      Schema |> select([r], r.x) |> order_by(fragment("rand")) |> offset(10) |> limit(5)

    union_query1 = Schema |> select([r], r.y) |> order_by([r], r.y) |> offset(20) |> limit(40)
    union_query2 = Schema |> select([r], r.z) |> order_by([r], r.z) |> offset(30) |> limit(60)

    query = base_query |> union(^union_query1) |> union(^union_query2) |> plan()

    assert all(query) ==
             ~s{SELECT s0.x FROM schema s0 } <>
               ~s{UNION (SELECT s0.y FROM schema s0 ORDER BY s0.y OFFSET 20 ROWS FETCH NEXT 40 ROWS ONLY) } <>
               ~s{UNION (SELECT s0.z FROM schema s0 ORDER BY s0.z OFFSET 30 ROWS FETCH NEXT 60 ROWS ONLY) } <>
               ~s{ORDER BY rand OFFSET 10 ROWS FETCH NEXT 5 ROWS ONLY}

    query = base_query |> union_all(^union_query1) |> union_all(^union_query2) |> plan()

    assert all(query) ==
             ~s{SELECT s0.x FROM schema s0 } <>
               ~s{UNION ALL (SELECT s0.y FROM schema s0 ORDER BY s0.y OFFSET 20 ROWS FETCH NEXT 40 ROWS ONLY) } <>
               ~s{UNION ALL (SELECT s0.z FROM schema s0 ORDER BY s0.z OFFSET 30 ROWS FETCH NEXT 60 ROWS ONLY) } <>
               ~s{ORDER BY rand OFFSET 10 ROWS FETCH NEXT 5 ROWS ONLY}
  end

  test "except" do
    base_query =
      Schema |> select([r], r.x) |> order_by(fragment("rand")) |> offset(10) |> limit(5)

    except_query1 = Schema |> select([r], r.y) |> order_by([r], r.y) |> offset(20) |> limit(40)
    except_query2 = Schema |> select([r], r.z) |> order_by([r], r.z) |> offset(30) |> limit(60)

    query = base_query |> except(^except_query1) |> except(^except_query2) |> plan()

    assert all(query) ==
             ~s{SELECT s0.x FROM schema s0 } <>
               ~s{MINUS (SELECT s0.y FROM schema s0 ORDER BY s0.y OFFSET 20 ROWS FETCH NEXT 40 ROWS ONLY) } <>
               ~s{MINUS (SELECT s0.z FROM schema s0 ORDER BY s0.z OFFSET 30 ROWS FETCH NEXT 60 ROWS ONLY) } <>
               ~s{ORDER BY rand OFFSET 10 ROWS FETCH NEXT 5 ROWS ONLY}
  end

  test "intersect" do
    base_query =
      Schema |> select([r], r.x) |> order_by(fragment("rand")) |> offset(10) |> limit(5)

    intersect_query1 = Schema |> select([r], r.y) |> order_by([r], r.y) |> offset(20) |> limit(40)
    intersect_query2 = Schema |> select([r], r.z) |> order_by([r], r.z) |> offset(30) |> limit(60)

    query = base_query |> intersect(^intersect_query1) |> intersect(^intersect_query2) |> plan()

    assert all(query) ==
             ~s{SELECT s0.x FROM schema s0 } <>
               ~s{INTERSECT (SELECT s0.y FROM schema s0 ORDER BY s0.y OFFSET 20 ROWS FETCH NEXT 40 ROWS ONLY) } <>
               ~s{INTERSECT (SELECT s0.z FROM schema s0 ORDER BY s0.z OFFSET 30 ROWS FETCH NEXT 60 ROWS ONLY) } <>
               ~s{ORDER BY rand OFFSET 10 ROWS FETCH NEXT 5 ROWS ONLY}
  end

  test "limit and offset" do
    query = Schema |> limit([r], 3) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 FETCH NEXT 3 ROWS ONLY}

    query = Schema |> offset([r], 5) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 OFFSET 5 ROWS}

    query = Schema |> offset([r], 5) |> limit([r], 3) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 OFFSET 5 ROWS FETCH NEXT 3 ROWS ONLY}
  end

  test "string escape" do
    query = "\"Schema\"" |> where('"Foo"': "\" ") |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM \"Schema\" t0 WHERE (t0.\"Foo\" = '\" ')}
  end

  test "is_nil" do
    query = Schema |> select([r], r.x) |> where([r], is_nil(r.x)) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 WHERE (s0.x IS NULL)}

    query = Schema |> select([r], r.x) |> where([r], not is_nil(r.x)) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 WHERE (NOT (s0.x IS NULL))}
  end

  test "fragments" do
    query = Schema |> select([r], fragment("lower(?)", r.x)) |> plan()
    assert all(query) == ~s{SELECT lower(s0.x) FROM schema s0}

    value = 13
    query = Schema |> select([r], fragment("CASE WHEN ? THEN ? ELSE ? END", r.x == ^value, true, false)) |> plan()
    assert all(query) == ~s{SELECT CASE WHEN s0.x = :1 THEN 1 ELSE 0 END FROM schema s0}
  end

  test "literals" do
    query = "schema" |> where(foo: true) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 WHERE (s0.foo = 1)}

    query = "schema" |> where(foo: false) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 WHERE (s0.foo = 0)}

    query = "schema" |> where(foo: "abc") |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 WHERE (s0.foo = 'abc')}

    query = "schema" |> where(foo: <<0, ?a, ?b, ?c>>) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 WHERE (s0.foo = '00616263')}

    query = "schema" |> where(foo: 123) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 WHERE (s0.foo = 123)}

    query = "schema" |> where(foo: 123.0) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 WHERE (s0.foo = 123.0)}
  end

  test "datetime_add" do
    query = "schema" |> where([s], datetime_add(s.foo, 1, "month") > s.bar) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 WHERE ((s0.foo +  INTERVAL '1' month) > s0.bar)}

    query = "schema" |> where([s], datetime_add(type(s.foo, :string), 1, "month") > s.bar) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 WHERE ((CAST(s0.foo AS varchar2(2000)) +  INTERVAL '1' month) > s0.bar)}
  end

  test "tagged type" do
    query = Schema |> select([], type(^"601d74e4-a8d3-4b6e-8365-eddb4c893327", Ecto.UUID)) |> plan()
    assert all(query) == ~s{SELECT CAST(:1 AS raw(16)) FROM schema s0}
  end

  test "in subquery" do
    posts = subquery("posts" |> where(title: ^"hello") |> select([p], p.id))
    query = "comments" |> where([c], c.post_id in subquery(posts)) |> select([c], c.x) |> plan()
    assert all(query) ==
           ~s{SELECT c0.x FROM comments c0 } <>
           ~s{WHERE (c0.post_id IN (SELECT sp0.id FROM posts sp0 WHERE (sp0.title = :1)))}

    posts = subquery("posts" |> where(title: parent_as(:comment).subtitle) |> select([p], p.id))
    query = "comments" |> from(as: :comment) |> where([c], c.post_id in subquery(posts)) |> select([c], c.x) |> plan()
    assert all(query) ==
           ~s{SELECT c0.x FROM comments c0 } <>
           ~s{WHERE (c0.post_id IN (SELECT sp0.id FROM posts sp0 WHERE (sp0.title = c0.subtitle)))}
  end

  test "having" do
    query = Schema |> having([p], max(p.x) == max(p.x)) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 HAVING (max(s0.x) = max(s0.x))}

    query = Schema |> having([p], max(p.x) == max(p.x)) |> having([p], max(p.y) == max(p.y)) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 HAVING (max(s0.x) = max(s0.x)) AND (max(s0.y) = max(s0.y))}
  end

  test "or_having" do
    query = Schema |> or_having([p], max(p.x) == max(p.x)) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 HAVING (max(s0.x) = max(s0.x))}

    query = Schema |> or_having([p], max(p.x) == max(p.x)) |> or_having([p], max(p.y) == max(p.y)) |> select([], true) |> plan()
    assert all(query) == ~s{SELECT 1 FROM schema s0 HAVING (max(s0.x) = max(s0.x)) OR (max(s0.y) = max(s0.y))}
  end

  test "group by" do
    query = Schema |> group_by([r], r.x) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 GROUP BY s0.x}

    query = Schema |> group_by([r], [r.x, r.y]) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 GROUP BY s0.x, s0.y}

    query = Schema |> group_by([r], [r.x, r.y]) |> having([r], r.x > 2) |> select([r], [r.x, r.y, count()]) |> plan()
    assert all(query) == ~s{SELECT s0.x, s0.y, count(*) FROM schema s0 GROUP BY s0.x, s0.y HAVING (s0.x > 2)}

    query = Schema |> group_by([r], [r.x]) |> having(count(fragment("*")) > 2) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0 GROUP BY s0.x HAVING (count(*) > 2)}

    query = Schema |> group_by([r], []) |> select([r], r.x) |> plan()
    assert all(query) == ~s{SELECT s0.x FROM schema s0}
  end

  test "fragments allow ? to be escaped with backslash" do
    query =
      plan(
        from(e in "schema",
          where: fragment("? = \"query\\?\"", e.start_time),
          select: true
        )
      )

    result =
      "SELECT 1 FROM schema s0 " <>
        "WHERE (s0.start_time = \"query?\")"

    assert all(query) == String.trim(result)
  end

  test "update all" do
    query = from(m in Schema, update: [set: [x: 0]]) |> plan(:update_all)
    assert update_all(query) ==
           ~s{UPDATE schema s0 SET x = 0}

    query = from(m in Schema, update: [set: [x: 0], inc: [y: 1, z: -3]]) |> plan(:update_all)
    assert update_all(query) ==
           ~s{UPDATE schema s0 SET x = 0, y = s0.y + 1, z = s0.z + -3}

    query = from(e in Schema, where: e.x == 123, update: [set: [x: 0]]) |> plan(:update_all)
    assert update_all(query) ==
           ~s{UPDATE schema s0 SET x = 0 WHERE (s0.x = 123)}

    query = from(m in Schema, update: [set: [x: ^0]]) |> plan(:update_all)
    assert update_all(query) ==
           ~s{UPDATE schema s0 SET x = :1}
  end

  test "update all with returning" do
    query = from(m in Schema, update: [set: [x: 0]]) |> select([m], m) |> plan(:update_all)
    assert update_all(query) ==
           ~s{UPDATE schema s0 SET x = 0 RETURN s0.id, s0.x, s0.y, s0.z, s0.w INTO :id, :x, :y, :z, :w}

    query = from(m in Schema, update: [set: [x: ^1]]) |> where([m], m.x == ^2) |> select([m], m.y) |> plan(:update_all)
    assert update_all(query) ==
           ~s{UPDATE schema s0 SET x = :1 WHERE (s0.x = :2) RETURN s0.y INTO :y}
  end

  test "update all with prefix" do
    query =
      from(m in Schema, update: [set: [x: 0]]) |> Map.put(:prefix, "prefix") |> plan(:update_all)

    assert update_all(query) ==
             ~s{UPDATE prefix.schema s0 SET x = 0}

    query =
      from(m in Schema, prefix: "first", update: [set: [x: 0]])
      |> Map.put(:prefix, "prefix")
      |> plan(:update_all)

    assert update_all(query) ==
             ~s{UPDATE first.schema s0 SET x = 0}
  end

  test "delete all" do
    query = Schema |> Queryable.to_query() |> plan()
    assert delete_all(query) == ~s{DELETE FROM schema s0}

    query = from(e in Schema, where: e.x == 123)|> plan()
    assert delete_all(query) == ~s{DELETE FROM schema s0 WHERE (s0.x = 123)}
  end

  test "delete all with returning" do
    query = Schema |> Queryable.to_query |> select([m], m) |> plan()
    assert delete_all(query) == ~s{DELETE FROM schema s0 RETURN s0.id, s0.x, s0.y, s0.z, s0.w INTO :id, :x, :y, :z, :w}

    query = from(e in Schema, where: e.x == 123) |> select([e], e.y) |> plan()
    assert delete_all(query) == ~s{DELETE FROM schema s0 WHERE (s0.x = 123) RETURN s0.y INTO :y}
  end

  test "delete all with prefix" do
    query = Schema |> Queryable.to_query() |> Map.put(:prefix, "prefix") |> plan()
    assert delete_all(query) == ~s{DELETE FROM prefix.schema s0}

    query = Schema |> from(prefix: "first") |> Map.put(:prefix, "prefix") |> plan()
    assert delete_all(query) == ~s{DELETE FROM first.schema s0}
  end

  ## Partitions and windows

  describe "windows and partitions" do
    test "count over window" do
      query = Schema
              |> windows([r], w: [partition_by: r.x])
              |> select([r], count(r.x) |> over(:w))
              |> plan()
      assert all(query) == ~s{SELECT count(s0.x) OVER (PARTITION BY s0.x) FROM schema s0}
    end

    test "count over window order by" do
      query = Schema
              |> select([r], count(r.x) |> over(partition_by: [r.x, r.z], order_by: r.x))
              |> plan()
      assert all(query) == ~s{SELECT count(s0.x) OVER (PARTITION BY s0.x, s0.z ORDER BY s0.x) FROM schema s0}
    end

    test "count over all" do
      query = Schema
              |> select([r], count(r.x) |> over)
              |> plan()
      assert all(query) == ~s{SELECT count(s0.x) OVER () FROM schema s0}
    end

    test "nth_value over all" do
      query = Schema
              |> select([r], nth_value(r.x, 42) |> over)
              |> plan()
      assert all(query) == ~s{SELECT nth_value(s0.x, 42) OVER () FROM schema s0}
    end

    test "custom aggregation over all" do
      query = Schema
              |> select([r], fragment("custom_function(?)", r.x) |> over)
              |> plan()
      assert all(query) == ~s{SELECT custom_function(s0.x) OVER () FROM schema s0}
    end

    test "row_number over window order by" do
      query = Schema
              |> select([r], row_number |> over(partition_by: [r.x, r.z], order_by: r.x))
              |> plan()
      assert all(query) == ~s{SELECT row_number() OVER (PARTITION BY s0.x, s0.z ORDER BY s0.x) FROM schema s0}
    end

    test "lag/2 over window order by" do
      query = Schema
              |> select([r], lag(r.x, 42) |> over(partition_by: [r.x, r.z], order_by: r.x))
              |> plan()
      assert all(query) == ~s{SELECT lag(s0.x, 42) OVER (PARTITION BY s0.x, s0.z ORDER BY s0.x) FROM schema s0}
    end

    test "frame clause" do
      query = Schema
              |> select([r], count(r.x) |> over(partition_by: [r.x, r.z], order_by: r.x, 
			    frame: fragment("ROWS BETWEEN 2 PRECEDING AND 2 FOLLOWING")))
              |> plan()
      assert all(query) == ~s{SELECT count(s0.x) OVER (PARTITION BY s0.x, s0.z ORDER BY s0.x } <>
               ~s{ROWS BETWEEN 2 PRECEDING AND 2 FOLLOWING) FROM schema s0}
    end
  end

end
