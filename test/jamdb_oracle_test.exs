defmodule Jamdb.OracleTest do
  use ExUnit.Case
  import Ecto.Query
  alias Jamdb.Oracle.TestRepo

  test "query" do
    assert [] = TestRepo.all(from dual in "dual", select: :nil, where: is_nil(^1)) |> IO.inspect
    assert {:ok, _ret } = TestRepo.query("select 1+:1, sysdate, rowid from dual where 1=:1 ", [1]) |> IO.inspect
  end
end
