ExUnit.start()

Code.require_file "jamdb_oracle_test.exs", __DIR__

alias Jamdb.Oracle.TestRepo

Application.put_env(:jamdb, TestRepo,
  adapter: Ecto.Adapters.Jamdb.Oracle,
  url: Application.get_env(:ecto, :jamdb_oracle_test_url),
  timeout: 15000,
  pool_timeout: 5000,
  pool_size: 1,
  pool: DBConnection.Ownership,
  ownership_pool: DBConnection.Poolboy)

defmodule Jamdb.Oracle.TestRepo do
  use Ecto.Repo, otp_app: :jamdb
end

{:ok, _pid} = TestRepo.start_link()

defmodule Jamdb.Oracle.TestCase do
  use ExUnit.Case
  import Ecto.Query

  test "query" do
    assert [] = TestRepo.all(from dual in "dual", select: :nil, where: is_nil(^1)) |> IO.inspect
    assert {:ok, _ret } = TestRepo.query("select 1+:1, sysdate, rowid from dual where 1=:1 ", [1]) |> IO.inspect
  end
end
