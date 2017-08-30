Logger.configure(level: :debug)
ExUnit.start

# Configure Ecto for support and tests
Application.put_env(:ecto, :primary_key_type, :id)

# Configure Oracle connection
Code.require_file "jamdb_oracle_test.exs", __DIR__

# Load support files
Code.require_file "../deps/ecto/integration_test/support/repo.exs", __DIR__

# Pool repo for async, safe tests
alias Ecto.Integration.TestRepo

Application.put_env(:ecto, TestRepo,
  adapter: Ecto.Adapters.Jamdb.Oracle,
  url: Application.get_env(:ecto, :jamdb_oracle_test_url),
  pool_size: 1,
  pool: Ecto.Adapters.SQL.Sandbox,
  ownership_pool: DBConnection.Poolboy)

defmodule Ecto.Integration.TestRepo do
  use Ecto.Integration.Repo, otp_app: :ecto
end

# Pool repo for non-async tests
alias Ecto.Integration.PoolRepo

Application.put_env(:ecto, PoolRepo,
  adapter: Ecto.Adapters.Jamdb.Oracle,
  pool: DBConnection.Poolboy,
  url: Application.get_env(:ecto, :jamdb_oracle_test_url),
  timeout: 15000,
  pool_size: 10,
  max_restarts: 20,
  max_seconds: 10)

defmodule Ecto.Integration.PoolRepo do
  use Ecto.Integration.Repo, otp_app: :ecto
end

defmodule Ecto.Integration.Case do
  use ExUnit.CaseTemplate

  setup do
    :ok = Ecto.Adapters.SQL.Sandbox.checkout(TestRepo)
  end
end

{:ok, _pid} = TestRepo.start_link
{:ok, _pid} = PoolRepo.start_link

TestRepo.query("select 1+:1, sysdate, rowid from dual where 1=:1 ", [1]) |> IO.inspect
