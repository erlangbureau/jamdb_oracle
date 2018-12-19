defmodule Jamdb.Oracle.TestRepo do
  use Ecto.Repo,
  otp_app: :jamdb_oracle,
  adapter: Ecto.Adapters.Jamdb.Oracle
end
Supervisor.start_link([Jamdb.Oracle.TestRepo], strategy: :one_for_one)
ExUnit.start()
