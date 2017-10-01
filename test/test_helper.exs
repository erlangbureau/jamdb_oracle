defmodule Jamdb.Oracle.TestRepo do
  use Ecto.Repo, otp_app: :jamdb_oracle
end
{:ok, _pid} = Jamdb.Oracle.TestRepo.start_link()
ExUnit.start()
