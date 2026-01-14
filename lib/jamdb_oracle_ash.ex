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
