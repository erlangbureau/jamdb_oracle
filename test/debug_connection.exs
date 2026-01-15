# Elixir test script for debug logging
defmodule TestDebugConnection do
  @moduledoc """
  Test connection with debug logging enabled to diagnose timeout issues
  """

  def test do
    # REPLACE WITH YOUR CREDENTIALS
    opts = [
      host: "YOUR_HOST",
      port: 1521,
      user: "YOUR_USER",
      password: "YOUR_PASSWORD",
      # Use 'database' instead of 'service_name'
      database: "YOUR_DATABASE",
      # Enable debug logging
      debug: true
    ]

    IO.puts("\n=== Testing Connection with Debug Logging ===\n")

    case JamdbOracle.connect(opts) do
      {:ok, _, state} ->
        IO.puts("\n✓ SUCCESS: Connected successfully")
        JamdbOracle.disconnect(state)

      {:error, type, reason, _state} ->
        IO.puts("\n✗ FAILED: Connection failed")
        IO.puts("  Type: #{inspect(type)}")
        IO.puts("  Reason: #{inspect(reason)}")
    end
  end
end

# Run test
TestDebugConnection.test()
