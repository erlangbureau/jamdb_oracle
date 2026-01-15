defmodule TestDebugVerbose do
  @moduledoc """
  Verbose test with timestamps and full error details
  """

  def test do
    # REPLACE WITH YOUR CREDENTIALS
    opts = [
      host: "YOUR_HOST",
      port: 1521,
      user: "YOUR_USER",
      password: "YOUR_PASSWORD",
      database: "YOUR_DATABASE",
      # Increase to 30 seconds to see if it's a slow connection
      timeout: 30000,
      debug: true
    ]

    IO.puts("\n========================================")
    IO.puts("  Debug Connection Test")
    IO.puts("========================================\n")
    IO.puts("Connection options:")
    IO.puts("  Host: #{opts[:host]}")
    IO.puts("  Port: #{opts[:port]}")
    IO.puts("  User: #{opts[:user]}")
    IO.puts("  Database: #{opts[:database]}")
    IO.puts("  Debug: #{opts[:debug]}")
    IO.puts("  Timeout: #{opts[:timeout]}ms\n")

    IO.puts("Attempting connection...")
    start_time = System.monotonic_time(:millisecond)

    result = JamdbOracle.connect(opts)

    end_time = System.monotonic_time(:millisecond)
    duration = end_time - start_time

    IO.puts("\n--- Connection Result ---")
    IO.puts("Duration: #{duration}ms")

    case result do
      {:ok, _, state} ->
        IO.puts("\n✓ SUCCESS: Connected successfully!")
        JamdbOracle.disconnect(state)

      {:error, type, reason, _state} ->
        IO.puts("\n✗ FAILED: Connection failed")
        IO.puts("  Error Type: #{inspect(type)}")
        IO.puts("  Reason: #{inspect(reason)}")
        IO.puts("\n  Common causes of timeout:")
        IO.puts("    - Wrong port (1521 for plain TCP, 2484 for SSL/TLS)")
        IO.puts("    - Firewall blocking connection")
        IO.puts("    - Server not responding")
        IO.puts("    - Network connectivity issue")
        IO.puts("    - Wrong host name or IP")
    end

    IO.puts("\n========================================\n")
  end
end

# Run test
TestDebugVerbose.test()
