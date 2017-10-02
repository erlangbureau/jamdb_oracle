use Mix.Config

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
env_file = "#{Mix.env}.exs"
if Path.join("config", env_file) |> File.exists? do
  import_config env_file
end
