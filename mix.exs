defmodule Jamdb.Oracle.Mixfile do
  use Mix.Project

  def project do
    [app: :jamdb_oracle,
     version: "0.5.7",
     elixir: "~> 1.10",
     description: description(),
     package: package(),
     deps: deps()]
  end

  defp deps do
    [
      {:ecto_sql, "~> 3.8"}
    ]
  end

  defp description do
    "Erlang driver and Ecto adapter for Oracle"
  end

  defp package do
    [files: ["src","include","lib","mix.exs"],
    maintainers: ["Mykhailo Vstavskyi","Sergiy Kostyushkin"],
    licenses: ["MIT"],
    links: %{"Github" => "https://github.com/erlangbureau/jamdb_oracle"}]
  end
end
