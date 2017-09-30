defmodule Jamdb.Oracle.Mixfile do
  use Mix.Project

  def project do
    [app: :jamdb_oracle,
     version: "0.0.10",
     elixir: "~> 1.0",
     build_embedded: Mix.env == :prod,
     start_permanent: Mix.env == :prod,
     description: description,
     package: package,
     deps: deps]
  end

  def application do
    [applications: [:db_connection]]
  end

  defp deps do
    [{:jose, "~> 1.8.0"},
     {:ecto, "~> 2.1.0"},
     {:db_connection, "~> 1.1.0"},
     {:ex_doc, "~> 0.16.0", only: :docs}]
  end

  defp description do
    "Erlang driver and Ecto adapter for Oracle"
  end

  defp package do
    [files: ["src","include","lib","test","rebar.config","mix.exs"],
    maintainers: ["Mykhailo Vstavskyi","Sergiy Kostyushkin"],
    licenses: ["MIT"],
    links: %{"Github" => "https://github.com/erlangbureau/jamdb_oracle"}]
  end
end
