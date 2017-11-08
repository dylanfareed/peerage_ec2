defmodule Peerage.Via.Ec2.Mixfile do
  use Mix.Project

  def project do
    [app: :peerage_ec2,
     version: "1.0.0",
     elixir: "~> 1.5",
     start_permanent: Mix.env == :prod,
     deps: deps(),
     name: "Peerage EC2",
     package: package(),
     description: description(),
     source_url: "https://github.com/BoweryFarming/peerage_ec2",
     homepage_url: "https://github.com/BoweryFarming/peerage_ec2",
     docs: [main: "readme", extras: ["README.md"]]]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [{:peerage, "~> 1.0"}, # Easy Elixir clusters, pluggable discovery
     {:sweet_xml, "~> 0.6.5"},] # :xmerl wrapper to help query xml docs
  end

  def package do
    [files: ["lib", "mix.exs", "README*"],
     maintainers: ["Kevin Sheurs", "Dylan Fareed", "Henry Sztul"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/BoweryFarming/peerage_ec2",
              "Docs" => "https://hexdocs.pm/peerage_ec2/readme.html"}]
  end

  def description do
    """
    A Peerage provider for easy clustering on AWS EC2 and Elastic Beanstalk
    """
  end
end
