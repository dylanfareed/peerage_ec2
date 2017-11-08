# This file is responsible for configuring your application
# and its dependencies with the aid of the Mix.Config module.
use Mix.Config

config :peerage, via: Peerage.Via.Ec2, aws_access_key_id: System.get_env("AWS_ACCESS_KEY_ID"),
                                       aws_secret_access_key: System.get_env("AWS_SECRET_ACCESS_KEY"),
                                       log_results: false,
                                       tags: [{:cluster, "cluster"}, {:service, "service"}]
