# This file is responsible for configuring your application
# and its dependencies with the aid of the Config module.
#
# This configuration file is loaded before any dependency and
# is restricted to this project.

# General application configuration
import Config

config :auth_ub_gu,
  ecto_repos: [AuthUbGu.Repo],
  generators: [timestamp_type: :utc_datetime]

# Configures the endpoint
config :auth_ub_gu, AuthUbGuWeb.Endpoint,
  url: [host: "localhost"],
  adapter: Bandit.PhoenixAdapter,
  render_errors: [
    formats: [html: AuthUbGuWeb.ErrorHTML, json: AuthUbGuWeb.ErrorJSON],
    layout: false
  ],
  pubsub_server: AuthUbGu.PubSub,
  live_view: [signing_salt: "hlbrQ8hg"]

# Configures the mailer
#
# By default it uses the "Local" adapter which stores the emails
# locally. You can see the emails in your browser, at "/dev/mailbox".
#
# For production it's recommended to configure a different adapter
# at the `config/runtime.exs`.
config :auth_ub_gu, AuthUbGu.Mailer, adapter: Swoosh.Adapters.Local

# Configure esbuild (the version is required)
config :esbuild,
  version: "0.17.11",
  auth_ub_gu: [
    args:
      ~w(js/app.js --bundle --target=es2017 --outdir=../priv/static/assets --external:/fonts/* --external:/images/*),
    cd: Path.expand("../assets", __DIR__),
    env: %{"NODE_PATH" => Path.expand("../deps", __DIR__)}
  ]

# Configure tailwind (the version is required)
config :tailwind,
  version: "3.4.3",
  auth_ub_gu: [
    args: ~w(
      --config=tailwind.config.js
      --input=css/app.css
      --output=../priv/static/assets/app.css
    ),
    cd: Path.expand("../assets", __DIR__)
  ]

# Configures Elixir's Logger
config :logger, :console,
  format: "$time $metadata[$level] $message\n",
  metadata: [:request_id]

# Use Jason for JSON parsing in Phoenix
config :phoenix, :json_library, Jason

config :auth_ub_gu, AuthUbGu.Auth.Guardian,
  issuer: "auth_ub_gu",
  secret_key: "TXG2SSXo3pfSuVIbqMgHTGopj17HMAXZLCTic3lUuqDg1bbRI16IftSiECOIh6x3"

config :ueberauth, Ueberauth,
  providers: [
    # Example provider
    google: {Ueberauth.Strategy.Google, [default_scope: "email profile"]}
  ]

config :ueberauth, Ueberauth.Strategy.Google.OAuth,
  client_id: "1059919869688-e50g6tllghoc67u7k361m897fq3ecqts.apps.googleusercontent.com",
  client_secret: "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"

# System.get_env("GUARDIAN_SECRET_KEY")

# Import environment specific config. This must remain at the bottom
# of this file so it overrides the configuration defined above.
import_config "#{config_env()}.exs"
