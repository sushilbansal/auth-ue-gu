defmodule AuthUbGu.Repo do
  use Ecto.Repo,
    otp_app: :auth_ub_gu,
    adapter: Ecto.Adapters.Postgres
end
