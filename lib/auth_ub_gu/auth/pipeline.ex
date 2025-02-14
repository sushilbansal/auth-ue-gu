defmodule AuthUbGu.Auth.Pipeline do
  use Guardian.Plug.Pipeline,
    otp_app: :auth_ub_gu,
    error_handler: AuthUbGu.Auth.ErrorHandler,
    module: AuthUbGu.Auth.Guardian

  # Look for a token in the session.
  # If there is no session or no token nothing happens and control is passed to the next plug
  # If a token is found it's verified and added to the conn struct available with `Guardian.Plug.current_token` and `Guardian.Plug.current_claims`
  # LiveView, traditional web apps (browser-based authentication)
  plug Guardian.Plug.VerifySession
  # Look for a token in the HTTP Authorization header. (prefixed with `"Bearer "`)
  #  APIs, mobile apps, stateless auth
  plug Guardian.Plug.VerifyHeader
  # Load the user if either of the verifications worked
  plug Guardian.Plug.LoadResource, allow_blank: true

  # not using this plug as it would halt the pipeline if the user is not authenticated
  # we want to let the live view handle the redirect
  # plug Guardian.Plug.EnsureAuthenticated, halt: false

  # Custom function - can be used to test the results of prev plug
  # plug :after_load

  # def after_load(conn, _opts) do
  #   user = Guardian.Plug.put_current_resource(conn)
  #   # Debug output
  #   IO.inspect(conn, label: " ================= Loaded User")
  #   conn
  # end
end
