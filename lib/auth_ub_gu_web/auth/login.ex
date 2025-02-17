defmodule AuthUbGuWeb.Auth.Login do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller
  alias AuthUbGu.Auth.Guardian

  alias AuthUbGu.Accounts
  alias AuthUbGuWeb.Auth.Shared

  @doc """
  Logs the user in.

  It renews the session ID and clears the whole session
  to avoid fixation attacks. See the renew_session
  function to customize this behaviour.

  It also sets a `:live_socket_id` key in the session,
  so LiveView sessions are identified and automatically
  disconnected on log out. The line can be safely removed
  if you are not using LiveView.
  """

  def log_in_user(conn, user, context, params \\ %{}) do
    conn =
      conn
      |> Shared.renew_session()
      |> Guardian.Plug.sign_in(user)

    token = Guardian.Plug.current_token(conn)

    Accounts.generate_user_session_token(user, token, context)
    user_return_to = get_session(conn, :user_return_to)

    conn
    |> maybe_write_remember_me_cookie(token, params)
    |> redirect(to: user_return_to || Shared.signed_in_path(conn))
  end

  defp maybe_write_remember_me_cookie(conn, token, %{"remember_me" => "true"}) do
    # Guardian.Plug.remember_me(conn, user)
    cookie_settings = Shared.get_access_cookie_settings()

    put_resp_cookie(
      conn,
      cookie_settings.remember_me_cookie,
      token,
      cookie_settings.remember_me_options
    )
  end

  defp maybe_write_remember_me_cookie(conn, _token, _params) do
    conn
  end
end
