defmodule AuthUbGuWeb.Auth.Logout do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller
  alias AuthUbGuWeb.Auth.Shared
  alias AuthUbGu.Auth.Guardian

  alias AuthUbGu.Accounts

  @doc """
  Logs the user out.

  It clears all session data for safety. See renew_session.
  """
  def log_out_user(conn) do
    # user_token = get_session(conn, Accounts.get_auth_token_name())
    # need to get the user token from the guardian plug
    user_token =
      Guardian.Plug.current_token(conn) || get_session(conn, Accounts.get_auth_token_name())

    user_token && Accounts.delete_user_session_token(user_token)

    if live_socket_id = get_session(conn, :live_socket_id) do
      AuthUbGuWeb.Endpoint.broadcast(live_socket_id, "disconnect", %{})
    end

    cookie_settings = Shared.get_access_cookie_settings()

    conn
    # remove the user from the guardian plug
    |> Guardian.Plug.sign_out(clear_remember_me: true)
    |> Shared.renew_session()
    |> delete_resp_cookie(cookie_settings.remember_me_cookie)
    |> Guardian.Plug.sign_out(clear_remember_me: true)
    |> Guardian.Plug.clear_remember_me()
    |> redirect(to: ~p"/")
  end
end
