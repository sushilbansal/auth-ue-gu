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
  @spec log_out_user(Plug.Conn.t()) :: Plug.Conn.t()
  def log_out_user(conn) do
    conn
    |> disconnect_live_socket()
    |> delete_token_from_db()
    |> guardian_sign_out()
    |> Shared.renew_session()
    |> delete_all_cookies()
    |> redirect(to: ~p"/")
  end

  defp disconnect_live_socket(conn) do
    if live_socket_id = get_session(conn, :live_socket_id) do
      AuthUbGuWeb.Endpoint.broadcast(live_socket_id, "disconnect", %{})
    end

    conn
  end

  defp delete_token_from_db(conn) do
    {token, conn} = Shared.get_access_token(conn)
    token && Accounts.delete_user_session_token(token)
    conn
  end

  defp guardian_sign_out(conn) do
    Guardian.Plug.sign_out(conn, clear_remember_me: true)
  end

  defp delete_all_cookies(conn) do
    %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()

    conn
    |> delete_resp_cookie(remember_me_cookie)
  end
end
