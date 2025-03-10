defmodule AuthUbGuWeb.Auth.Logout do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller
  alias AuthUbGuWeb.Auth.Token
  alias AuthUbGuWeb.Auth.Shared

  alias AuthUbGu.Accounts

  @doc """
  Logs the user out.

  It clears all session data for safety. See renew_session.
  """
  @spec log_out_user(Plug.Conn.t(), list()) :: Plug.Conn.t()
  def log_out_user(conn, opts \\ []) do
    conn
    |> disconnect_live_socket()
    |> delete_refresh_token_from_db()
    |> Shared.renew_session()
    |> delete_all_cookies()
    |> redirect_after_logout(opts)
  end

  defp redirect_after_logout(conn, opts) do
    if Keyword.get(opts, :redirect_after_logout, true) do
      conn
      |> redirect(to: ~p"/")
    else
      conn
    end
  end

  defp disconnect_live_socket(conn) do
    if live_socket_id = get_session(conn, :live_socket_id) do
      AuthUbGuWeb.Endpoint.broadcast(live_socket_id, "disconnect", %{})
    end

    conn
  end

  defp delete_refresh_token_from_db(conn) do
    {refresh_token, conn} = Token.get_refresh_token_from_session_or_cookies(conn)
    refresh_token && Accounts.delete_user_token(refresh_token, "refresh")
    conn
  end

  defp delete_all_cookies(conn) do
    %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()

    conn
    |> delete_resp_cookie(remember_me_cookie)
  end
end
