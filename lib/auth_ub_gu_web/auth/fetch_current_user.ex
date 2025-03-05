defmodule AuthUbGuWeb.Auth.FetchCurrentUser do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  alias AuthUbGuWeb.Auth.Logout
  alias AuthUbGuWeb.Auth.Token
  alias AuthUbGu.Auth.Guardian

  @doc """
  Fetch the current user from the access token in the session or refresh token.
  and store it in the conn assigns.
  """
  @spec fetch_current_user(Plug.Conn.t(), list()) :: Plug.Conn.t()
  def fetch_current_user(conn, _opts) do
    case Token.get_access_token_from_session_or_refresh_token(conn) do
      {conn, nil} ->
        conn
        |> Logout.log_out_user(redirect_after_logout: false)
        |> assign(:current_user, nil)

      {conn, access_token} ->
        case Guardian.resource_from_token(access_token) do
          {:ok, user, _claims} ->
            assign(conn, :current_user, user)

          _ ->
            conn
            |> Logout.log_out_user(redirect_after_logout: false)
            |> assign(:current_user, nil)
        end
    end
  end
end
