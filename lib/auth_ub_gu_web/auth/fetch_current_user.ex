defmodule AuthUbGuWeb.Auth.FetchCurrentUser do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  alias AuthUbGuWeb.Auth.Token
  alias AuthUbGu.Auth.Guardian

  @doc """
  Authenticates the user by looking into the session
  and remember me token.
  """
  @spec fetch_current_user(Plug.Conn.t(), list()) :: Plug.Conn.t()
  def fetch_current_user(conn, _opts) do
    case Token.get_access_token_from_session_or_refresh_token(conn) do
      {conn, nil} ->
        assign(conn, :current_user, nil)

      {conn, access_token} ->
        case Guardian.resource_from_token(access_token) do
          {:ok, user, _claims} -> assign(conn, :current_user, user)
          _ -> assign(conn, :current_user, nil)
        end

        # not logging out the user here as this plug just fetches the user
        # user need not to be logged in to access the site.
        # it will be decided in require_authenticated_user plug
    end
  end
end
