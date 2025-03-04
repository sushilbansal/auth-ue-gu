defmodule AuthUbGuWeb.Auth.FetchCurrentUser do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  alias AuthUbGuWeb.Auth.Token
  alias AuthUbGu.Auth.Guardian

  alias AuthUbGu.Accounts
  alias AuthUbGuWeb.Auth.Logout

  @doc """
  Authenticates the user by looking into the session
  and remember me token.
  """
  @spec fetch_current_user(Plug.Conn.t(), list()) :: Plug.Conn.t()
  def fetch_current_user(conn, _opts) do
    # want to use the guardian plug to get the user
    # and then run a background task to validate the token
    case Token.get_access_token_from_session_or_refresh_token(conn) do
      {conn, token} when not is_nil(token) ->
        case Guardian.resource_from_token(token) do
          {:ok, user, _claims} ->
            # Assign the user immediately
            assign(conn, :current_user, user)

            # Run background task to verify token in DB
            # not relying on the guardian plug to verify the token
            # user could have been deleted or token revoked
            # TODO: check if we need it here or somewhere else
            Task.Supervisor.start_child(AuthUbGu.TaskSupervisor, fn ->
              validate_token_in_db(token, "session", conn)
            end)

          {:error, _} ->
            assign(conn, :current_user, nil)
        end
    end

    # {user_token, conn} = ensure_user_token(conn)
    # user = user_token && Accounts.get_user_by_session_token(user_token)
    # assign(conn, :current_user, user)
  end

  # Validates the token in the database as a background task.
  # user could have been deleted or token revoked.
  @spec validate_token_in_db(String.t(), String.t(), Plug.Conn.t()) :: :ok
  defp validate_token_in_db(token, context, conn) do
    # validate the token in the db and return the user if token is valid
    case Accounts.get_user_by_session_token(
           token,
           context
         ) do
      nil ->
        # logout the user and revoke the token in the db
        Logout.log_out_user(conn, redirect_after_logout: false)

      _ ->
        :ok
    end
  end
end
