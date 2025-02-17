defmodule AuthUbGuWeb.Auth.FetchCurrentUser do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  alias AuthUbGuWeb.Auth.Shared
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

    case Shared.get_access_token(conn) do
      {nil, conn} ->
        assign(conn, :current_user, nil)

      {token, conn} ->
        case Guardian.decode_and_verify(token) do
          {:ok, _claims} ->
            # get the user from the guardian plug
            user = Guardian.Plug.current_resource(conn)

            # Run background task to verify token in DB
            # not relying on the guardian plug to verify the token
            # user could have been deleted or token revoked
            Task.Supervisor.start_child(AuthUbGu.TaskSupervisor, fn ->
              validate_token_in_db(token, "session", conn)
            end)

            # Assign the user immediately
            assign(conn, :current_user, user)

          _ ->
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
    %{"access" => access_ttl} = Shared.get_guardian_ttl_settings()

    # validate the token in the db and return the user if token is valid
    case Accounts.get_user_by_session_token(
           token,
           context,
           Shared.convert_ttl_to_db_format(access_ttl)
         ) do
      nil ->
        # logout the user and revoke the token in the db
        Logout.log_out_user(conn)

      _ ->
        :ok
    end
  end
end
