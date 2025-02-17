defmodule AuthUbGuWeb.Auth.FetchCurrentUser do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  alias AuthUbGuWeb.Auth.Shared
  alias AuthUbGu.Auth.Guardian

  alias AuthUbGu.Accounts
  alias AuthUbGuWeb.Auth.Logout

  @access_ttl {1, :minute}

  @doc """
  Authenticates the user by looking into the session
  and remember me token.
  """
  def fetch_current_user(conn, _opts) do
    # want to use the guardian plug to get the user
    # and then run a background task to validate the token

    case ensure_user_token(conn) do
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
  defp validate_token_in_db(token, context, conn) do
    {validity, interval} = @access_ttl

    # validate the token in the db and return the user if token is valid
    case Accounts.get_user_by_session_token(token, context,
           validity: validity,
           interval: Atom.to_string(interval)
         ) do
      nil ->
        # logout the user and revoke the token in the db
        Logout.log_out_user(conn)

      _ ->
        :ok
    end
  end

  # since we are using guardian plug to get the user
  # we need to fetch the token from the guardian plug or cookies
  defp ensure_user_token(conn) do
    cookie_settings = Shared.get_access_cookie_settings()
    %{remember_me_cookie: remember_me_cookie} = cookie_settings
    # if token = get_session(conn, Accounts.get_auth_token_name()) do
    if token = Guardian.Plug.current_token(conn) do
      {token, conn}
    else
      conn = fetch_cookies(conn, signed: [remember_me_cookie])

      if token = conn.cookies[remember_me_cookie] do
        {token, Shared.put_token_in_session(conn, token)}
      else
        {nil, conn}
      end
    end
  end
end
