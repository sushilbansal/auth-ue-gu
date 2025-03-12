defmodule AuthUbGuWeb.Auth.Login do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller

  alias AuthUbGuWeb.Auth.Token
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
  @spec log_in_user(Plug.Conn.t(), Accounts.User.t(), map()) :: Plug.Conn.t()
  def log_in_user(conn, user, params \\ %{}) do
    user_return_to = get_session(conn, :user_return_to)
    {access_token, refresh_token} = generate_tokens(user)

    conn
    |> Shared.renew_session(force_renew: true)
    |> Token.put_access_token_in_session(access_token)
    |> Token.store_refresh_token_in_session_cookies_db(user, refresh_token, params)
    |> redirect_after_login(user_return_to, params)
  end

  defp generate_tokens(user) do
    {Token.generate_access_token(user), Token.generate_refresh_token(user)}
  end

  # mostly used for testing - testing fails if the user is redirected
  # so disable the redirect in the test
  defp redirect_after_login(conn, _user_return_to, %{"redirect_after_login" => "false"}) do
    conn
  end

  defp redirect_after_login(conn, user_return_to, %{}) do
    conn
    |> redirect(to: user_return_to || Shared.signed_in_path(conn))
  end
end
