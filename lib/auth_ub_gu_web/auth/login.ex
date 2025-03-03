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
  @spec log_in_user(Plug.Conn.t(), Accounts.User.t(), String.t(), map()) :: Plug.Conn.t()
  def log_in_user(conn, user, context, params \\ %{}) do
    conn =
      conn
      |> Shared.renew_session()
      |> guardian_sign_in(user)

    conn
    |> insert_token_in_db(user, context)
    |> maybe_write_remember_me_cookie(params)
    |> after_sign_in_redirect()
  end

  # inserts the token in the database
  defp insert_token_in_db(conn, user, context) do
    Accounts.insert_token(user, get_token_from_guardian(conn), context)
    conn
  end

  defp get_token_from_guardian(conn) do
    Guardian.Plug.current_token(conn)
  end

  @spec guardian_sign_in(Plug.Conn.t(), Accounts.User.t()) :: Plug.Conn.t()
  defp guardian_sign_in(conn, user) do
    %{access: %{session: access_ttl}} = Shared.get_guardian_ttl_settings()

    conn
    |> Guardian.Plug.sign_in(user, %{}, ttl: access_ttl)
  end

  @spec maybe_write_remember_me_cookie(Plug.Conn.t(), map()) :: Plug.Conn.t()
  defp maybe_write_remember_me_cookie(conn, %{"remember_me" => "true"}) do
    # Guardian.Plug.remember_me(conn, user)

    %{remember_me_cookie: remember_me_cookie, remember_me_options: remember_me_options} =
      Shared.get_access_cookie_settings()

    put_resp_cookie(
      conn,
      remember_me_cookie,
      get_token_from_guardian(conn),
      remember_me_options
    )
  end

  defp maybe_write_remember_me_cookie(conn, _params) do
    conn
  end

  @spec after_sign_in_redirect(Plug.Conn.t()) :: Plug.Conn.t()
  defp after_sign_in_redirect(conn) do
    user_return_to = get_session(conn, :user_return_to)

    conn
    |> redirect(to: user_return_to || Shared.signed_in_path(conn))
  end
end
