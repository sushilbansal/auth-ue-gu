defmodule AuthUbGuWeb.UserAuth do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller
  alias AuthUbGu.Auth.Guardian

  alias AuthUbGu.Accounts

  # Make the remember me cookie valid for 60 days.
  # If you want bump or reduce this value, also change
  # the token expiry itself in UserToken.
  # @max_age 60 * 60 * 24 * 60
  # TODO: check what is the default name for the guardian cookie and use that may be??
  @remember_me_cookie "_auth_ub_gu_web_user_remember_me"
  # @remember_me_options [sign: true, max_age: @max_age, same_site: "Lax"]

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

  def log_in_user(conn, user, context, _params \\ %{}) do
    conn =
      conn
      |> renew_session()
      |> Guardian.Plug.sign_in(user)

    token = Guardian.Plug.current_token(conn)

    Accounts.generate_user_session_token(user, token, context)
    user_return_to = get_session(conn, :user_return_to)

    conn
    # |> maybe_write_remember_me_cookie(token, params)
    |> redirect(to: user_return_to || signed_in_path(conn))
  end

  # defp maybe_write_remember_me_cookie(conn, token, %{"remember_me" => "true"}) do
  #   # Guardian.Plug.remember_me(conn, user)
  #   put_resp_cookie(conn, @remember_me_cookie, token, @remember_me_options)
  # end

  # defp maybe_write_remember_me_cookie(conn, _token, _params) do
  #   conn
  # end

  # This function renews the session ID and erases the whole
  # session to avoid fixation attacks. If there is any data
  # in the session you may want to preserve after log in/log out,
  # you must explicitly fetch the session data before clearing
  # and then immediately set it after clearing, for example:
  #
  #     defp renew_session(conn) do
  #       preferred_locale = get_session(conn, :preferred_locale)
  #
  #       conn
  #       |> configure_session(renew: true)
  #       |> clear_session()
  #       |> put_session(:preferred_locale, preferred_locale)
  #     end
  #
  defp renew_session(conn) do
    delete_csrf_token()

    conn
    |> configure_session(renew: true)
    |> clear_session()
  end

  @doc """
  Logs the user out.

  It clears all session data for safety. See renew_session.
  """
  def log_out_user(conn) do
    # user_token = get_session(conn, Accounts.get_auth_token_name())
    # need to get the user token from the guardian plug
    user_token = Guardian.Plug.current_token(conn)
    user_token && Accounts.delete_user_session_token(user_token)

    if live_socket_id = get_session(conn, :live_socket_id) do
      AuthUbGuWeb.Endpoint.broadcast(live_socket_id, "disconnect", %{})
    end

    conn
    # remove the user from the guardian plug
    |> Guardian.Plug.sign_out()
    |> renew_session()
    |> delete_resp_cookie(@remember_me_cookie)
    # |> Guardian.Plug.clear_remember_me()
    |> redirect(to: ~p"/")
  end

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
  # TODO: check if this method works
  defp validate_token_in_db(token, context, conn) do
    # validate the token in the db and return the user if token is valid
    case Accounts.get_user_by_session_token(token, context) do
      nil ->
        # logout the user and revoke the token in the db
        log_out_user(conn)

      _ ->
        :ok
    end
  end

  # since we are using guardian plug to get the user
  # we need to fetch the token from the guardian plug or cookies
  defp ensure_user_token(conn) do
    # if token = get_session(conn, Accounts.get_auth_token_name()) do
    if token = Guardian.Plug.current_token(conn) do
      {token, conn}
    else
      conn = fetch_cookies(conn, signed: [@remember_me_cookie])

      if token = conn.cookies[@remember_me_cookie] do
        {token, put_token_in_session(conn, token)}
      else
        {nil, conn}
      end
    end
  end

  @doc """
  Handles mounting and authenticating the current_user in LiveViews.

  ## `on_mount` arguments

    * `:mount_current_user` - Assigns current_user
      to socket assigns based on user_token, or nil if
      there's no user_token or no matching user.

    * `:ensure_authenticated` - Authenticates the user from the session,
      and assigns the current_user to socket assigns based
      on user_token.
      Redirects to login page if there's no logged user.

    * `:redirect_if_user_is_authenticated` - Authenticates the user from the session.
      Redirects to signed_in_path if there's a logged user.

  ## Examples

  Use the `on_mount` lifecycle macro in LiveViews to mount or authenticate
  the current_user:

      defmodule AuthUbGuWeb.PageLive do
        use AuthUbGuWeb, :live_view

        on_mount {AuthUbGuWeb.UserAuth, :mount_current_user}
        ...
      end

  Or use the `live_session` of your router to invoke the on_mount callback:

      live_session :authenticated, on_mount: [{AuthUbGuWeb.UserAuth, :ensure_authenticated}] do
        live "/profile", ProfileLive, :index
      end
  """
  def on_mount(:mount_current_user, _params, session, socket) do
    {:cont, mount_current_user(socket, session)}
  end

  def on_mount(:ensure_authenticated, _params, session, socket) do
    socket = mount_current_user(socket, session)

    if socket.assigns.current_user do
      {:cont, socket}
    else
      socket =
        socket
        |> Phoenix.LiveView.put_flash(:error, "You must log in to access this page.")
        |> Phoenix.LiveView.redirect(to: ~p"/users/log_in")

      {:halt, socket}
    end
  end

  def on_mount(:redirect_if_user_is_authenticated, _params, session, socket) do
    socket = mount_current_user(socket, session)

    if socket.assigns.current_user do
      {:halt, Phoenix.LiveView.redirect(socket, to: signed_in_path(socket))}
    else
      {:cont, socket}
    end
  end

  defp mount_current_user(socket, session) do
    Phoenix.Component.assign_new(socket, :current_user, fn ->
      # this is the benefit of having the same name for session token as the default guardian token name
      # TODO: check if this works
      if user_token = session[Atom.to_string(Accounts.get_auth_token_name())] do
        Accounts.get_user_by_session_token(user_token, "session")
      end
    end)
  end

  @doc """
  Used for routes that require the user to not be authenticated.
  """
  def redirect_if_user_is_authenticated(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
      |> redirect(to: signed_in_path(conn))
      |> halt()
    else
      conn
    end
  end

  @doc """
  Used for routes that require the user to be authenticated.

  If you want to enforce the user email is confirmed before
  they use the application at all, here would be a good place.
  """
  def require_authenticated_user(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> put_flash(:error, "You must log in to access this page.")
      |> maybe_store_return_to()
      |> redirect(to: ~p"/users/log_in")
      |> halt()
    end
  end

  defp put_token_in_session(conn, token) do
    live_socket_id = Base.url_encode64(token) |> String.slice(0, 16)

    conn
    # |> put_session(Accounts.get_auth_token_name(), token)
    # |> Guardian.Plug.put_session_token(token)
    |> put_session(:live_socket_id, "users_sessions:#{live_socket_id}")
  end

  defp maybe_store_return_to(%{method: "GET"} = conn) do
    put_session(conn, :user_return_to, current_path(conn))
  end

  defp maybe_store_return_to(conn), do: conn

  defp signed_in_path(_conn), do: ~p"/"
end
