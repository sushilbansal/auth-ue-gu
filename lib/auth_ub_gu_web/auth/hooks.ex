defmodule AuthUbGuWeb.Auth.Hooks do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller
  alias AuthUbGu.Auth.Guardian
  alias AuthUbGuWeb.Auth.Logout
  alias AuthUbGuWeb.Auth.Shared

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

  # executes in live view - no access to cookies
  # usually the user will not be in session if it is logged out in other tab
  # generally issue with current_user should be handled in the require_authenticated_user function
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
      {:halt, Phoenix.LiveView.redirect(socket, to: Shared.signed_in_path(socket))}
    else
      {:cont, socket}
    end
  end

  # it is used in the on_mount callback. so no access to cookies.
  defp mount_current_user(socket, session) do
    Phoenix.Component.assign_new(socket, :current_user, fn ->
      # use guardian to get the user from the access token
      if access_token = session["access_token"] do
        case Guardian.resource_from_token(access_token) do
          {:ok, user, _claims} -> user
          _ -> nil
        end
      end
    end)
  end

  @doc """
  Used for routes that require the user to not be authenticated.
  """
  def redirect_if_user_is_authenticated(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
      |> redirect(to: Shared.signed_in_path(conn))
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
      # if the user is not logged in, we need to clear the session, cookies and delete refresh token from db
      |> Logout.log_out_user(redirect_after_logout: false)
      |> Shared.maybe_store_return_to()
      |> redirect(to: ~p"/users/log_in")
      |> halt()
    end
  end
end
