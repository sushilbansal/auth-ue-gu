defmodule AuthUbGu.Auth.ErrorHandler do
  alias AuthUbGuWeb.UserAuth
  # alias AuthUbGu.Accounts.User
  # import Plug.Conn
  import Phoenix.Controller

  @behaviour Guardian.Plug.ErrorHandler

  @impl Guardian.Plug.ErrorHandler
  def auth_error(conn, {type, _reason}, _opts) do
    body = to_string(type)

    case body do
      "invalid_token" ->
        # need to log out the user if the token is invalid
        # current_user is still assigned in the session (conn and socket)

        conn
        |> put_flash(:error, "Session has expired. Please log in again.")
        |> UserAuth.log_out_user()
    end

    conn
    |> redirect(to: "/users/log_in")
  end
end
