defmodule AuthUbGuWeb.AuthController do
  use AuthUbGuWeb, :controller

  alias AuthUbGuWeb.UserAuth
  alias AuthUbGu.Accounts.User
  alias AuthUbGu.Accounts
  alias AuthUbGu.Auth.Guardian

  plug Ueberauth

  # Step 1: Redirect user to provider's login page
  def request(conn, %{"provider" => provider}) do
    conn
    |> redirect(external: Ueberauth.Strategy.Helpers.callback_url(conn, provider))
  end

  # Step 2: Handle OAuth callback
  def callback(%{assigns: %{ueberauth_auth: auth}} = conn, %{"provider" => provider}) do
    # it is based on the same logic as the login function in the user session controller
    # this function -   defp create(conn, %{"user" => user_params}, info)
    case(Accounts.find_or_create_oauth_user(auth, provider)) do
      {:ok, user} ->
        conn
        |> put_flash(:info, "Logged in successfully")
        |> UserAuth.log_in_user(user, "session", %{
          "email" => auth.info.email,
          "remember_me" => "true"
        })

      {:error, _changeset} ->
        conn
        |> put_flash(:error, "Failed to authenticate. Please try using other ways.")
        # redirect to main login page with all login options
        |> redirect(to: ~p"/users/log_in")
    end
  end

  def callback(conn, _params) do
    unauthorized_response(conn, "Authentication failed")
  end

  # standard login with email and password - will be called from api likely
  # TODO: needs testing
  def login(conn, %{"email" => email, "password" => password}) do
    case Accounts.get_user_by_email_and_password(email, password) do
      %User{} = user ->
        jwt = Accounts.generate_jwt_for_user(user)

        conn
        |> Guardian.Plug.sign_in(user)
        |> configure_session(renew: true)
        |> success_response(user, jwt)

      nil ->
        unauthorized_response(conn, "Invalid email or password")
    end
  end

  # TODO: needs testing
  def logout(conn, _params) do
    token =
      get_req_header(conn, "authorization")
      |> List.first()
      |> String.replace("Bearer ", "")

    Accounts.revoke_jwt(token)

    conn
    |> put_status(:ok)
    |> json(%{message: "Logged out"})
  end

  defp success_response(conn, user, jwt) do
    conn
    |> put_status(:ok)
    |> json(%{token: jwt, user: %{id: user.id, email: user.email, name: user.name}})
  end

  defp unauthorized_response(conn, reason) do
    conn
    |> put_status(:unauthorized)
    |> json(%{error: reason})
  end
end

# defp maybe_store_return_to(%{method: "GET"} = conn) do
#   put_session(conn, :user_return_to, current_path(conn))
# end

# |> redirect(to: Routes.page_path(conn, :index))
