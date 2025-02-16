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

  def refresh(conn, %{"refresh_token" => refresh_token}) do
    # Guardian.Plug.find_token_from_cookies()

    case Guardian.refresh_all_token(refresh_token) do
      {:ok, tokens} ->
        conn
        |> put_status(:ok)
        |> json(tokens)

      {:error, _reason} ->
        unauthorized_response(
          conn,
          "Invalid refresh token. Please log in again."
        )
    end
  end

  # how to refresh token in the frontend - example in JS
  # fetch("/api/refresh", {
  #   method: "POST",
  #   headers: { "Content-Type": "application/json" },
  #   body: JSON.stringify({ refresh_token: storedRefreshToken }),
  # })
  #   .then(res => res.json())
  #   .then(data => {
  #     localStorage.setItem("access_token", data.access);
  #     localStorage.setItem("refresh_token", data.refresh);
  #   })
  #   .catch(err => console.error("Refresh failed", err));

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

# test "GET /auth/me", %{conn: conn} do
#   user = insert(:user) # See https://github.com/thoughtbot/ex_machina

#   {:ok, token, _} = encode_and_sign(user, %{}, token_type: :access)

#   conn = conn
#   |> put_req_header("authorization", "Bearer " <> token)
#   |> get(auth_path(conn, :me))

#   # Assert things here
# end
