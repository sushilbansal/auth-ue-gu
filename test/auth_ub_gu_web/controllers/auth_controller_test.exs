defmodule AuthUbGuWeb.AuthControllerTest do
  use AuthUbGuWeb.ConnCase, async: true

  import Plug.Conn
  import Phoenix.ConnTest

  alias AuthUbGuWeb.Auth.Shared

  @provider "google"

  setup do
    # Mock authentication data
    auth = %Ueberauth.Auth{
      provider: String.to_atom(@provider),
      uid: "123",
      info: %Ueberauth.Auth.Info{
        email: "test@example.com",
        name: "Test User"
      },
      credentials: %Ueberauth.Auth.Credentials{
        token: "valid_token"
      }
    }

    {:ok, auth: auth}
  end

  describe "request/2" do
    test "redirects to the provider's login page", %{conn: conn} do
      conn = get(conn, ~p"/auth/#{@provider}")
      assert redirected_to(conn, 302)
      assert redirected_to(conn) =~ "https://accounts.google.com/o/oauth2/v2/auth"
    end
  end

  describe "callback/2" do
    test "create user from google information", %{conn: conn, auth: auth} do
      conn =
        conn
        |> assign(:ueberauth_auth, auth)
        |> get(~p"/auth/#{@provider}/callback")

      %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()

      assert get_session(conn, :access_token)
      assert get_session(conn, :refresh_token)
      assert conn.resp_cookies[remember_me_cookie]
      assert Phoenix.Flash.get(conn.assigns.flash, :info) == "Logged in successfully"
      assert redirected_to(conn) == ~p"/"

      # Now do a logged in request and assert on the menu
      # conn = get(conn, ~p"/")
      # response = html_response(conn, 200)
      # assert response =~ auth.info.email
    end

    test "handles authentication failure gracefully", %{conn: conn} do
      conn =
        conn
        |> get(~p"/auth/#{@provider}/callback")

      assert Phoenix.Flash.get(conn.assigns.flash, :error) == "Authentication failed"
      assert redirected_to(conn, 401) == ~p"/users/log_in"
    end
  end

  # describe "callback/2" do
  #   test "logs in the user successfully", %{conn: conn, auth: auth} do
  #     # Mock the Accounts.find_or_create_oauth_user/2 function
  #     Accounts
  #     |> expect(:find_or_create_oauth_user, fn _, _ -> {:ok, @valid_user} end)

  #     # Mock token generation and session handling
  #     Token
  #     |> expect(:generate_access_token, fn _ -> "access_token" end)
  #     |> expect(:generate_refresh_token, fn _ -> "refresh_token" end)
  #     |> expect(:put_access_token_in_session, fn conn, _ -> conn end)
  #     |> expect(:store_refresh_token_in_session_cookies_db, fn conn, _, _, _ -> conn end)

  #     Shared
  #     |> expect(:renew_session, fn conn -> conn end)

  #     conn =
  #       conn
  #       |> assign(:ueberauth_auth, auth)
  #       |> get(~p"/auth/#{@provider}/callback")

  #     assert get_flash(conn, :info) == "Logged in successfully"
  #     assert redirected_to(conn) == ~p"/"
  #   end

  #   test "handles authentication failure gracefully", %{conn: conn} do
  #     conn =
  #       conn
  #       |> assign(:ueberauth_auth, %Ueberauth.Auth{})
  #       |> get(~p"/auth/invalid_provider/callback")

  #     assert get_flash(conn, :error) == "Failed to authenticate. Please try using other ways."
  #     assert redirected_to(conn) == ~p"/users/log_in"
  #   end

  #   test "handles invalid authentication data", %{conn: conn} do
  #     Accounts
  #     |> expect(:find_or_create_oauth_user, fn _, _ -> {:error, :invalid_data} end)

  #     conn =
  #       conn
  #       |> assign(:ueberauth_auth, %Ueberauth.Auth{provider: :google})
  #       |> get(~p"/auth/google/callback")

  #     assert get_flash(conn, :error) == "Failed to authenticate. Please try using other ways."
  #     assert redirected_to(conn) == ~p"/users/log_in"
  #   end
  # end

  # describe "unauthorized response" do
  #   test "returns 401 for failed authentication", %{conn: conn} do
  #     conn = get(conn, ~p"/auth/invalid_provider/callback")
  #     assert conn.status == 401
  #     assert json_response(conn, 401)["error"] == "Authentication failed"
  #   end
  # end
end
