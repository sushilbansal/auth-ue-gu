defmodule AuthUbGuWeb.Auth.LoginTest do
  use AuthUbGuWeb.ConnCase, async: true

  import Plug.Conn
  import Phoenix.ConnTest

  alias AuthUbGuWeb.Auth.Login
  alias AuthUbGuWeb.Auth.Logout
  alias AuthUbGuWeb.Auth.Token
  alias AuthUbGuWeb.Auth.Shared
  alias AuthUbGu.Accounts

  import AuthUbGu.AccountsFixtures

  setup %{conn: conn} do
    conn =
      conn
      |> Map.replace!(:secret_key_base, AuthUbGuWeb.Endpoint.config(:secret_key_base))
      |> init_test_session(%{})

    %{user: user_fixture(), conn: conn}
  end

  describe "log_in_user/3" do
    test "stores the access  in the session", %{conn: conn, user: user} do
      conn = Login.log_in_user(conn, user)

      assert token = get_session(conn, :access_token)

      assert get_session(conn, :live_socket_id) ==
               Token.generate_live_socket_id_from_access_token(token)

      assert redirected_to(conn) == ~p"/"
    end

    test "stores the refresh token in the session and db", %{conn: conn, user: user} do
      conn = Login.log_in_user(conn, user)

      assert refresh_token = get_session(conn, :refresh_token)
      assert Accounts.is_token_valid(refresh_token, "refresh") == true
    end

    test "writes a cookie for the refresh token", %{conn: conn, user: user} do
      conn =
        conn
        |> fetch_cookies()
        |> Login.log_in_user(user, %{"remember_me" => "true"})

      %{remember_me_cookie: remember_me_cookie, max_age: max_age} =
        Shared.get_access_cookie_settings()

      assert get_session(conn, :refresh_token) == conn.cookies[remember_me_cookie]

      assert %{value: signed_token, max_age: max_age_real} = conn.resp_cookies[remember_me_cookie]
      assert signed_token != get_session(conn, :refresh_token)
      assert max_age == max_age_real
    end

    test "clears everything previously stored in the session", %{conn: conn, user: user} do
      conn = conn |> put_session(:to_be_cleared, "value") |> Login.log_in_user(user)
      refute get_session(conn, :to_be_cleared)
    end

    test "redirects to the configured path", %{conn: conn, user: user} do
      conn = conn |> put_session(:user_return_to, "/some_path") |> Login.log_in_user(user)
      assert redirected_to(conn) == "/some_path"
    end
  end
end
