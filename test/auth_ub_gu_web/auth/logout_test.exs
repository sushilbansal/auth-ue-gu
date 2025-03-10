defmodule AuthUbGuWeb.Auth.LogoutTest do
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

  describe "logout_user/2" do
    test "erases session and cookies", %{conn: conn, user: user} do
      %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()

      conn =
        conn
        |> fetch_cookies()
        |> Login.log_in_user(user, %{"remember_me" => "true", "redirect_after_login" => "false"})

      refresh_token = get_session(conn, :refresh_token)

      conn = conn |> Logout.log_out_user()

      refute get_session(conn, :access_token)
      refute get_session(conn, :refresh_token)

      refute conn.cookies[remember_me_cookie]
      assert %{max_age: 0} = conn.resp_cookies[remember_me_cookie]

      assert redirected_to(conn) == ~p"/"
      refute Accounts.is_token_valid(refresh_token, "refresh")
    end

    test "broadcasts to the given live_socket_id", %{conn: conn} do
      live_socket_id = "users_sessions:abcdef-token"
      AuthUbGuWeb.Endpoint.subscribe(live_socket_id)

      conn
      |> put_session(:live_socket_id, live_socket_id)
      |> Logout.log_out_user()

      assert_receive %Phoenix.Socket.Broadcast{event: "disconnect", topic: ^live_socket_id}
    end

    test "works even if user is already logged out", %{conn: conn} do
      %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()

      conn = conn |> fetch_cookies() |> Logout.log_out_user()

      refute get_session(conn, :access_token)
      assert %{max_age: 0} = conn.resp_cookies[remember_me_cookie]
      assert redirected_to(conn) == ~p"/"
    end
  end
end
