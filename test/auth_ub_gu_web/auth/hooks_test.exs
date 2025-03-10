defmodule AuthUbGuWeb.Auth.HooksTest do
  use AuthUbGuWeb.ConnCase, async: true

  import Plug.Conn
  import Phoenix.ConnTest
  import AuthUbGu.AccountsFixtures

  alias Phoenix.LiveView
  alias AuthUbGuWeb.Auth.Shared
  alias AuthUbGuWeb.Auth.Login
  alias AuthUbGuWeb.Auth.Token
  alias AuthUbGuWeb.Auth.Hooks

  @provider "google"

  setup %{conn: conn} do
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

    conn =
      conn
      |> Map.replace!(:secret_key_base, AuthUbGuWeb.Endpoint.config(:secret_key_base))
      |> init_test_session(%{})

    {:ok, auth: auth, conn: conn, user: user_fixture()}
  end

  describe "fetch_current_user/2" do
    test "auth and fetch the user", %{conn: conn, auth: auth} do
      conn =
        conn
        |> assign(:ueberauth_auth, auth)
        |> get(~p"/auth/#{@provider}/callback")

      conn = conn |> Hooks.fetch_current_user([])

      assert conn.assigns.current_user.provider_uid == auth.uid
      assert conn.assigns.current_user.email == auth.info.email
    end

    test "authenticates user from access token in session", %{conn: conn, user: user} do
      access_token = Token.generate_access_token(user)
      conn = conn |> put_session(:access_token, access_token) |> Hooks.fetch_current_user([])
      assert conn.assigns.current_user.id == user.id
    end

    test "authenticates user from refresh token in session", %{conn: conn, user: user} do
      refresh_token = Token.generate_refresh_token(user)

      conn =
        conn
        |> put_session(:refresh_token, refresh_token)
        |> Token.insert_refresh_token_in_db(user, refresh_token)
        |> Hooks.fetch_current_user([])

      assert conn.assigns.current_user.id == user.id
    end

    test "authenticates user from cookies", %{conn: conn, user: user} do
      %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()

      logged_in_conn =
        conn
        |> fetch_cookies()
        |> Login.log_in_user(user, %{"remember_me" => "true", "redirect_after_login" => "false"})

      refresh_token = logged_in_conn.cookies[remember_me_cookie]
      %{value: signed_token} = logged_in_conn.resp_cookies[remember_me_cookie]

      conn =
        conn
        |> put_req_cookie(remember_me_cookie, signed_token)
        |> Hooks.fetch_current_user([])

      assert conn.assigns.current_user.id == user.id
      assert get_session(conn, :refresh_token) == refresh_token

      access_token = get_session(conn, :access_token)

      assert get_session(conn, :live_socket_id) ==
               Token.generate_live_socket_id_from_access_token(access_token)
    end

    test "does not authenticate if data is missing", %{conn: conn, user: user} do
      Token.generate_refresh_token(user)
      conn = Hooks.fetch_current_user(conn, [])

      refute get_session(conn, :refresh_token)
      refute conn.assigns.current_user
    end
  end

  describe "on_mount: mount_current_user" do
    test "assigns current_user based on valid access token", %{conn: conn, user: user} do
      access_token = Token.generate_access_token(user)
      session = conn |> put_session(:access_token, access_token) |> get_session()

      {:cont, updated_socket} =
        Hooks.on_mount(:mount_current_user, %{}, session, %LiveView.Socket{})

      assert updated_socket.assigns.current_user.id == user.id
    end

    test "assigns nil to current_user if there isn't a valid access_token", %{conn: conn} do
      access_token = "invalid_token"
      session = conn |> put_session(:access_token, access_token) |> get_session()

      {:cont, updated_socket} =
        Hooks.on_mount(:mount_current_user, %{}, session, %LiveView.Socket{})

      assert updated_socket.assigns.current_user == nil
    end

    test "assigns nil to current_user if there isn't an access_token", %{conn: conn} do
      session = conn |> get_session()

      {:cont, updated_socket} =
        Hooks.on_mount(:mount_current_user, %{}, session, %LiveView.Socket{})

      assert updated_socket.assigns.current_user == nil
    end
  end

  describe "on_mount: ensure_authenticated" do
    test "authenticates current_user based on valid access_token", %{conn: conn, user: user} do
      access_token = Token.generate_access_token(user)
      session = conn |> put_session(:access_token, access_token) |> get_session()

      {:cont, updated_socket} =
        Hooks.on_mount(:ensure_authenticated, %{}, session, %LiveView.Socket{})

      assert updated_socket.assigns.current_user.id == user.id
    end

    test "redirects to login page if there isn't a valid access_token", %{conn: conn} do
      access_token = "invalid_token"
      session = conn |> put_session(:access_token, access_token) |> get_session()

      socket = %LiveView.Socket{
        endpoint: AuthUbGuWeb.Endpoint,
        assigns: %{__changed__: %{}, flash: %{}}
      }

      {:halt, updated_socket} =
        Hooks.on_mount(:ensure_authenticated, %{}, session, socket)

      assert updated_socket.assigns.current_user == nil
    end

    test "redirects to login page if there isn't a user_token", %{conn: conn} do
      session = conn |> get_session()

      socket = %LiveView.Socket{
        endpoint: AuthUbGuWeb.Endpoint,
        assigns: %{__changed__: %{}, flash: %{}}
      }

      {:halt, updated_socket} =
        Hooks.on_mount(:ensure_authenticated, %{}, session, socket)

      assert updated_socket.assigns.current_user == nil
    end
  end

  describe "on_mount: :redirect_if_user_is_authenticated" do
    test "redirects if there is an authenticated user", %{conn: conn, user: user} do
      access_token = Token.generate_access_token(user)
      session = conn |> put_session(:access_token, access_token) |> get_session()

      assert {:halt, _updated_socket} =
               Hooks.on_mount(
                 :redirect_if_user_is_authenticated,
                 %{},
                 session,
                 %LiveView.Socket{}
               )
    end

    test "does not redirect if there is no authenticated user", %{conn: conn} do
      session = conn |> get_session()

      assert {:cont, _updated_socket} =
               Hooks.on_mount(
                 :redirect_if_user_is_authenticated,
                 %{},
                 session,
                 %LiveView.Socket{}
               )
    end
  end

  describe "require_authenticated_user/2" do
    test "redirects if user is not authenticated", %{conn: conn} do
      conn = conn |> fetch_flash() |> Hooks.require_authenticated_user([])
      assert conn.halted

      assert redirected_to(conn) == ~p"/users/log_in"

      assert Phoenix.Flash.get(conn.assigns.flash, :error) ==
               "You must log in to access this page."
    end

    test "stores the path to redirect to on GET", %{conn: conn} do
      halted_conn =
        %{conn | path_info: ["foo"], query_string: ""}
        |> fetch_flash()
        |> Hooks.require_authenticated_user([])

      assert halted_conn.halted
      assert get_session(halted_conn, :user_return_to) == "/foo"

      halted_conn =
        %{conn | path_info: ["foo"], query_string: "bar=baz"}
        |> fetch_flash()
        |> Hooks.require_authenticated_user([])

      assert halted_conn.halted
      assert get_session(halted_conn, :user_return_to) == "/foo?bar=baz"

      halted_conn =
        %{conn | path_info: ["foo"], query_string: "bar", method: "POST"}
        |> fetch_flash()
        |> Hooks.require_authenticated_user([])

      assert halted_conn.halted
      refute get_session(halted_conn, :user_return_to)
    end

    test "does not redirect if user is authenticated", %{conn: conn, user: user} do
      conn = conn |> assign(:current_user, user) |> Hooks.require_authenticated_user([])

      refute conn.halted
      refute conn.status
    end
  end
end
