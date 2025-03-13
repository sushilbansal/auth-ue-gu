defmodule AuthUbGuWeb.Auth.TokenTest do
  use AuthUbGuWeb.ConnCase, async: true

  import Plug.Conn
  import Phoenix.ConnTest
  import AuthUbGu.AccountsFixtures

  alias AuthUbGu.Accounts
  alias AuthUbGu.Auth.Guardian
  alias AuthUbGuWeb.Auth.Shared
  alias AuthUbGuWeb.Auth.Token

  setup %{conn: conn} do
    conn =
      conn
      |> Map.replace!(:secret_key_base, AuthUbGuWeb.Endpoint.config(:secret_key_base))
      |> init_test_session(%{})

    %{user: user_fixture(), conn: conn}
  end

  describe "" do
  end

  describe "get_access_token_from_session_or_refresh_token/1" do
    test "(C) access token is valid (R) verify the access token is valid", %{
      conn: conn,
      user: user
    } do
      token_ttl = %{
        access: %{
          guardian: {5, :minutes}
        }
      }

      access_token = Token.generate_access_token(user, access_ttl: token_ttl.access.guardian)
      put_session(conn, :access_token, access_token)

      assert {:ok, _claims} = Guardian.decode_and_verify(access_token)
    end

    test "(C) access token is invalid; (R) verify that access token is invalid",
         %{conn: conn, user: user} do
      token_ttl = %{
        access: %{
          guardian: {0.01, :second}
        }
      }

      access_token = Token.generate_access_token(user, access_ttl: token_ttl.access.guardian)
      put_session(conn, :access_token, access_token)

      Process.sleep(2000)
      assert {:error, :token_expired} = Guardian.decode_and_verify(access_token)
    end

    test "(C) access token is invalid; (R) generate the access token from refresh token (in session)",
         %{conn: conn, user: user} do
      token_ttl = %{
        access: %{
          guardian: {0.1, :second}
        },
        refresh: %{
          guardian: {5, :minutes}
        }
      }

      access_token = Token.generate_access_token(user, access_ttl: token_ttl.access.guardian)
      conn = put_session(conn, :access_token, access_token)

      Process.sleep(1000)
      assert {:error, :token_expired} = Guardian.decode_and_verify(access_token)

      # Generate refresh token and store it in session and database
      refresh_token = Token.generate_refresh_token(user, refresh_ttl: token_ttl.refresh.guardian)
      conn = put_session(conn, :refresh_token, refresh_token)
      Accounts.insert_token(user, refresh_token, "refresh")

      # get the refresh token from the session and generate a new access token
      {refresh_token, conn} = Token.get_refresh_token_from_session(conn)

      {_conn, new_access_token} =
        Token.generate_access_token_from_refresh_token(conn, refresh_token)

      assert {:ok, _claims} = Guardian.decode_and_verify(new_access_token)
    end
  end

  describe "get_refresh_token_from_cookies/1" do
    test "(C) valid refresh token stored in cookie (R) same token retrieved from cookies", %{
      conn: conn,
      user: user
    } do
      %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()
      refresh_token = Token.generate_refresh_token(user)

      conn =
        conn
        |> fetch_cookies()
        |> put_resp_cookie(remember_me_cookie, refresh_token)

      {token, _conn} = Token.get_refresh_token_from_cookies(conn)
      assert token == refresh_token
    end
  end

  describe "store_refresh_token_in_session_cookies_db/4" do
    test "(C) store  refresh token in session, cookies & db (R) fetch and verify the token is same",
         %{
           conn: conn,
           user: user
         } do
      %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()
      # Generate refresh token and store it in session and database
      refresh_token = Token.generate_refresh_token(user)

      conn =
        conn
        |> fetch_cookies()
        |> Token.store_refresh_token_in_session_cookies_db(user, refresh_token, %{
          "remember_me" => "true"
        })

      # verify refresh token is stored in the session and cookies
      assert get_session(conn, :refresh_token) == conn.cookies[remember_me_cookie]
      assert %{value: signed_token, max_age: max_age} = conn.resp_cookies[remember_me_cookie]
      assert signed_token != get_session(conn, :refresh_token)
      assert max_age == 5_184_000

      # verify refresh token is valid in the database
      assert Accounts.is_token_valid(refresh_token, "refresh") == true
    end
  end

  describe "regenerate_refresh_token_and_store/3" do
    test "(C) refresh token in session or cookies is expiring or has expired (R) generate a new refresh token and store it",
         %{conn: conn, user: user} do
      %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()

      refresh_token = Token.generate_refresh_token(user)

      conn =
        conn |> fetch_cookies() |> Token.regenerate_refresh_token_and_store(user, refresh_token)

      # token in session and cookies should be the same
      assert get_session(conn, :refresh_token) == conn.cookies[remember_me_cookie]
      refute get_session(conn, :refresh_token) == refresh_token
    end
  end

  describe "generate_access_token_from_refresh_token/2" do
    test "(C) refresh token is valid in session but not in db (R) access token is not generated",
         %{conn: conn, user: user} do
      refresh_token = Token.generate_refresh_token(user)
      conn = put_session(conn, :refresh_token, refresh_token)
      assert {_conn, nil} = Token.generate_access_token_from_refresh_token(conn, refresh_token)
    end

    test "(C) refresh token is valid in session & db (R) access token is generated",
         %{conn: conn, user: user} do
      refresh_token = Token.generate_refresh_token(user)
      conn = put_session(conn, :refresh_token, refresh_token)
      Accounts.insert_token(user, refresh_token, "refresh")

      assert {_conn, new_access_token} =
               Token.generate_access_token_from_refresh_token(conn, refresh_token)

      assert {:ok, _claims} = Guardian.decode_and_verify(new_access_token)
    end

    test "(C) refresh token is valid in session & db but near its expiry (R) both refresh & access token are regenerated",
         %{conn: conn, user: user} do
      token_ttl = %{
        refresh: %{
          guardian: {1, :minute}
        }
      }

      # generate soon expiring refresh token and store it in session and database
      refresh_token = Token.generate_refresh_token(user, refresh_ttl: token_ttl.refresh.guardian)
      conn = put_session(conn, :refresh_token, refresh_token)
      Accounts.insert_token(user, refresh_token, "refresh")

      assert {conn, new_access_token} =
               Token.generate_access_token_from_refresh_token(conn, refresh_token)

      assert {:ok, _claims} = Guardian.decode_and_verify(new_access_token)
      # the old refresh token is replaced with a new one
      refute get_session(conn, :refresh_token) == refresh_token
    end
  end

  describe "get_refresh_token_from_session_or_cookies/1" do
    test "(C) valid refresh token is stored in session (R) same token is retrieved from session",
         %{conn: conn, user: user} do
      refresh_token = Token.generate_refresh_token(user)
      conn = put_session(conn, :refresh_token, refresh_token)

      {token, _conn} = Token.get_refresh_token_from_session_or_cookies(conn)
      assert token == refresh_token
    end

    test "(C) no refresh token in session (R) retrieve refresh token from cookie",
         %{conn: conn, user: user} do
      %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()

      refresh_token = Token.generate_refresh_token(user)

      conn =
        conn
        |> fetch_cookies()
        |> put_resp_cookie(remember_me_cookie, refresh_token)

      {token, _conn} = Token.get_refresh_token_from_session_or_cookies(conn)
      assert token == refresh_token
    end
  end
end
