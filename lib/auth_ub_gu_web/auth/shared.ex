defmodule AuthUbGuWeb.Auth.Shared do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller

  @doc """
  Get the access cookie settings.
  """
  @spec get_access_cookie_settings() :: map()
  def get_access_cookie_settings do
    max_age = 60 * 60 * 24 * 60

    %{
      max_age: max_age,
      remember_me_cookie: "_auth_ub_gu_web_user_remember_me",
      remember_me_options: [
        sign: true,
        max_age: max_age,
        same_site: "Lax",
        http_only: true,
        secure: true
      ]
    }
  end

  @doc """
  Get the guardian TTL settings.
  """
  @spec get_ttl_settings() :: map()
  def get_ttl_settings do
    # for db - can't use plurals like minutes, days etc
    %{
      access: %{
        db: {5, "minute"},
        guardian: {5, :minutes}
      },
      refresh: %{
        db: {60, "minute"},
        guardian: {60, :minutes}
      }
    }
  end

  @doc """
  This function renews the session ID and erases the whole
  session to avoid fixation attacks. If there is any data
  in the session you may want to preserve after log in/log out,
  you must explicitly fetch the session data before clearing
  and then immediately set it after clearing, for example:

      defp renew_session(conn) do
        preferred_locale = get_session(conn, :preferred_locale)

        conn
        |> configure_session(renew: true)
        |> clear_session()
        |> put_session(:preferred_locale, preferred_locale)
      end
  """
  @spec renew_session(Plug.Conn.t()) :: Plug.Conn.t()
  def renew_session(conn) do
    delete_csrf_token()

    conn
    |> configure_session(renew: true)
    |> clear_session()
  end

  @spec maybe_write_remember_me_cookie(Plug.Conn.t(), String.t(), map()) :: Plug.Conn.t()
  def maybe_write_remember_me_cookie(conn, refresh_token, %{"remember_me" => "true"}) do
    %{remember_me_cookie: remember_me_cookie, remember_me_options: remember_me_options} =
      get_access_cookie_settings()

    put_resp_cookie(
      conn,
      remember_me_cookie,
      refresh_token,
      remember_me_options
    )
  end

  def maybe_write_remember_me_cookie(conn, _refresh_token, _params) do
    conn
  end

  @doc """
  Maybe store the return to path in the session.
  """
  @spec maybe_store_return_to(Plug.Conn.t()) :: Plug.Conn.t()
  def maybe_store_return_to(%{method: "GET"} = conn) do
    put_session(conn, :user_return_to, current_path(conn))
  end

  def maybe_store_return_to(conn), do: conn

  @doc """
  Get the return path after sign in.
  """
  def signed_in_path(_conn), do: ~p"/"
end
