defmodule AuthUbGuWeb.Auth.Shared do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller

  @max_age 60 * 60 * 24 * 60
  @remember_me_cookie "_auth_ub_gu_web_user_remember_me"
  @remember_me_options [sign: true, max_age: @max_age, same_site: "Lax"]

  @doc """
  Get the access cookie settings.
  """
  @spec get_access_cookie_settings() :: map()
  def get_access_cookie_settings do
    %{
      max_age: @max_age,
      remember_me_cookie: @remember_me_cookie,
      remember_me_options: @remember_me_options
    }
  end

  @doc """
  Get the guardian TTL settings.
  """
  @spec get_guardian_ttl_settings() :: map()
  def get_guardian_ttl_settings do
    %{
      "access" => {1, :minute},
      "refresh" => {5, :minutes},
      "remember_me" => {30, :minutes}
    }
  end

  @doc """
  Convert the TTL settings to the database format.
  """
  @spec convert_ttl_to_db_format(tuple()) :: list()
  def convert_ttl_to_db_format({validity, interval}) do
    [validity: validity, interval: Atom.to_string(interval)]
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

  @doc """
  Get the access token from the guardian plug or cookies.
  """
  @spec get_access_token(Plug.Conn.t()) :: {String.t() | nil, Plug.Conn.t()}
  def get_access_token(conn) do
    if token = get_access_token_from_guardian(conn) do
      {token, conn}
    else
      if token = get_access_token_from_cookies(conn) do
        {token, put_access_token_in_session(conn, token)}
      else
        {nil, conn}
      end
    end
  end

  @spec get_access_token_from_guardian(Plug.Conn.t()) :: String.t() | nil
  defp get_access_token_from_guardian(conn) do
    Guardian.Plug.current_token(conn)
  end

  # this function is similar to get_access_token_from_guardian
  # as we maintain session through guardian plug
  # defp get_access_token_from_session(conn) do
  #   get_session(conn, Accounts.get_auth_token_name())
  # end
  @spec get_access_token_from_cookies(Plug.Conn.t()) :: String.t() | nil
  defp get_access_token_from_cookies(conn) do
    %{remember_me_cookie: remember_me_cookie} = get_access_cookie_settings()

    conn = fetch_cookies(conn, signed: [remember_me_cookie])
    conn.cookies[remember_me_cookie]
  end

  @doc """
  Put the access token in the session.
  """
  @spec put_access_token_in_session(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def put_access_token_in_session(conn, token) do
    live_socket_id = Base.url_encode64(token) |> String.slice(0, 16)

    conn
    |> put_guardian_session_token(token)
    |> put_session(:live_socket_id, "users_sessions:#{live_socket_id}")
  end

  @spec put_guardian_session_token(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  defp put_guardian_session_token(conn, token) do
    %{"access" => access_ttl} = get_guardian_ttl_settings()

    conn
    |> Guardian.Plug.put_session_token(token, ttl: access_ttl)
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
