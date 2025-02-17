defmodule AuthUbGuWeb.Auth.Shared do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn
  import Phoenix.Controller

  @max_age 60 * 60 * 24 * 60
  @remember_me_cookie "_auth_ub_gu_web_user_remember_me"
  @remember_me_options [sign: true, max_age: @max_age, same_site: "Lax"]

  def get_access_cookie_settings do
    %{
      max_age: @max_age,
      remember_me_cookie: @remember_me_cookie,
      remember_me_options: @remember_me_options
    }
  end

  # This function renews the session ID and erases the whole
  # session to avoid fixation attacks. If there is any data
  # in the session you may want to preserve after log in/log out,
  # you must explicitly fetch the session data before clearing
  # and then immediately set it after clearing, for example:
  #
  #     defp renew_session(conn) do
  #       preferred_locale = get_session(conn, :preferred_locale)
  #
  #       conn
  #       |> configure_session(renew: true)
  #       |> clear_session()
  #       |> put_session(:preferred_locale, preferred_locale)
  #     end
  #
  def renew_session(conn) do
    delete_csrf_token()

    conn
    |> configure_session(renew: true)
    |> clear_session()
  end

  def put_token_in_session(conn, token) do
    live_socket_id = Base.url_encode64(token) |> String.slice(0, 16)

    conn
    # |> put_session(Accounts.get_auth_token_name(), token)
    # |> Guardian.Plug.put_session_token(token)
    |> put_session(:live_socket_id, "users_sessions:#{live_socket_id}")
  end

  def maybe_store_return_to(%{method: "GET"} = conn) do
    put_session(conn, :user_return_to, current_path(conn))
  end

  def maybe_store_return_to(conn), do: conn

  def signed_in_path(_conn), do: ~p"/"
end
