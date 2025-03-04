defmodule AuthUbGuWeb.Auth.Token do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn

  alias AuthUbGuWeb.Auth.Shared
  alias AuthUbGu.Accounts
  alias AuthUbGu.Auth.Guardian

  # 7 days in seconds
  @refresh_threshold 7 * 24 * 60 * 60

  @doc """
  just get the access token
  """
  def get_access_token_from_session_or_refresh_token(conn) do
    # get both tokens from the session
    access_token = get_session(conn, :access_token)
    refresh_token = get_refresh_token_from_session_or_cookies(conn)

    # check if the access token is valid
    case Guardian.decode_and_verify(access_token) do
      {:ok, _claims} ->
        {conn, access_token}

      {:error, _reason} ->
        # send the refresh token to get a new access token
        case generate_access_token_from_refresh_token(conn, refresh_token) do
          {conn, nil} ->
            {conn, nil}

          {conn, new_access_token} ->
            # update the access token in the session
            put_access_token_in_session(conn, new_access_token)
            {conn, new_access_token}
        end
    end
  end

  @doc """
  Get the access token from the session or cookies.
  """
  @spec get_refresh_token_from_session_or_cookies(Plug.Conn.t()) :: String.t() | nil
  def get_refresh_token_from_session_or_cookies(conn) do
    if token = get_session(conn, :refresh_token) do
      token
    else
      if token = get_refresh_token_from_cookies(conn) do
        # not starting a new session here as we are just fetching the refresh token
        token
      else
        nil
      end
    end
  end

  def store_refresh_token_in_session_cookies_db(conn, user, refresh_token, params) do
    conn
    |> put_session(:refresh_token, refresh_token)
    |> insert_refresh_token_in_db(user, refresh_token)
    |> Shared.maybe_write_remember_me_cookie(refresh_token, params)
  end

  # inserts the token in the database
  def insert_refresh_token_in_db(conn, user, refresh_token) do
    Accounts.insert_token(user, refresh_token, "refresh")
    conn
  end

  # get the refresh token from the cookies
  @spec get_refresh_token_from_cookies(Plug.Conn.t()) :: String.t() | nil
  defp get_refresh_token_from_cookies(conn) do
    %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()

    conn = fetch_cookies(conn, signed: [remember_me_cookie])
    conn.cookies[remember_me_cookie]
  end

  @doc """
  Put the access token in the session.
  """
  @spec put_access_token_in_session(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def put_access_token_in_session(conn, access_token) do
    live_socket_id = Base.url_encode64(access_token) |> String.slice(0, 16)

    conn
    |> put_session(:access_token, access_token)
    |> put_session(:live_socket_id, "users_sessions:#{live_socket_id}")
  end

  def generate_access_token_from_refresh_token(conn, nil) do
    {conn, nil}
  end

  def generate_access_token_from_refresh_token(conn, refresh_token) do
    case Guardian.decode_and_verify(refresh_token, %{"typ" => "refresh"}) do
      {:ok, claims} ->
        validate_refresh_token_and_regenerate_refresh_token(conn, claims, refresh_token)

      _ ->
        Accounts.delete_user_token(refresh_token, "refresh")
        {conn, nil}
    end
  end

  def validate_refresh_token_and_regenerate_refresh_token(conn, claims, refresh_token) do
    user = Accounts.get_user!(claims["sub"])

    if Accounts.is_token_valid(refresh_token, "refresh") do
      # generate a new access token
      new_access_token = generate_access_token(user)

      # Check if refresh token is nearing expiry
      if nearing_expiry?(claims) do
        # regenerate a new refresh token and store it in the session, cookies & db
        conn = regenerate_refresh_token_and_store(conn, user, refresh_token)
        {conn, new_access_token}
      else
        {conn, new_access_token}
      end
    else
      Accounts.delete_user_token(refresh_token, "refresh")
      {conn, nil}
    end
  end

  defp nearing_expiry?(%{"exp" => exp}) do
    exp - :os.system_time(:second) < @refresh_threshold
  end

  def regenerate_refresh_token_and_store(conn, user, refresh_token) do
    new_refresh_token = generate_refresh_token(user)
    Accounts.delete_user_token(refresh_token, "refresh")
    store_refresh_token_in_session_cookies_db(conn, user, new_refresh_token, %{})
  end

  def generate_access_token(user) do
    %{access: %{guardian: access_ttl}} = Shared.get_ttl_settings()

    {:ok, access_token, _} =
      Guardian.encode_and_sign(user, %{}, token_type: "access", ttl: access_ttl)

    access_token
  end

  def generate_refresh_token(user) do
    %{refresh: %{guardian: refresh_ttl}} = Shared.get_ttl_settings()

    {:ok, refresh_token, _} =
      Guardian.encode_and_sign(user, %{}, token_type: "refresh", ttl: refresh_ttl)

    refresh_token
  end
end
