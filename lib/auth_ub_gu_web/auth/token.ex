defmodule AuthUbGuWeb.Auth.Token do
  use AuthUbGuWeb, :verified_routes

  import Plug.Conn

  alias AuthUbGuWeb.Auth.Shared
  alias AuthUbGu.Accounts
  alias AuthUbGu.Auth.Guardian

  # 7 days in seconds
  # @refresh_threshold 7 * 24 * 60 * 60

  # if the refresh token is expiring in 60 mins,
  # then expiry will be tested for validity in 60 mins - @refresh_threshold (45 mins) i.e. in 15 mins
  @refresh_threshold_from_end 45 * 60

  @doc """
  Get the access token from the session or refresh token.
  """
  @spec get_access_token_from_session_or_refresh_token(Plug.Conn.t()) ::
          {Plug.Conn.t(), String.t() | nil}
  def get_access_token_from_session_or_refresh_token(conn) do
    access_token = get_session(conn, :access_token)

    case Guardian.decode_and_verify(access_token) do
      {:ok, _claims} ->
        {conn, access_token}

      _ ->
        {refresh_token, conn} = get_refresh_token_from_session_or_cookies(conn)

        case generate_access_token_from_refresh_token(conn, refresh_token) do
          {conn, nil} ->
            {conn, nil}

          {conn, new_access_token} ->
            {put_access_token_in_session(conn, new_access_token), new_access_token}
        end
    end
  end

  @doc """
  Get the access token from the session or cookies.
  """
  @spec get_refresh_token_from_session_or_cookies(Plug.Conn.t()) ::
          {String.t() | nil, Plug.Conn.t()}
  def get_refresh_token_from_session_or_cookies(conn) do
    with {nil, conn} <- get_refresh_token_from_session(conn),
         {nil, conn} <- get_refresh_token_from_cookies(conn) do
      {nil, conn}
    else
      {token, conn} -> {token, conn}
    end
  end

  def generate_access_token_from_refresh_token(conn, nil) do
    {conn, nil}
  end

  @doc """
  Generate a new access token from the refresh token.
  if the refresh token is nearing expiry, regenerate it and store it in the session, cookies and database.
  else if the refresh token is invalid, delete it from the database
  """
  @spec generate_access_token_from_refresh_token(Plug.Conn.t(), String.t()) ::
          {Plug.Conn.t(), String.t()} | {Plug.Conn.t(), nil}
  def generate_access_token_from_refresh_token(conn, refresh_token) do
    with {:ok, claims} <- Guardian.decode_and_verify(refresh_token, %{"typ" => "refresh"}),
         # check if the refresh token is valid in the database.
         true <- Accounts.is_token_valid(refresh_token, "refresh"),
         user <- Accounts.get_user!(claims["sub"]) do
      conn =
        if nearing_expiry?(claims) do
          regenerate_refresh_token_and_store(conn, user, refresh_token)
        else
          conn
        end

      {conn, generate_access_token(user)}
    else
      _ -> {conn, nil}
    end
  end

  defp nearing_expiry?(%{"exp" => exp}) do
    exp - :os.system_time(:second) < @refresh_threshold_from_end
  end

  @doc """
  Regenerate the refresh token and store it in the session, cookies and database.
  """
  @spec regenerate_refresh_token_and_store(Plug.Conn.t(), Accounts.User.t(), String.t()) ::
          Plug.Conn.t()
  def regenerate_refresh_token_and_store(conn, user, refresh_token) do
    # delete the old refresh token which has expired or nearing expiry
    Accounts.delete_user_token(refresh_token, "refresh")
    new_refresh_token = generate_refresh_token(user)

    store_refresh_token_in_session_cookies_db(conn, user, new_refresh_token, %{
      "remember_me" => "true"
    })
  end

  @spec get_refresh_token_from_session(Plug.Conn.t()) :: {String.t() | nil, Plug.Conn.t()}
  def get_refresh_token_from_session(conn) do
    {get_session(conn, :refresh_token), conn}
  end

  # get the refresh token from the cookies and store it in the session
  @spec get_refresh_token_from_cookies(Plug.Conn.t()) :: {String.t() | nil, Plug.Conn.t()}
  def get_refresh_token_from_cookies(conn) do
    %{remember_me_cookie: remember_me_cookie} = Shared.get_access_cookie_settings()

    conn = fetch_cookies(conn, signed: [remember_me_cookie])

    if token = conn.cookies[remember_me_cookie] do
      {token, put_session(conn, :refresh_token, token)}
    else
      {nil, conn}
    end
  end

  @doc """
  Store the refresh token in the session, cookies and database.
  """
  @spec store_refresh_token_in_session_cookies_db(
          Plug.Conn.t(),
          Accounts.User.t(),
          String.t(),
          map()
        ) ::
          Plug.Conn.t()
  def store_refresh_token_in_session_cookies_db(conn, user, refresh_token, params) do
    conn
    |> put_session(:refresh_token, refresh_token)
    |> insert_refresh_token_in_db(user, refresh_token)
    |> Shared.maybe_write_remember_me_cookie(refresh_token, params)
  end

  @doc """
  Insert the refresh token in the database.
  """
  @spec insert_refresh_token_in_db(Plug.Conn.t(), Accounts.User.t(), String.t()) ::
          Plug.Conn.t()
  def insert_refresh_token_in_db(conn, user, refresh_token) do
    # TODO: need to get the device info from the request headers
    # and store it in the user token table
    Accounts.insert_token(user, refresh_token, "refresh")
    conn
  end

  @doc """
  Put the access token in the session.
  """
  @spec put_access_token_in_session(Plug.Conn.t(), String.t()) :: Plug.Conn.t()
  def put_access_token_in_session(conn, access_token) do
    conn
    |> put_session(:access_token, access_token)
    |> put_session(:live_socket_id, generate_live_socket_id_from_access_token(access_token))
  end

  def generate_live_socket_id_from_access_token(access_token) do
    "users_sessions:#{String.slice(access_token, 0, 16)}"
  end

  @doc """
  Generate an access token.
  """
  @spec generate_access_token(Accounts.User.t(), list()) :: String.t()
  def generate_access_token(user, opts \\ []) do
    access_ttl = Keyword.get(opts, :access_ttl, Shared.get_ttl_settings().access.guardian)

    {:ok, access_token, _} =
      Guardian.encode_and_sign(user, %{}, token_type: "access", ttl: access_ttl)

    access_token
  end

  @doc """
  Generate a refresh token.
  """
  @spec generate_refresh_token(Accounts.User.t(), list()) :: String.t()
  def generate_refresh_token(user, opts \\ []) do
    refresh_ttl = Keyword.get(opts, :refresh_ttl, Shared.get_ttl_settings().refresh.guardian)

    {:ok, refresh_token, _} =
      Guardian.encode_and_sign(user, %{}, token_type: "refresh", ttl: refresh_ttl)

    refresh_token
  end
end
