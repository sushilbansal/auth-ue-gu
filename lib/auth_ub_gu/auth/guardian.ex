defmodule AuthUbGu.Auth.Guardian do
  use Guardian, otp_app: :auth_ub_gu

  alias AuthUbGu.Accounts.User
  alias AuthUbGu.Accounts

  # @access_token_ttl {15, :minute}
  # @refresh_token_ttl {7, :day}

  # Required by Guardian: Assigns a unique ID for the token
  def subject_for_token(%User{id: id}, _claims) do
    {:ok, to_string(id)}
  end

  # Fetch user from jwt claims
  def resource_from_claims(%{"sub" => id}) do
    case Accounts.get_user!(id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  def on_refresh(old_token_and_claims, new_token_and_claims, _options) do
    {:ok, old_token_and_claims, new_token_and_claims}
  end

  @doc """
  Generate both Access & Refresh tokens for the user
  """
  def generate_all_tokens(user) do
    {:ok, access_token, _} = encode_and_sign(user, %{})
    {:ok, refresh_token} = generate_refresh_token(user)
    {:ok, %{access: access_token, refresh: refresh_token}}
  end

  defp generate_refresh_token(user) do
    refresh_token = :crypto.strong_rand_bytes(32) |> Base.encode64()
    Accounts.generate_user_session_token(user, refresh_token, "refresh")

    {:ok, refresh_token}
  end

  def refresh_all_token(refresh_token) do
    case Accounts.get_user_by_session_token(refresh_token, "refresh",
           validity: 7,
           interval: "day"
         ) do
      nil -> {:error, :invalid_refresh_token}
      user -> generate_all_tokens(user)
    end
  end
end
