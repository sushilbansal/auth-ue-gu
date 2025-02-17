defmodule AuthUbGu.Auth.Guardian do
  use Guardian, otp_app: :auth_ub_gu

  alias AuthUbGu.Accounts.User
  alias AuthUbGu.Accounts

  # revoke jwt token when user logs out
  # TODO: not tested yet
  # def on_revoke(claims, _token, _options) do
  #   Accounts.revoke_jwt(claims["jti"])
  # end

  # Required by Guardian: Assigns a unique ID for the token
  def subject_for_token(%User{id: id}, _claims) do
    {:ok, to_string(id)}
  end

  # Fetch user from jwt claims
  # TODO: not tested yet
  def resource_from_claims(%{"sub" => id}) do
    case Accounts.get_user!(id) do
      nil -> {:error, :not_found}
      user -> {:ok, user}
    end
  end

  def on_revoke(claims, _token, _options) do
    {:ok, claims}
  end

  def on_refresh(old_token_and_claims, new_token_and_claims, _options) do
    {:ok, old_token_and_claims, new_token_and_claims}
  end
end
