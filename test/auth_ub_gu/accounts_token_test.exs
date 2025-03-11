defmodule AuthUbGu.AccountsTokenTest do
  alias AuthUbGuWeb.Auth.Token
  use AuthUbGu.DataCase, async: true

  alias AuthUbGu.Accounts

  import AuthUbGu.AccountsFixtures
  import AuthUbGu.AuthFixtures

  alias AuthUbGu.Accounts.{UserToken}

  describe "insert_token/3" do
    setup do
      %{user: user_fixture()}
    end

    test "inserts a refresh token in the user token table", %{user: user} do
      refresh_token = Token.generate_refresh_token(user)
      # while saving the token, we hash it before saving
      Accounts.insert_token(user, refresh_token, "refresh")

      hashed_token = UserToken.hash_token(refresh_token)
      assert user_token = Repo.get_by(UserToken, token: hashed_token)
      assert user_token.context == "refresh"

      # Creating the same token for another user should fail
      assert_raise Ecto.ConstraintError, fn ->
        Repo.insert!(%UserToken{
          token: user_token.token,
          user_id: user_fixture().id,
          context: "refresh"
        })
      end
    end
  end

  describe "delete_user_token/1" do
    test "deletes the token" do
      user = user_fixture()
      refresh_token = Token.generate_refresh_token(user)
      Accounts.insert_token(user, refresh_token, "refresh")

      assert Accounts.delete_user_token(refresh_token, "refresh") == :ok
      refute Accounts.is_token_valid(refresh_token, "refresh")
    end
  end

  describe "is_token_valid/2" do
    setup do
      user = user_fixture()
      refresh_token = Token.generate_refresh_token(user)
      Accounts.insert_token(user, refresh_token, "refresh")
      %{user: user, refresh_token: refresh_token}
    end

    test "returns true if token is valid and exists in the db", %{
      refresh_token: refresh_token
    } do
      assert Accounts.is_token_valid(refresh_token, "refresh")
    end

    test "returns true for invalid token" do
      refute Accounts.is_token_valid("oops", "refresh")
    end

    # test "does not return user for expired token", %{token: token} do
    #   {1, nil} = Repo.update_all(UserToken, set: [inserted_at: ~N[2020-01-01 00:00:00]])
    #   refute Accounts.get_user_by_session_token(token)
    # end
  end

  describe "find_or_create_oauth_user/2" do
    test "no existing user with the same email" do
      auth_attrs = valid_auth_attributes()
      assert Accounts.get_user_by_email(auth_attrs.info.email) == nil
      Accounts.find_or_create_oauth_user(auth_attrs, "google")

      assert user = Accounts.get_user_by_email(auth_attrs.info.email)
      assert user.provider == "google"
      assert user.provider_uid == auth_attrs.uid
    end

    test "existing user with the same email but no provider and provider_uid" do
      user = user_fixture()
      assert user = Accounts.get_user_by_email(user.email)
      refute user.provider
      refute user.provider_uid

      # use the same email to create a user with provider and provider_uid
      auth_attrs =
        valid_auth_attributes(%{
          info: %Ueberauth.Auth.Info{
            email: user.email,
            name: user.name
          }
        })

      Accounts.find_or_create_oauth_user(auth_attrs, "google")
      assert user = Accounts.get_user_by_email(auth_attrs.info.email)

      assert user.provider == "google"
      assert user.provider_uid == auth_attrs.uid
    end

    test "existing user with the same email and provider and provider_uid" do
      auth_attrs = valid_auth_attributes()
      assert Accounts.get_user_by_email(auth_attrs.info.email) == nil
      Accounts.find_or_create_oauth_user(auth_attrs, "google")

      assert user = Accounts.get_user_by_email(auth_attrs.info.email)
      assert user.provider == "google"
      assert user.provider_uid == auth_attrs.uid

      # Trying to create the same user again; this should not create a new user
      Accounts.find_or_create_oauth_user(auth_attrs, "google")
      assert user = Accounts.get_user_by_email(auth_attrs.info.email)
      assert user.provider == "google"
      assert user.provider_uid == auth_attrs.uid
    end
  end
end
