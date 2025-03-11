defmodule AuthUbGu.AuthFixtures do
  @provider "google"

  @valid_auth %Ueberauth.Auth{
    provider: String.to_atom(@provider),
    uid: Faker.UUID.v4(),
    info: %Ueberauth.Auth.Info{
      email: Faker.Internet.email(),
      name: Faker.Person.name()
    },
    credentials: %Ueberauth.Auth.Credentials{
      token: Faker.Lorem.characters(10..50)
    }
  }

  def valid_auth_attributes(attrs \\ %{}) do
    Map.merge(attrs, @valid_auth)
  end
end
