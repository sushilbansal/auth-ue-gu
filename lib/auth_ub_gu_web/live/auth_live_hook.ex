defmodule AuthUbGuWeb.AuthLiveHook do
  import Phoenix.LiveView
  import Phoenix.Component

  alias AuthUbGu.Auth.Guardian
  alias AuthUbGu.Accounts

  # TODO: we also need a plug to ensure the user is authenticated
  def ensure_authenticated(conn) do
    case Guardian.Plug.current_resource(conn) do
      {:ok, user} ->
        {:ok, assign(conn, :current_user, user)}

      _ ->
        {:ok, assign(conn, :current_user, nil)}
    end
  end

  # |> redirect(to: Routes.user_settings_path(conn, :edit))

  def on_mount(:ensure_authenticated, _params, session, socket) do
    case Map.get(session, Atom.to_string(Accounts.get_auth_token_name())) do
      nil ->
        {:halt, redirect(socket, to: "/login")}

      token ->
        case Guardian.resource_from_token(token) do
          {:ok, user, _claims} ->
            {:cont, assign(socket, :current_user, user)}

          _ ->
            {:halt, redirect(socket, to: "/login")}
        end
    end
  end
end
