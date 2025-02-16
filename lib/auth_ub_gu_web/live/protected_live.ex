defmodule AuthUbGuWeb.ProtectedLive do
  use AuthUbGuWeb, :live_view

  @impl true
  def mount(_params, _session, %{assigns: %{current_user: user}} = socket) do
    {:ok, assign(socket, :user, user)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div>
      <h1>Welcome {@user.email}! to the protected route</h1>
    </div>
    """
  end
end
