defmodule AuthUbGuWeb.HomeLive do
  use AuthUbGuWeb, :live_view

  def render(assigns) do
    ~H"""
    <div class="container">
      <h1>Welcome to AuthUbGu!</h1>
      <p>
        This is the home page. No need for authentication here.
      </p>
    </div>
    """
  end
end
