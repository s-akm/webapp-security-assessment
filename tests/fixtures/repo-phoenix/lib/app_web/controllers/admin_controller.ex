defmodule AppWeb.AdminController do
  use AppWeb, :controller
  plug :require_authenticated_user

  def index(conn, _params), do: json(conn, %{ok: true})
end
