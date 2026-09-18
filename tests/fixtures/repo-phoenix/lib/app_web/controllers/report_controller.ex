defmodule AppWeb.ReportController do
  use AppWeb, :controller

  def create(conn, %{"email" => email}) do
    Mailer.send_report(email)
    json(conn, %{ok: true})
  end
end
