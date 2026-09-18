package controllers

class ReportController @Inject() (cc: ControllerComponents) extends AbstractController(cc) {
  def store = Action { implicit request =>
    db.run(sql"select * from users where id = ${request.body}")
    Ok("{}")
  }
}
