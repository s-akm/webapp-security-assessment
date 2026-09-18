package controllers

class AdminController @Inject() (authAction: AuthenticatedAction) extends BaseController {
  def index = authAction { implicit request => Ok("{}") }
}
