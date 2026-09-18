#[get("/api/admin")]
async fn admin(user: AuthenticatedUser) -> impl Responder {
    HttpResponse::Ok().json(user)
}

#[post("/api/report")]
async fn report(form: web::Form<ReportForm>) -> impl Responder {
    send_mail(&form.email);
    HttpResponse::Ok().finish()
}
