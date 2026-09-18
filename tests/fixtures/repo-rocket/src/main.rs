#[macro_use] extern crate rocket;

#[get("/api/admin")]
fn admin(user: AuthenticatedUser) -> &'static str { "{}" }

#[post("/api/report?<email>")]
fn report(email: String) -> &'static str {
    send_mail(&email);
    "{}"
}

#[launch]
fn rocket() -> _ { rocket::build().mount("/", routes![admin, report]) }
