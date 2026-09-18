fun Application.configureRouting() {
    routing {
        authenticate("auth-jwt") {
            get("/api/admin") { call.respond(mapOf("ok" to true)) }
        }
        post("/api/report") {
            sendMail(call.receiveParameters()["email"]!!)
            call.respond(mapOf("ok" to true))
        }
    }
}
