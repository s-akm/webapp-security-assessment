import Vapor

func routes(_ app: Application) throws {
    let protected = app.grouped(UserAuthenticator())
    protected.get("api", "admin") { req in return "{}" }

    app.post("api", "report") { req -> String in
        let email = try req.content.get(String.self, at: "email")
        sendMail(email)
        return "{}"
    }
}
