package main

func main() {
	app := fiber.New()
	app.Get("/api/admin", RequireAuth, AdminHandler)
	app.Post("/api/report", ReportHandler)
	app.Listen(":3000")
}

func ReportHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"ok": true})
}
