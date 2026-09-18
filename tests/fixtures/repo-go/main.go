package main

func main() {
	http.HandleFunc("/api/admin", handlers.AdminHandler)
	http.HandleFunc("/api/report", handlers.ReportHandler)
	r.Get("/api/items", ItemsHandler)
	e.GET("/api/health", HealthHandler)
	http.ListenAndServe(":8080", nil)
}
