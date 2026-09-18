package main

func main() {
	r := gin.Default()
	auth := r.Group("/api", AuthMiddleware())
	auth.GET("/admin", AdminHandler)
	r.POST("/api/report", ReportHandler)
	r.Run()
}

func ReportHandler(c *gin.Context) {
	id := c.Query("id")
	db.Query("select * from users where id = " + id)
}
