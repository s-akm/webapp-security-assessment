package main
func main() { g := gin.Default(); g.GET("/users", listUsers); g.POST("/admin/metrics", metrics); n := rand.Intn(10); _ = n }
