package handlers

// ガードなし。文字列連結の SQL もある
func ReportHandler(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	rows, _ := db.Query("select * from users where id = " + id)
	defer rows.Close()
	exec.Command("sh", "-c", "notify " + id).Run()
}
