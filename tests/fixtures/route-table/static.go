http.Handle("/static/", http.FileServer(http.Dir("./public")))
