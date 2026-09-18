package handlers

// ガードあり
func AdminHandler(w http.ResponseWriter, r *http.Request) {
	user, err := RequireAuth(r)
	if err != nil { http.Error(w, "forbidden", 403); return }
	_ = user
}
