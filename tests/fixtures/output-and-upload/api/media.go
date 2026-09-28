package api

import ("net/http"; "path/filepath")

var allowedExt = map[string]bool{".png": true, ".jpg": true}

func Upload(w http.ResponseWriter, r *http.Request) {
	_, hdr, _ := r.FormFile("clip")
	if !allowedExt[filepath.Ext(hdr.Filename)] { w.WriteHeader(415) }
}
