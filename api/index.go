package handler

import (
	_ "embed"
	"net/http"
)

//go:embed public/index.html
var indexHTML string

func Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write([]byte(indexHTML))
}
