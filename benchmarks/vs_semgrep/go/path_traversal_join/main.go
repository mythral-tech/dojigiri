package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

const uploadsDir = "/var/app/uploads"

func downloadHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("name")
	if filename == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	safePath := filepath.Join(uploadsDir, filename)

	f, err := os.Open(safePath)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	io.Copy(w, f)
}

func main() {
	http.HandleFunc("/download", downloadHandler)
	http.ListenAndServe(":8080", nil)
}
