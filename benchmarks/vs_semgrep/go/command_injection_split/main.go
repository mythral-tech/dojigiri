package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"
)

func convertHandler(w http.ResponseWriter, r *http.Request) {
	input := r.URL.Query().Get("opts")
	filename := r.URL.Query().Get("file")

	parts := strings.Split(input, " ")
	args := append(parts, filename)

	cmd := exec.Command("convert", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		http.Error(w, fmt.Sprintf("conversion failed: %s", err), 500)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.Write(output)
}

func main() {
	http.HandleFunc("/convert", convertHandler)
	http.ListenAndServe(":8080", nil)
}
