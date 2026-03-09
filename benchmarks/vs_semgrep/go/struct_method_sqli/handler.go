package main

import (
	"encoding/json"
	"net/http"
)

type SearchRequest struct {
	Query string `json:"query"`
}

func searchHandler(repo *UserRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req SearchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		users, err := repo.Search(req.Query)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		json.NewEncoder(w).Encode(users)
	}
}

func main() {
	repo := NewUserRepository("postgres://localhost/app")
	http.HandleFunc("/api/search", searchHandler(repo))
	http.ListenAndServe(":8080", nil)
}
