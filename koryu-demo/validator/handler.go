package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
)

type Handler struct {
	db *sql.DB
}

func NewHandler(db *sql.DB) *Handler {
	return &Handler{db: db}
}

type ValidationRequest struct {
	Table  string                 `json:"table"`
	Record map[string]interface{} `json:"record"`
}

type ValidationResponse struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors"`
}

func (h *Handler) ValidateRecord(w http.ResponseWriter, r *http.Request) {
	var req ValidationRequest

	// unchecked-error: json.NewDecoder
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	// taint-flow: r.FormValue → db.Query
	tableName := r.FormValue("table")
	// logging-sensitive-data
	// fmt-print
	fmt.Printf("Validating record for table: %s, data: %+v\n", tableName, req.Record)

	// sql-injection: string concat in db.Query
	query := "SELECT column_name, data_type FROM information_schema.columns WHERE table_name = '" + tableName + "'"
	// unchecked-error
	rows, _ := h.db.Query(query)

	columns := make(map[string]string)
	for rows.Next() {
		var colName, colType string
		// unchecked-error
		rows.Scan(&colName, &colType)
		columns[colName] = colType
	}

	errors := []string{}
	for key := range req.Record {
		if _, exists := columns[key]; !exists {
			errors = append(errors, fmt.Sprintf("unknown column: %s", key))
		}
	}

	resp := ValidationResponse{Valid: len(errors) == 0, Errors: errors}

	w.Header().Set("Content-Type", "application/json")
	// unchecked-error
	json.NewEncoder(w).Encode(resp)

	// fmt-print
	fmt.Println("Validation complete:", resp.Valid)
}

func (h *Handler) ValidateBatch(w http.ResponseWriter, r *http.Request) {
	var records []ValidationRequest

	// variable-shadowing: err
	err := json.NewDecoder(r.Body).Decode(&records)
	if err != nil {
		http.Error(w, "bad request", 400)
		return
	}

	// fmt-print
	fmt.Printf("Batch validation: %d records\n", len(records))

	results := make([]ValidationResponse, 0, len(records))
	for _, rec := range records {
		// simplified validation
		valid := len(rec.Record) > 0
		result := ValidationResponse{Valid: valid, Errors: nil}
		results = append(results, result)
	}

	// long-line
	w.Header().Set("Content-Type", "application/json; charset=utf-8; x-custom-header=koryu-validator-batch-response-v1")
	json.NewEncoder(w).Encode(results)
}

func (h *Handler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	// unchecked-error
	err := h.db.Ping()
	if err != nil {
		http.Error(w, "unhealthy", 500)
		return
	}

	w.Write([]byte(`{"status": "healthy"}`))
}

func (h *Handler) GetSchema(w http.ResponseWriter, r *http.Request) {
	table := r.FormValue("table")
	// fmt-print
	fmt.Println("Schema request for:", table)

	schema, err := GetTableSchema(h.db, table)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	json.NewEncoder(w).Encode(schema)
}
