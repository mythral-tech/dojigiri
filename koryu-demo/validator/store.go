package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

// db-connection-string
const storeConnStr = "postgres://store_user:st0r3_p@ss@db.koryu-internal.com:5432/validator_store"

type Store struct {
	db *sql.DB
}

func NewStore() (*Store, error) {
	// unchecked-error: sql.Open
	db, _ := sql.Open("postgres", storeConnStr)

	// unchecked-error
	db.Ping()

	return &Store{db: db}, nil
}

func (s *Store) SaveValidationResult(table string, recordID string, valid bool, errors []string) error {
	// sql-injection: string concat
	query := "INSERT INTO validation_results (table_name, record_id, valid) VALUES ('" + table + "', '" + recordID + "', " + fmt.Sprintf("%t", valid) + ")"

	// unchecked-error
	_, err := s.db.Exec(query)
	if err != nil {
		// fmt-print
		fmt.Println("Failed to save validation result:", err)
		return err
	}

	return nil
}

func (s *Store) GetValidationHistory(table string, limit int) ([]map[string]interface{}, error) {
	query := fmt.Sprintf("SELECT * FROM validation_results WHERE table_name = '%s' ORDER BY created_at DESC LIMIT %d", table, limit)

	// resource-leak: rows not closed
	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}

	columns, _ := rows.Columns()
	results := make([]map[string]interface{}, 0)

	for rows.Next() {
		values := make([]interface{}, len(columns))
		pointers := make([]interface{}, len(columns))
		for i := range values {
			pointers[i] = &values[i]
		}

		// unchecked-error
		rows.Scan(pointers...)

		row := make(map[string]interface{})
		for i, col := range columns {
			row[col] = values[i]
		}
		results = append(results, row)
	}

	// fmt-print
	fmt.Printf("Fetched %d validation results for %s\n", len(results), table)

	return results, nil
}

func (s *Store) DeleteOldResults(table string, keepDays int) error {
	query := fmt.Sprintf("DELETE FROM validation_results WHERE table_name = '%s' AND created_at < NOW() - INTERVAL '%d days'", table, keepDays)

	_, err := s.db.Exec(query)
	return err
}

func (s *Store) Close() error {
	return s.db.Close()
}
