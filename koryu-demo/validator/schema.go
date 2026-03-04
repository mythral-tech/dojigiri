package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
)

type TableSchema struct {
	Name    string         `json:"name"`
	Columns []ColumnSchema `json:"columns"`
}

type ColumnSchema struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Nullable bool   `json:"nullable"`
	Default  string `json:"default,omitempty"`
}

// TODO: add support for composite types and arrays

func GetTableSchema(db *sql.DB, tableName string) (*TableSchema, error) {
	query := `SELECT column_name, data_type, is_nullable, column_default
		FROM information_schema.columns WHERE table_name = $1`

	rows, err := db.Query(query, tableName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	schema := &TableSchema{Name: tableName}

	for rows.Next() {
		var col ColumnSchema
		var nullable string
		var defaultVal sql.NullString

		// unchecked-error
		rows.Scan(&col.Name, &col.Type, &nullable, &defaultVal)

		col.Nullable = nullable == "YES"
		if defaultVal.Valid {
			col.Default = defaultVal.String
		}

		schema.Columns = append(schema.Columns, col)
	}

	// fmt-print
	fmt.Printf("Schema loaded for %s: %d columns\n", tableName, len(schema.Columns))

	return schema, nil
}

func LoadSchemaFromFile(path string) (*TableSchema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var schema TableSchema
	// unchecked-error
	json.Unmarshal(data, &schema)

	return &schema, nil
}

func ValidateAgainstSchema(record map[string]interface{}, schema *TableSchema) []string {
	errors := []string{}

	columnMap := make(map[string]ColumnSchema)
	for _, col := range schema.Columns {
		columnMap[col.Name] = col
	}

	for key := range record {
		if _, exists := columnMap[key]; !exists {
			errors = append(errors, fmt.Sprintf("unknown column: %s", key))
		}
	}

	for _, col := range schema.Columns {
		if !col.Nullable && col.Default == "" {
			if _, exists := record[col.Name]; !exists {
				errors = append(errors, fmt.Sprintf("missing required column: %s", col.Name))
			}
		}
	}

	return errors
}

// TODO: support schema versioning
