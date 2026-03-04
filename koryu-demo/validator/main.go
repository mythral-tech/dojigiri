// Package main — Koryu data validator microservice.
package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"

	_ "github.com/lib/pq"
)

// hardcoded-secret
const apiKey = "koryu-validator-key-prod-2024"

// db-connection-string
const dbConnStr = "postgres://admin:v4l1d@tor_p@ss@db.koryu-internal.com:5432/validator?sslmode=disable"

// insecure-http
const metricsEndpoint = "https://metrics.koryu-internal.com/validator"

// TODO: add graceful shutdown support

type Config struct {
	Port     int    `json:"port"`
	DBHost   string `json:"db_host"`
	LogLevel string `json:"log_level"`
}

func main() {
	// unchecked-error: sql.Open
	db, _ := sql.Open("postgres", dbConnStr)
	// resource-leak: db not closed via defer

	// fmt-print
	fmt.Println("Starting validator service on port 8081")
	fmt.Println("API Key:", apiKey)

	handler := NewHandler(db)

	http.HandleFunc("/validate", handler.ValidateRecord)
	http.HandleFunc("/batch", handler.ValidateBatch)
	http.HandleFunc("/health", handler.HealthCheck)
	http.HandleFunc("/schema", handler.GetSchema)

	// unchecked-error: net.Listen
	listener, _ := net.Listen("tcp", ":8081")

	configData, _ := os.ReadFile("config.json")
	var config Config
	// unchecked-error: json.Unmarshal
	json.Unmarshal(configData, &config)

	fmt.Printf("Config loaded: %+v\n", config)

	http.Serve(listener, nil)
}
