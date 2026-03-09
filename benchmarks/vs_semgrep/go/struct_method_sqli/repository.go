package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type User struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type UserRepository struct {
	db *sql.DB
}

func NewUserRepository(dsn string) *UserRepository {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		panic(err)
	}
	return &UserRepository{db: db}
}

func (r *UserRepository) Search(term string) ([]User, error) {
	query := fmt.Sprintf("SELECT id, name, email FROM users WHERE name LIKE '%%%s%%'", term)
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		rows.Scan(&u.ID, &u.Name, &u.Email)
		users = append(users, u)
	}
	return users, nil
}
