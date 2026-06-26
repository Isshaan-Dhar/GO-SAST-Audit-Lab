package main

import (
	"database/sql"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------
// TARGET 2: Hardcoded Secret (CWE-798)
// ---------------------------------------------------------
const hardcodedJWTSecret = "super-secret-dev-key-123"

// ---------------------------------------------------------
// TARGET 1: SQL Injection (CWE-89)
// ---------------------------------------------------------
func GetUserVulnerable(db *sql.DB, username string) {
	query := fmt.Sprintf("SELECT id, name, role FROM users WHERE username = '%s'", username)

	rows, err := db.Query(query)
	if err != nil {
		fmt.Println("Error executing query:", err)
		return
	}
	defer rows.Close()
}

// ---------------------------------------------------------
// TARGET 3: Insecure JWT Validation (Algorithm Confusion)
// ---------------------------------------------------------
func ValidateJWTInsecure(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(hardcodedJWTSecret), nil
	})

	if err != nil {
		return false
	}
	return token.Valid
}
