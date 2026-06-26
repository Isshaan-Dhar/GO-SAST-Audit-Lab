package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// ---------------------------------------------------------
// TARGET 2: Hardcoded Secret (CWE-798)
// ---------------------------------------------------------
func init() {
	if os.Getenv("JWT_SECRET") == "" {
		log.Fatal("FATAL: JWT_SECRET environment variable is not set. Halting startup.")
	}
}

// ---------------------------------------------------------
// TARGET 1: SQL Injection (CWE-89)
// ---------------------------------------------------------
func GetUserVulnerable(db *sql.DB, username string) {
	query := "SELECT id, name, role FROM users WHERE username = ?"

	rows, err := db.Query(query, username)
	if err != nil {
		fmt.Println("Error executing query:", err)
		return
	}
	defer rows.Close()
}

// ---------------------------------------------------------
// TARGET 3: Insecure JWT Validation (Algorithm Confusion)
// ---------------------------------------------------------
func ValidateJWTSecure(tokenString string) bool {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	}, jwt.WithValidMethods([]string{"HS256"}))

	if err != nil {
		return false
	}
	return token.Valid
}
