package main

import (
	"os"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func TestValidateJWTSecure_AlgNoneRejected(t *testing.T) {
	os.Setenv("JWT_SECRET", "super-secret-test-key")

	token := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"role": "admin"})

	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("Failed to construct malicious token: %v", err)
	}

	isValid := ValidateJWTSecure(tokenString)

	if isValid {
		t.Errorf("CRITICAL VULNERABILITY: Token with 'alg:none' was accepted!")
	} else {
		t.Log("SUCCESS: Token with 'alg:none' was correctly rejected by the allowlist.")
	}
}
