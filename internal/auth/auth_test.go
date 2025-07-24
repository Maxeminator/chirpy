package auth_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/Maxeminator/chirpy/internal/auth"
	"github.com/google/uuid"
)

func TestMakeAndValidateJWT(t *testing.T) {
	userID := uuid.New()
	secret := "supersecret"
	token, err := auth.MakeJWT(userID, secret, time.Minute)
	if err != nil {
		t.Fatalf("failed to make JWT: %v", err)
	}

	returnedID, err := auth.ValidateJWT(token, secret)
	if err != nil {
		t.Fatalf("failed to validate JWT: %v", err)
	}

	if returnedID != userID {
		t.Errorf("expected %v, got %v", userID, returnedID)
	}
}

func TestExpireJWT(t *testing.T) {
	userID := uuid.New()
	secret := "supersecret"
	token, err := auth.MakeJWT(userID, secret, -1*time.Minute)
	if err != nil {
		t.Fatalf("failed to make JWT: %v", err)
	}

	_, err = auth.ValidateJWT(token, secret)
	if err == nil {
		t.Fatalf("expected error for expired token, got nil")
	}
}

func TestBadSecretJWT(t *testing.T) {
	userID := uuid.New()
	secret := "supersecret"
	token, err := auth.MakeJWT(userID, secret, time.Minute)
	if err != nil {
		t.Fatalf("failed to make JWT: %v", err)
	}
	_, err = auth.ValidateJWT(token, "top-secret")
	if err == nil {
		t.Fatalf("expected error for invalid secret, got nil")
	}
}

func TestGetBearerToken_Valid(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Bearer testtoken123")

	token, err := auth.GetBearerToken(headers)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if token != "testtoken123" {
		t.Fatalf("expected token 'testtoken123', got '%s'", token)
	}
}

func TestGetBearerToken_MissingHeader(t *testing.T) {
	headers := http.Header{}
	_, err := auth.GetBearerToken(headers)

	if err == nil {
		t.Fatal("expected error for missing header, got nil")
	}
}

func TestGetBearerToken_InvalidPrefix(t *testing.T) {
	headers := http.Header{}
	headers.Set("Authorization", "Token notBearerToken")

	_, err := auth.GetBearerToken(headers)

	if err == nil {
		t.Fatal("expected error for invalid prefix, got nil")
	}
}
