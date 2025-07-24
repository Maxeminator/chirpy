package auth_test

import (
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
