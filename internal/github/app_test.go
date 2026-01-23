package github_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"prcommenter/internal/github"
)

func generateTestPrivateKey(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	return pem.EncodeToMemory(pemBlock)
}

func TestGenerateAppJWT(t *testing.T) {
	privateKey := generateTestPrivateKey(t)

	jwt, err := github.GenerateAppJWT("12345", privateKey)
	if err != nil {
		t.Fatalf("failed to generate JWT: %v", err)
	}

	// JWT should have 3 parts separated by dots
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Errorf("expected JWT to have 3 parts, got %d", len(parts))
	}
}

func TestGenerateAppJWT_InvalidKey(t *testing.T) {
	_, err := github.GenerateAppJWT("12345", []byte("not a valid key"))
	if err == nil {
		t.Error("expected error for invalid key")
	}
}
