package github

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// installation represents a GitHub App installation
type installation struct {
	ID int64 `json:"id"`
}

// installationTokenResponse represents the response from GitHub's installation token endpoint
type installationTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GenerateAppJWT creates a JWT for GitHub App authentication.
// The JWT is signed with RS256 using the app's private key.
func GenerateAppJWT(appID string, privateKeyPEM []byte) (string, error) {
	privateKey, err := parsePrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Unix(),
		"exp": now.Add(10 * time.Minute).Unix(),
		"iss": appID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	return signedToken, nil
}

// FindInstallationID discovers the installation ID for a repository.
func FindInstallationID(ctx context.Context, jwt, owner, repo string) (int64, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/installation", owner, repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to request installation: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	var inst installation
	if err := json.Unmarshal(body, &inst); err != nil {
		return 0, fmt.Errorf("failed to parse installation response: %w", err)
	}

	return inst.ID, nil
}

// GetInstallationToken exchanges a JWT for a short-lived installation access token.
func GetInstallationToken(ctx context.Context, jwt string, installationID int64) (string, error) {
	url := fmt.Sprintf("https://api.github.com/app/installations/%d/access_tokens", installationID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+jwt)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request installation token: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("GitHub API returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp installationTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to parse token response: %w", err)
	}

	return tokenResp.Token, nil
}

// GetAppToken generates a JWT, discovers the installation ID, and exchanges for an access token.
// This is the main entry point for GitHub App authentication.
func GetAppToken(ctx context.Context, appID string, privateKeyPEM []byte, owner, repo string) (string, error) {
	jwt, err := GenerateAppJWT(appID, privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to generate app JWT: %w", err)
	}

	installationID, err := FindInstallationID(ctx, jwt, owner, repo)
	if err != nil {
		return "", fmt.Errorf("failed to find installation: %w", err)
	}

	token, err := GetInstallationToken(ctx, jwt, installationID)
	if err != nil {
		return "", fmt.Errorf("failed to get installation token: %w", err)
	}

	return token, nil
}

func parsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	// Normalize PEM: replace literal \n with actual newlines
	normalized := strings.ReplaceAll(string(pemBytes), "\\n", "\n")

	block, _ := pem.Decode([]byte(normalized))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS#1 format first (RSA PRIVATE KEY)
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	// Try PKCS#8 format (PRIVATE KEY)
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	return rsaKey, nil
}
