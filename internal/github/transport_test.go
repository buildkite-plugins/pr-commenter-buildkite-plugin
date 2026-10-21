package github_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"prcommenter/internal/github"

	api "github.com/google/go-github/github"
)

// Route the production OAuth2 transport to a local TLS GitHub API fixture.
// No fake (or real) token leaves the test process's loopback connection.
type localTransport struct {
	base   http.RoundTripper
	target *url.URL
}

func (r localTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.target.Scheme, r.target.Host
	return r.base.RoundTrip(req)
}

func TestAuthenticatedCommentOperationsOverTLS(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if got := r.Header.Get("Authorization"); got != "Bearer synthetic-test-token" {
			t.Errorf("unexpected Authorization header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /repos/owner/repo/issues/42/comments":
			_, _ = w.Write([]byte(`[{"id":7,"body":"existing"}]`))
		case "POST /repos/owner/repo/issues/42/comments", "PATCH /repos/owner/repo/issues/comments/7":
			var c api.IssueComment
			if err := json.NewDecoder(r.Body).Decode(&c); err != nil || c.GetBody() != "message" {
				t.Errorf("unexpected comment: %v, %v", c, err)
			}
			_, _ = w.Write([]byte(`{"id":7,"body":"message"}`))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	target, _ := url.Parse(server.URL)
	old := http.DefaultTransport
	t.Cleanup(func() { http.DefaultTransport = old })
	trusted := server.Client().Transport
	http.DefaultTransport = localTransport{base: trusted, target: target}
	client, err := github.New("synthetic-test-token")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := client.ListComments(ctx, "owner", "repo", 42, nil); err != nil {
		t.Fatal(err)
	}
	body := "message"
	c := &api.IssueComment{Body: &body}
	if _, _, err := client.CreateComment(ctx, "owner", "repo", 42, c); err != nil {
		t.Fatal(err)
	}
	if _, _, err := client.EditComment(ctx, "owner", "repo", 7, c); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("got %d authenticated requests, want 3", got)
	}

	// The same client path must reject an untrusted chain before sending HTTP.
	untrusted := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}}
	defer untrusted.CloseIdleConnections()
	http.DefaultTransport = localTransport{base: untrusted, target: target}
	client, err = github.New("synthetic-test-token")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = client.ListComments(ctx, "owner", "repo", 42, nil)
	var verificationError *tls.CertificateVerificationError
	if !errors.As(err, &verificationError) {
		t.Fatalf("expected TLS certificate verification failure, got %v", err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("HTTP reached server after TLS rejection: %d requests", got)
	}
}
