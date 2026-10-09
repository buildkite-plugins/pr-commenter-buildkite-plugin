package secret_test

import (
	"os/exec"
	"strings"
	"testing"

	"prcommenter/internal/secret"
)

func TestGetSecret(t *testing.T) {
	oldExecCmd := secret.ExecCommand
	defer func() { secret.ExecCommand = oldExecCmd }()

	secret.ExecCommand = func(command string, args ...string) *exec.Cmd {
		return exec.Command("echo", "foobar")
	}

	got, err := secret.GetSecret("MOCK_SECRET")
	if err != nil {
		t.Fatalf("error getting secret value: %s", err)
	}

	want := "foobar"
	if got != want {
		t.Fatalf("wanted %s, got %s", want, got)
	}
}

func TestGetEnvironmentToken(t *testing.T) {
	t.Setenv("PR_COMMENTER_GITHUB_TOKEN", "environment-token")

	got, err := secret.GetEnvironmentToken("PR_COMMENTER_GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("GetEnvironmentToken() error = %v", err)
	}
	if got != "environment-token" {
		t.Fatalf("GetEnvironmentToken() = %q, want %q", got, "environment-token")
	}
}

func TestGetEnvironmentTokenTrimsWhitespace(t *testing.T) {
	t.Setenv("PR_COMMENTER_GITHUB_TOKEN", " environment-token\n")

	got, err := secret.GetEnvironmentToken("PR_COMMENTER_GITHUB_TOKEN")
	if err != nil {
		t.Fatalf("GetEnvironmentToken() error = %v", err)
	}
	if got != "environment-token" {
		t.Fatalf("GetEnvironmentToken() = %q, want %q", got, "environment-token")
	}
}

func TestGetEnvironmentTokenErrors(t *testing.T) {
	const tokenValue = "do-not-include-this-token"
	t.Setenv("EMPTY_PR_COMMENTER_GITHUB_TOKEN", "")
	t.Setenv("WHITESPACE_PR_COMMENTER_GITHUB_TOKEN", "  \t")
	t.Setenv("SECRET_PR_COMMENTER_GITHUB_TOKEN", tokenValue)

	tests := []struct {
		name        string
		environment string
		wantError   string
	}{
		{
			name:        "empty variable name",
			environment: "",
			wantError:   "token environment variable name cannot be empty",
		},
		{
			name:        "whitespace variable name",
			environment: "  ",
			wantError:   "token environment variable name cannot be empty",
		},
		{
			name:        "missing variable",
			environment: "MISSING_PR_COMMENTER_GITHUB_TOKEN",
			wantError:   `token environment variable "MISSING_PR_COMMENTER_GITHUB_TOKEN" is not set`,
		},
		{
			name:        "empty variable",
			environment: "EMPTY_PR_COMMENTER_GITHUB_TOKEN",
			wantError:   `token environment variable "EMPTY_PR_COMMENTER_GITHUB_TOKEN" is empty`,
		},
		{
			name:        "whitespace variable",
			environment: "WHITESPACE_PR_COMMENTER_GITHUB_TOKEN",
			wantError:   `token environment variable "WHITESPACE_PR_COMMENTER_GITHUB_TOKEN" is empty`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := secret.GetEnvironmentToken(test.environment)
			if err == nil {
				t.Fatal("GetEnvironmentToken() error = nil, want an error")
			}
			if err.Error() != test.wantError {
				t.Fatalf("GetEnvironmentToken() error = %q, want %q", err, test.wantError)
			}
			if strings.Contains(err.Error(), tokenValue) {
				t.Fatal("GetEnvironmentToken() error contains the token value")
			}
		})
	}
}
