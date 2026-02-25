package secret_test

import (
	"os/exec"
	"testing"

	"prcommenter/internal/secret"
)

func TestGetSecret(t *testing.T) {
	oldExecCmd := secret.ExecCommand
	defer func() { secret.ExecCommand = oldExecCmd }()

	oldOsLookupEnv := secret.OsLookupEnv
	defer func() { secret.OsLookupEnv = oldOsLookupEnv }()

	secret.OsLookupEnv = func(name string) (string, bool) {
		return "", false
	}

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

func TestGetSecretFromEnv(t *testing.T) {
	oldExecCmd := secret.ExecCommand
	defer func() { secret.ExecCommand = oldExecCmd }()

	oldOsLookupEnv := secret.OsLookupEnv
	defer func() { secret.OsLookupEnv = oldOsLookupEnv }()

	secret.OsLookupEnv = func(name string) (string, bool) {
		return name + "_FOUND", true
	}

	secret.ExecCommand = func(command string, args ...string) *exec.Cmd {
		return exec.Command("false")
	}

	got, err := secret.GetSecret("MOCK_SECRET")
	if err != nil {
		t.Fatalf("error getting secret value: %s", err)
	}

	want := "MOCK_SECRET_FOUND"
	if got != want {
		t.Fatalf("wanted %s, got %s", want, got)
	}
}
