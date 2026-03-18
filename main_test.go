package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"prcommenter/internal/secret"
)

// setupCommonEnv sets environment variables required to reach the message-path
// handling logic in run(), bypassing repo parsing and PR detection.
func setupCommonEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BUILDKITE_PULL_REQUEST_REPO", "https://github.com/wrapbook/app.git")
	t.Setenv("BUILDKITE_PULL_REQUEST", "123")
	t.Setenv("BUILDKITE_PIPELINE_SLUG", "review-app-deploy")
	t.Setenv("BUILDKITE_LABEL", ":rocket: Review App Deploy")
	t.Setenv("BUILDKITE_PLUGIN_PR_COMMENTER_SECRET_NAME", "GITHUB_TOKEN")
}

// mockSecret mocks secret retrieval so tests don't require a real buildkite-agent.
func mockSecret(t *testing.T) {
	t.Helper()
	secret.ExecCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("echo", "fake-token")
	}
	t.Cleanup(func() { secret.ExecCommand = exec.Command })
}

// TestRun_CanceledBuild_SkipsComment verifies that when a build is canceled
// (BUILDKITE_COMMAND_EXIT_STATUS == -1) and deploy_status.md was never written,
// the plugin exits cleanly before attempting secret retrieval.
func TestRun_CanceledBuild_SkipsComment(t *testing.T) {
	setupCommonEnv(t)

	missingPath := filepath.Join(t.TempDir(), "deploy_status.md")
	t.Setenv("BUILDKITE_PLUGIN_PR_COMMENTER_MESSAGE_PATH", missingPath)
	t.Setenv("BUILDKITE_COMMAND_EXIT_STATUS", "-1")

	if result := run(); result != exitOK {
		t.Errorf("expected exitOK for canceled build with missing message-path, got %d", result)
	}
}

// TestRun_CanceledBuild_FileExists_Proceeds verifies that when a build is canceled
// but deploy_status.md was written before cancellation, the plugin proceeds normally
// (does not print the cancellation skip message).
func TestRun_CanceledBuild_FileExists_Proceeds(t *testing.T) {
	setupCommonEnv(t)
	mockSecret(t)

	existingFile := filepath.Join(t.TempDir(), "deploy_status.md")
	if err := os.WriteFile(existingFile, []byte("## Deployment\nsome status"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BUILDKITE_PLUGIN_PR_COMMENTER_MESSAGE_PATH", existingFile)
	t.Setenv("BUILDKITE_COMMAND_EXIT_STATUS", "-1")

	// Capture stdout to verify the cancellation skip message was NOT printed.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStdout := os.Stdout
	os.Stdout = w
	run()
	w.Close()
	os.Stdout = origStdout
	out, _ := io.ReadAll(r)

	if strings.Contains(string(out), "Build was canceled, skipping comment") {
		t.Error("early-exit fired despite deploy_status.md existing — cancellation check should not skip when file is present")
	}
}

// TestRun_UnexpectedFailure_ReturnsError verifies that when the script exits
// unexpectedly (e.g. set -e triggered) and deploy_status.md was never written,
// the plugin fails so the missing file is surfaced rather than silently ignored.
func TestRun_UnexpectedFailure_ReturnsError(t *testing.T) {
	setupCommonEnv(t)
	mockSecret(t)

	missingPath := filepath.Join(t.TempDir(), "deploy_status.md")
	t.Setenv("BUILDKITE_PLUGIN_PR_COMMENTER_MESSAGE_PATH", missingPath)
	t.Setenv("BUILDKITE_COMMAND_EXIT_STATUS", "1")

	if result := run(); result != exitError {
		t.Errorf("expected exitError for unexpected failure with missing message-path, got %d", result)
	}
}

// TestRun_PostFailure_ReturnsError verifies that when posting the comment fails
// (e.g. invalid token), run() returns exitError rather than silently succeeding.
func TestRun_PostFailure_ReturnsError(t *testing.T) {
	setupCommonEnv(t)
	mockSecret(t)
	// No MESSAGE or MESSAGE_PATH — falls through to default message.
	// Post will fail with 401 from the fake token, which should surface as exitError.
	if result := run(); result != exitError {
		t.Errorf("expected exitError when Post fails with invalid token, got %d", result)
	}
}

// TestRun_EmptyMessagePath_TreatedAsUnset verifies that MESSAGE_PATH="" is ignored
// (treated as not set) rather than attempting to read a file at path "".
func TestRun_EmptyMessagePath_TreatedAsUnset(t *testing.T) {
	setupCommonEnv(t)
	mockSecret(t)
	t.Setenv("BUILDKITE_PLUGIN_PR_COMMENTER_MESSAGE_PATH", "")
	t.Setenv("BUILDKITE_COMMAND_EXIT_STATUS", "0")

	// Empty path should be treated as unset — plugin falls back to default message
	// and attempts Post (which fails with fake token → exitError, not a file I/O error).
	result := run()
	if result != exitError {
		t.Errorf("expected exitError (Post with fake token), got %d — empty MESSAGE_PATH may have caused a file read error", result)
	}
}
