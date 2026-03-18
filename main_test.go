package main

import (
	"os/exec"
	"path/filepath"
	"testing"

	"prcommenter/internal/secret"
)

// setupCommonEnv sets environment variables required to reach the message-path
// handling logic in run(), bypassing repo parsing, PR detection, and secret retrieval.
func setupCommonEnv(t *testing.T) {
	t.Helper()
	t.Setenv("BUILDKITE_PULL_REQUEST_REPO", "https://github.com/wrapbook/app.git")
	t.Setenv("BUILDKITE_PULL_REQUEST", "123")
	t.Setenv("BUILDKITE_LABEL", ":rocket: Review App Deploy")
	t.Setenv("BUILDKITE_PIPELINE_SLUG", "review-app-deploy")
	t.Setenv("BUILDKITE_PLUGIN_PR_COMMENTER_SECRET_NAME", "GITHUB_TOKEN")

	// Mock secret retrieval so tests don't require a real buildkite-agent
	secret.ExecCommand = func(name string, args ...string) *exec.Cmd {
		return exec.Command("echo", "fake-token")
	}
	t.Cleanup(func() { secret.ExecCommand = exec.Command })
}

// TestRun_CanceledBuild_SkipsComment verifies that when a build is canceled
// (BUILDKITE_COMMAND_EXIT_STATUS == -1) and deploy_status.md was never written,
// the plugin exits cleanly without failing the build.
func TestRun_CanceledBuild_SkipsComment(t *testing.T) {
	setupCommonEnv(t)

	missingPath := filepath.Join(t.TempDir(), "deploy_status.md")
	t.Setenv("BUILDKITE_PLUGIN_PR_COMMENTER_MESSAGE_PATH", missingPath)
	t.Setenv("BUILDKITE_COMMAND_EXIT_STATUS", "-1")

	if result := run(); result != exitOK {
		t.Errorf("expected exitOK for canceled build with missing message-path, got %d", result)
	}
}

// TestRun_UnexpectedFailure_ReturnsError verifies that when the script exits
// unexpectedly (e.g. set -e triggered) and deploy_status.md was never written,
// the plugin fails so the missing file is surfaced rather than silently ignored.
func TestRun_UnexpectedFailure_ReturnsError(t *testing.T) {
	setupCommonEnv(t)

	missingPath := filepath.Join(t.TempDir(), "deploy_status.md")
	t.Setenv("BUILDKITE_PLUGIN_PR_COMMENTER_MESSAGE_PATH", missingPath)
	t.Setenv("BUILDKITE_COMMAND_EXIT_STATUS", "1")

	if result := run(); result != exitError {
		t.Errorf("expected exitError for unexpected failure with missing message-path, got %d", result)
	}
}
