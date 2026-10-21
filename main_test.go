package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"prcommenter/internal/common"
	"prcommenter/internal/secret"
)

func TestResolveTokenFromEnvironment(t *testing.T) {
	unsetEnv(t, common.PluginPrefix+"SECRET_NAME")
	t.Setenv(common.PluginPrefix+"TOKEN_ENV", "PR_COMMENTER_GITHUB_TOKEN")
	t.Setenv("PR_COMMENTER_GITHUB_TOKEN", "environment-token")

	token, err := resolveToken()
	if err != nil {
		t.Fatalf("resolveToken() error = %v", err)
	}
	if token != "environment-token" {
		t.Fatalf("resolveToken() = %q, want %q", token, "environment-token")
	}
}

func TestResolveTokenFromConfiguredBuildkiteSecret(t *testing.T) {
	unsetEnv(t, common.PluginPrefix+"TOKEN_ENV")
	t.Setenv(common.PluginPrefix+"SECRET_NAME", "CUSTOM_GITHUB_TOKEN")

	secretName := mockBuildkiteSecret(t, "buildkite-token")

	token, err := resolveToken()
	if err != nil {
		t.Fatalf("resolveToken() error = %v", err)
	}
	if token != "buildkite-token" {
		t.Fatalf("resolveToken() = %q, want %q", token, "buildkite-token")
	}
	if *secretName != "CUSTOM_GITHUB_TOKEN" {
		t.Fatalf("Buildkite secret name = %q, want %q", *secretName, "CUSTOM_GITHUB_TOKEN")
	}
}

func TestResolveTokenDefaultsToBuildkiteSecret(t *testing.T) {
	unsetEnv(t, common.PluginPrefix+"TOKEN_ENV")
	unsetEnv(t, common.PluginPrefix+"SECRET_NAME")

	secretName := mockBuildkiteSecret(t, "buildkite-token")

	token, err := resolveToken()
	if err != nil {
		t.Fatalf("resolveToken() error = %v", err)
	}
	if token != "buildkite-token" {
		t.Fatalf("resolveToken() = %q, want %q", token, "buildkite-token")
	}
	if *secretName != defaultSecretName {
		t.Fatalf("Buildkite secret name = %q, want %q", *secretName, defaultSecretName)
	}
}

func TestResolveTokenRejectsEmptyEnvironmentName(t *testing.T) {
	unsetEnv(t, common.PluginPrefix+"SECRET_NAME")
	t.Setenv(common.PluginPrefix+"TOKEN_ENV", "")

	_, err := resolveToken()
	if err == nil {
		t.Fatal("resolveToken() error = nil, want an error")
	}
	if err.Error() != "token environment variable name cannot be empty" {
		t.Fatalf("resolveToken() error = %q", err)
	}
}

func TestResolveTokenRejectsMultipleSources(t *testing.T) {
	t.Setenv(common.PluginPrefix+"TOKEN_ENV", "PR_COMMENTER_GITHUB_TOKEN")
	t.Setenv(common.PluginPrefix+"SECRET_NAME", "GITHUB_TOKEN")
	t.Setenv("PR_COMMENTER_GITHUB_TOKEN", "do-not-include-this-token")

	_, err := resolveToken()
	if err == nil {
		t.Fatal("resolveToken() error = nil, want an error")
	}
	if err.Error() != "token-env and secret-name are mutually exclusive" {
		t.Fatalf("resolveToken() error = %q", err)
	}
	if strings.Contains(err.Error(), "do-not-include-this-token") {
		t.Fatal("resolveToken() error contains the token value")
	}
}

func mockBuildkiteSecret(t *testing.T, token string) *string {
	t.Helper()

	oldExecCommand := secret.ExecCommand
	t.Cleanup(func() { secret.ExecCommand = oldExecCommand })

	var secretName string
	secret.ExecCommand = func(command string, args ...string) *exec.Cmd {
		if command != "buildkite-agent" {
			t.Fatalf("command = %q, want %q", command, "buildkite-agent")
		}
		if len(args) != 3 || args[0] != "secret" || args[1] != "get" {
			t.Fatalf("args = %q, want [secret get NAME]", args)
		}
		secretName = args[2]
		return exec.Command("printf", "%s", token)
	}

	return &secretName
}

func unsetEnv(t *testing.T, name string) {
	t.Helper()

	value, found := os.LookupEnv(name)
	if err := os.Unsetenv(name); err != nil {
		t.Fatalf("unset %s: %v", name, err)
	}
	t.Cleanup(func() {
		if found {
			_ = os.Setenv(name, value)
		} else {
			_ = os.Unsetenv(name)
		}
	})
}

func TestEnvironmentHookRemovesStaleBinaryOnBuildFailure(t *testing.T) {
	for _, failCommand := range []string{"run", "build"} {
		t.Run(failCommand, func(t *testing.T) {
			dir := t.TempDir()
			hooks := filepath.Join(dir, "hooks")
			if err := os.Mkdir(hooks, 0755); err != nil {
				t.Fatal(err)
			}
			script, err := os.ReadFile("hooks/environment")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(hooks, "environment"), script, 0755); err != nil {
				t.Fatal(err)
			}
			binary := filepath.Join(hooks, "pre-exit")
			if err := os.WriteFile(binary, []byte("stale binary"), 0755); err != nil {
				t.Fatal(err)
			}
			// Fail selection/checking or compilation, without invoking a real compiler.
			fakeGo := "#!/usr/bin/env bash\nset -eu\ntest ! -e hooks/pre-exit\nif [[ $1 == " + failCommand + " ]]; then exit 1; fi\n"
			if err := os.WriteFile(filepath.Join(dir, "go"), []byte(fakeGo), 0755); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command("bash", filepath.Join(hooks, "environment"))
			cmd.Env = append(os.Environ(), "PATH="+dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			if out, err := cmd.CombinedOutput(); err == nil {
				t.Fatalf("hook succeeded despite %s failure: %s", failCommand, out)
			}
			if _, err := os.Stat(binary); !os.IsNotExist(err) {
				t.Fatalf("stale hook remains after %s failure: %v", failCommand, err)
			}
		})
	}
}
