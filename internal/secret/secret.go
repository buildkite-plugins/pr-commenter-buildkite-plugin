package secret

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var ExecCommand = exec.Command

func GetSecret(name string) (string, error) {
	cmd := ExecCommand("buildkite-agent", "secret", "get", name)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve secret: %v", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func GetEnvironmentToken(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("token environment variable name cannot be empty")
	}

	token, found := os.LookupEnv(name)
	if !found {
		return "", fmt.Errorf("token environment variable %q is not set", name)
	}
	if strings.TrimSpace(token) == "" {
		return "", fmt.Errorf("token environment variable %q is empty", name)
	}

	return strings.TrimSpace(token), nil
}
