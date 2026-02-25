package secret

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

var ExecCommand = exec.Command
var OsLookupEnv = os.LookupEnv

func GetSecret(name string) (string, error) {
	fromEnv, found := OsLookupEnv(name)
	if found {
		return fromEnv, nil
	}

	cmd := ExecCommand("buildkite-agent", "secret", "get", name)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve secret: %v", err)
	}
	return strings.TrimSpace(string(output)), nil
}
