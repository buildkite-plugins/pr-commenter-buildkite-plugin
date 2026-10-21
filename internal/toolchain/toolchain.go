// Package toolchain enforces the Go releases containing the eMudhra verifier fix.
package toolchain

import (
	"fmt"
	"go/version"
	"regexp"
)

var releaseVersion = regexp.MustCompile(`^go1\.[0-9]+\.[0-9]+$`)

// Check rejects unpatched releases and unverifiable development/prerelease builds.
// A go.mod minimum alone also permits Go 1.27.0 through 1.27.2.
func Check(v string) error {
	if releaseVersion.MatchString(v) &&
		((version.Lang(v) == "go1.26" && version.Compare(v, "go1.26.10") >= 0) ||
			version.Compare(v, "go1.27.3") >= 0) {
		return nil
	}
	return fmt.Errorf("unsupported Go toolchain %q: use Go 1.26.10+ (1.26 series) or Go 1.27.3+; stable releases only", v)
}
