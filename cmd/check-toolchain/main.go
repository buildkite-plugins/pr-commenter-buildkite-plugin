// check-toolchain checks the selected compiler before generating a plugin hook.
package main

import (
	"fmt"
	"os"
	"runtime"

	"prcommenter/internal/toolchain"
)

func main() {
	if err := toolchain.Check(runtime.Version()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
