package toolchain

import "testing"

func TestCheck(t *testing.T) {
	for _, v := range []string{"go1.26.10", "go1.26.11", "go1.27.3", "go1.27.10", "go1.28.0"} {
		t.Run(v, func(t *testing.T) {
			if err := Check(v); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, v := range []string{"go1.24.12", "go1.25.10", "go1.26.0", "go1.26.9", "go1.27.0", "go1.27.1", "go1.27.2", "go1.28rc1", "go1.27.3-custom", "devel go1.28", "", "go1.27"} {
		t.Run(v, func(t *testing.T) {
			if err := Check(v); err == nil {
				t.Fatal("accepted unpatched or unverifiable toolchain")
			}
		})
	}
}
