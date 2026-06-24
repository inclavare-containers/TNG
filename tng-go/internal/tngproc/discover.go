// Package tngproc manages the TNG subprocess lifecycle.
package tngproc

import (
	"fmt"
	"os"
	"os/exec"
)

// findTngBinary locates the TNG executable using the following priority:
//  1. TNG_BINARY environment variable (must be an existing file)
//  2. PATH lookup for "tng"
//
// The TNG_BINARY env var is shared with the Python SDK (tng-python).
func findTngBinary() (string, error) {
	// Priority 1: TNG_BINARY environment variable
	if env := os.Getenv("TNG_BINARY"); env != "" {
		if _, err := os.Stat(env); err == nil {
			return env, nil
		}
		return "", fmt.Errorf("TNG_BINARY=%s: not found or not accessible", env)
	}

	// Priority 2: PATH lookup
	path, err := exec.LookPath("tng")
	if err == nil {
		return path, nil
	}

	return "", fmt.Errorf(
		"tng binary not found: set TNG_BINARY env var or install tng in PATH",
	)
}
