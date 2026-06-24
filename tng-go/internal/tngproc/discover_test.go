//go:build !integration

package tngproc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFindTngBinary_EnvSetValid(t *testing.T) {
	// Create a temp file to act as the TNG binary
	tmpDir := t.TempDir()
	fakeBinary := filepath.Join(tmpDir, "fake-tng")
	if err := os.WriteFile(fakeBinary, []byte{}, 0755); err != nil {
		t.Fatalf("failed to create fake binary: %v", err)
	}

	// Set TNG_BINARY to point to our fake binary
	t.Setenv("TNG_BINARY", fakeBinary)

	path, err := findTngBinary()
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if path != fakeBinary {
		t.Errorf("expected path %s, got %s", fakeBinary, path)
	}
}

func TestFindTngBinary_EnvSetInvalid(t *testing.T) {
	// Set TNG_BINARY to a non-existent path
	t.Setenv("TNG_BINARY", "/nonexistent/path/to/tng")

	_, err := findTngBinary()
	if err == nil {
		t.Fatal("expected error for non-existent TNG_BINARY, got nil")
	}
}

func TestFindTngBinary_NotSetNotOnPath(t *testing.T) {
	// Clear TNG_BINARY and ensure "tng" is not on PATH
	os.Unsetenv("TNG_BINARY")
	t.Setenv("PATH", "/nonexistent-empty-path")

	_, err := findTngBinary()
	if err == nil {
		t.Fatal("expected error when tng is not found, got nil")
	}
}
