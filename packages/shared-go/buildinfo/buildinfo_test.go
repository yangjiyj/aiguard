package buildinfo

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentFallsBackToVersionFile(t *testing.T) {
	t.Setenv("JJD_VERSION", "")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte("7.8.9\n"), 0o644); err != nil {
		t.Fatalf("write VERSION: %v", err)
	}
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldwd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}

	if got := Current().Version; got != "7.8.9" {
		t.Fatalf("version = %q, want VERSION file value", got)
	}
}
