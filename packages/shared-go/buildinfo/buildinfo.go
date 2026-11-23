package buildinfo

import (
	"os"
	"path/filepath"
	"strings"
)

const unknownVersion = "unknown"

// Info is the non-sensitive build metadata exposed in logs and version APIs.
type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	BuiltAt string `json:"built_at,omitempty"`
}

// Current returns build metadata injected by the deployment environment.
func Current() Info {
	version := strings.TrimSpace(os.Getenv("JJD_VERSION"))
	if version == "" {
		version = readVersionFile()
	}
	return Info{
		Version: version,
		Commit:  strings.TrimSpace(os.Getenv("JJD_COMMIT")),
		BuiltAt: strings.TrimSpace(os.Getenv("JJD_BUILT_AT")),
	}
}

func readVersionFile() string {
	candidates := []string{"VERSION", "/app/VERSION"}
	if wd, err := os.Getwd(); err == nil {
		dir := wd
		for {
			candidates = append(candidates, filepath.Join(dir, "VERSION"))
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err == nil {
			if version := strings.TrimSpace(string(data)); version != "" {
				return version
			}
		}
	}
	return unknownVersion
}
