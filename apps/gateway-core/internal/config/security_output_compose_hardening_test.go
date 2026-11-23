package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestOutputSafetySwitchesReachContainersWithoutHeaderOverride(t *testing.T) {
	for _, name := range []string{"docker-compose.yml", "docker-compose.offline.yml"} {
		t.Run(name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "docker-compose", name))
			if err != nil {
				t.Fatal(err)
			}
			var document struct {
				Services map[string]struct {
					Environment []string `yaml:"environment"`
				} `yaml:"services"`
			}
			if err := yaml.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			for _, service := range []string{"gateway-core", "proxy-server", "proxy-server-vm"} {
				container, ok := document.Services[service]
				if !ok && service == "proxy-server-vm" && name == "docker-compose.offline.yml" {
					continue
				}
				entries := map[string]bool{}
				for _, entry := range container.Environment {
					entries[entry] = true
				}
				if service == "gateway-core" {
					if !entries["SECURITY_ACTION_HEADER_ENABLED=${SECURITY_ACTION_HEADER_ENABLED:-}"] {
						t.Error("Compose overrides conditional security-action-header default")
					}
				} else {
					for _, entry := range []string{"PROXY_MITM_BYPASS_SUFFIXES=${PROXY_MITM_BYPASS_SUFFIXES:-}", "PROXY_RAW_DUMP_DIR=${PROXY_RAW_DUMP_DIR:-}"} {
						if !entries[entry] {
							t.Errorf("%s does not forward %s", service, entry)
						}
					}
				}
			}
		})
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "docker-compose", ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") {
			continue
		}
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = value
		}
	}
	for _, key := range []string{"SECURITY_ACTION_HEADER_ENABLED", "PROXY_MITM_BYPASS_SUFFIXES", "PROXY_RAW_DUMP_DIR"} {
		if value, ok := values[key]; !ok || value != "" {
			t.Errorf("customer %s must be unset by default, present=%v value=%q", key, ok, value)
		}
	}
}
