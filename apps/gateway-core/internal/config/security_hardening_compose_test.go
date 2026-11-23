package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestSecurityHardeningSwitchesReachGatewayContainers(t *testing.T) {
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
			got := map[string]bool{}
			for _, entry := range document.Services["gateway-core"].Environment {
				got[entry] = true
			}
			for _, entry := range []string{
				"SKILL_ADMISSION_FAIL_MODE=${SKILL_ADMISSION_FAIL_MODE:-closed}",
				"MCP_POLICY_FAIL_MODE=${MCP_POLICY_FAIL_MODE:-open}",
				"MCP_TOOL_RESULT_GUARD_ENABLED=${MCP_TOOL_RESULT_GUARD_ENABLED:-true}",
			} {
				if !got[entry] {
					t.Errorf("gateway container does not receive %s", entry)
				}
			}
		})
	}
}

func TestCapacityFailClosedSwitchReachesInspectionContainers(t *testing.T) {
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
				found := false
				for _, entry := range container.Environment {
					found = found || entry == "SECURITY_CAPACITY_FAIL_CLOSED=${SECURITY_CAPACITY_FAIL_CLOSED:-false}"
				}
				if !found {
					t.Errorf("%s does not forward the capacity fail policy", service)
				}
			}
		})
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "docker-compose", ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains("\n"+string(data)+"\n", "\nSECURITY_CAPACITY_FAIL_CLOSED=false\n") {
		t.Fatal("customer capacity default must remain fail-open")
	}
}

func TestProxyDetectionFailModeSwitchReachesContainers(t *testing.T) {
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
			for _, service := range []string{"proxy-server", "proxy-server-vm"} {
				container, ok := document.Services[service]
				if !ok && service == "proxy-server-vm" && name == "docker-compose.offline.yml" {
					continue
				}
				found := false
				for _, entry := range container.Environment {
					found = found || entry == "PROXY_DETECTION_FAIL_MODE=${PROXY_DETECTION_FAIL_MODE:-open}"
				}
				if !found {
					t.Errorf("%s does not forward ordinary detection failure policy", service)
				}
			}
		})
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "docker-compose", ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains("\n"+string(data)+"\n", "\nPROXY_DETECTION_FAIL_MODE=open\n") {
		t.Fatal("ordinary detection default must remain open")
	}
}

func TestForwardProxySwitchesReachAllContainers(t *testing.T) {
	expected := map[string][]string{
		"gateway-core": {
			"GATEWAY_FORWARD_PROXY_MODE=${GATEWAY_FORWARD_PROXY_MODE:-deny_unlisted}",
			"PROXY_WHITELIST_FAIL_MODE=${PROXY_WHITELIST_FAIL_MODE:-closed}",
		},
		// 控制面读同一份 .env：控制台在库里缺键时显示的生效值与网关一致（2.9.22）。
		"control-plane": {
			"GATEWAY_FORWARD_PROXY_MODE=${GATEWAY_FORWARD_PROXY_MODE:-deny_unlisted}",
			"PROXY_WHITELIST_FAIL_MODE=${PROXY_WHITELIST_FAIL_MODE:-closed}",
		},
		"proxy-server": {
			"PROXY_WHITELIST_FAIL_MODE=${PROXY_WHITELIST_FAIL_MODE:-closed}",
			"PROXY_DEFAULT_TENANT_ID=${PROXY_DEFAULT_TENANT_ID:-tenant_default}",
		},
		"proxy-server-vm": {
			"PROXY_WHITELIST_FAIL_MODE=${PROXY_WHITELIST_FAIL_MODE:-closed}",
			"PROXY_DEFAULT_TENANT_ID=${PROXY_DEFAULT_TENANT_ID:-tenant_default}",
		},
	}
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
			for service, entries := range expected {
				container, ok := document.Services[service]
				if !ok && service == "proxy-server-vm" && name == "docker-compose.offline.yml" {
					continue
				}
				got := map[string]bool{}
				for _, entry := range container.Environment {
					got[entry] = true
				}
				for _, entry := range entries {
					if !got[entry] {
						t.Errorf("%s container does not receive %s", service, entry)
					}
				}
			}
		})
	}
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "docker-compose", ".env.example"))
	if err != nil {
		t.Fatal(err)
	}
	lines := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		lines[strings.TrimSpace(line)] = true
	}
	for _, entry := range []string{"GATEWAY_FORWARD_PROXY_MODE=deny_unlisted", "PROXY_WHITELIST_FAIL_MODE=closed", "SECURITY_AUDIT_ONLY=false"} {
		if !lines[entry] {
			t.Errorf("customer defaults missing %s", entry)
		}
	}
}
