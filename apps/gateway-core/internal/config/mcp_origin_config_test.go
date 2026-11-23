package config

import "testing"

func TestLoadMCPAllowedOriginsRequiresExactHTTPOrigins(t *testing.T) {
	t.Setenv("MCP_GATEWAY_ENABLED", "false")
	t.Setenv("MCP_ALLOWED_ORIGINS", "https://console.example, http://127.0.0.1:3000/")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.MCPAllowedOrigins) != 2 ||
		cfg.MCPAllowedOrigins[0] != "https://console.example" ||
		cfg.MCPAllowedOrigins[1] != "http://127.0.0.1:3000" {
		t.Fatalf("MCPAllowedOrigins=%v", cfg.MCPAllowedOrigins)
	}

	for _, invalid := range []string{
		"https://*.example",
		"https://user@example.com",
		"https://example.com/path",
		"file:///tmp/mcp",
	} {
		t.Run(invalid, func(t *testing.T) {
			t.Setenv("MCP_ALLOWED_ORIGINS", invalid)
			if _, err := Load(); err == nil {
				t.Fatalf("invalid origin %q accepted", invalid)
			}
		})
	}
}
