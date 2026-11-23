package config

import "testing"

func TestAuditOnlySecurityActionHeaderDefault(t *testing.T) {
	for _, tc := range []struct {
		name, audit, header string
		want                bool
	}{
		{"record default", "true", "", false},
		{"protect default", "false", "", true},
		{"record explicit enable", "true", "true", true},
		{"protect explicit disable", "false", "false", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", tc.audit)
			t.Setenv("SECURITY_ACTION_HEADER_ENABLED", tc.header)
			t.Setenv("MCP_GATEWAY_ENABLED", "false")
			cfg, err := Load()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.SecurityActionHeader != tc.want {
				t.Fatalf("header enabled=%v want=%v", cfg.SecurityActionHeader, tc.want)
			}
		})
	}
}
