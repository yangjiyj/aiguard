package handler

import (
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

func TestSecurityActionHeaderRecordDefaultsWithoutHidingExplicitEnable(t *testing.T) {
	for _, tc := range []struct {
		name, env string
		want      bool
	}{
		{"default", "", false}, {"explicit", "true", true}, {"disabled", "false", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MCP_GATEWAY_ENABLED", "false")
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			t.Setenv("SECURITY_ACTION_HEADER_ENABLED", tc.env)
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			cfg.SecurityAuditOnly = true
			w := httptest.NewRecorder()
			setSecurityActionHeader(w, "audit", securityActionHeaderEnabled(cfg))
			if got := w.Header().Get(SecurityActionHeader) != ""; got != tc.want {
				t.Fatalf("record header present=%v want=%v", got, tc.want)
			}
		})
	}
}
