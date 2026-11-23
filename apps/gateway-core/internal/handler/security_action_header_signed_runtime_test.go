package handler

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

func TestSecurityActionHeaderSignedRuntimeMode(t *testing.T) {
	for _, tc := range []struct {
		name, header string
		record, want bool
	}{
		{"record default", "", true, false}, {"protect default", "", false, true},
		{"record explicit", "true", true, true}, {"protect disabled", "false", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("MCP_GATEWAY_ENABLED", "false")
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			t.Setenv("SECURITY_ACTION_HEADER_ENABLED", tc.header)
			cfg, err := config.Load()
			if err != nil {
				t.Fatal(err)
			}
			client := failClosedClient(t, tc.record, false)
			w := httptest.NewRecorder()
			setSecurityActionHeader(w, "audit", securityActionHeaderEnabledForRuntime(context.Background(), cfg, client))
			if got := w.Header().Get(SecurityActionHeader) != ""; got != tc.want {
				t.Fatalf("signed runtime header present=%v want=%v", got, tc.want)
			}
		})
	}
}
