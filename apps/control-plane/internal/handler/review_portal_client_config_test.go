package handler

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestReviewPortalClientConfigUsesTrustedOverrideOrSystemFallback(t *testing.T) {
	sys := newConsoleTestSystemRepo()
	sys.Set(context.Background(), "gateway_public_base_url", "https://system.test/v1")
	deps := &Dependencies{SystemRepo: sys}
	for _, tc := range []struct{ override, want string }{{"", "https://system.test/v1"}, {"https://explicit.test/custom/v1", "https://explicit.test/custom/v1"}} {
		req := httptest.NewRequest("GET", "/admin/v1/portal-integration/client-config", nil)
		req.Header.Set(portalIntegrationTenantHeader, "tenant")
		req.Header.Set("X-JJDGuard-Gateway-URL", tc.override)
		w := httptest.NewRecorder()
		GetPortalClientConfig(deps)(w, req)
		var reply struct {
			URL string `json:"api_url"`
		}
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.URL != tc.want {
			t.Fatalf("status=%d url=%s want=%s", w.Code, reply.URL, tc.want)
		}
		if w.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatal("client config cached")
		}
	}
}
func TestReviewPortalClientConfigMachineAuthentication(t *testing.T) {
	deps := &Dependencies{SystemRepo: newConsoleTestSystemRepo()}
	h := PortalIntegrationAPIMiddleware("fixture-machine-secret", deps)(GetPortalClientConfig(deps))
	for _, token := range []string{"", "fixture-machine-secret"} {
		req := httptest.NewRequest("GET", "/admin/v1/portal-integration/client-config", nil)
		req.Header.Set(portalIntegrationTenantHeader, "tenant")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		expected := 401
		if token != "" {
			expected = 200
		}
		if w.Code != expected {
			t.Fatalf("machine authentication=%d want=%d", w.Code, expected)
		}
	}
}
