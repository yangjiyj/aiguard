package handler

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestGatewayAccessSettingsNormalizeAndRejectUnsafeURLs(t *testing.T) {
	good := map[string]string{"gateway_public_base_url": " https://models.example:8443/customer/v1/v1/ ", "gateway_public_url_mode": "current_origin", "gateway_public_endpoints": `[{"name":"内网","url":"http://[2001:db8::1]:8084/prefix/"}]`}
	if err := normalizeGatewayPublicSettings(good); err != nil {
		t.Fatal(err)
	}
	if good["gateway_public_base_url"] != "https://models.example:8443/customer/v1" {
		t.Fatal(good)
	}
	var endpoints []gatewayPublicEndpoint
	if err := json.Unmarshal([]byte(good["gateway_public_endpoints"]), &endpoints); err != nil || len(endpoints) != 1 || endpoints[0].URL != "http://[2001:db8::1]:8084/prefix/v1" {
		t.Fatal(good)
	}
	for _, raw := range []string{"javascript:alert(1)", "https://user:password@gateway/v1", "https://gateway/v1?key=secret", "https://gateway/v1#fragment", "http://gateway:0/v1", "http://gateway:70000/v1", "https://gateway/../admin", "https://gateway/%2e%2e/admin", "https://gateway/a%2fb/v1", "https://gateway/v1\\admin", "http://gateway/\nadmin"} {
		settings := map[string]string{"gateway_public_base_url": raw}
		if normalizeGatewayPublicSettings(settings) == nil {
			t.Errorf("accepted unsafe URL %q", raw)
		}
	}
	for _, raw := range []string{`{}`, `null`, `[{"name":"","url":"http://gateway"}]`, `[{"name":"内网","url":"ftp://gateway"}]`, `[{"name":"内网","url":"http://gateway","extra":true}]`, `[{"name":"a","url":"http://gateway/v1"},{"name":"b","url":"http://gateway/"}]`} {
		if normalizeGatewayPublicSettings(map[string]string{"gateway_public_endpoints": raw}) == nil {
			t.Errorf("accepted endpoints %s", raw)
		}
	}
	if normalizeGatewayPublicSettings(map[string]string{"gateway_public_url_mode": "guess_ip"}) == nil {
		t.Fatal("invalid mode accepted")
	}
}
func TestPortalClientConfigIncludesNetworkEndpointsWithoutPrivateSettings(t *testing.T) {
	sys := newConsoleTestSystemRepo()
	sys.Set(context.Background(), "gateway_public_base_url", "https://customer.example/v1")
	sys.Set(context.Background(), "gateway_public_endpoints", `[{"name":"内网","url":"http://192.168.1.10:8084/v1"}]`)
	sys.Set(context.Background(), "gateway_public_url_mode", "current_origin")
	sys.Set(context.Background(), "judge_api_key", "private")
	req := httptest.NewRequest("GET", "/admin/v1/portal-integration/client-config", nil)
	req.Header.Set(portalIntegrationTenantHeader, "tenant")
	req.Header.Set("X-Forwarded-Host", "attacker.example")
	w := httptest.NewRecorder()
	GetPortalClientConfig(&Dependencies{SystemRepo: sys})(w, req)
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || got["api_url"] != "https://customer.example/v1" || got["gateway_public_url_mode"] != "current_origin" || len(got["gateway_public_endpoints"].([]any)) != 1 {
		t.Fatal(w.Body.String())
	}
	if _, ok := got["judge_api_key"]; ok {
		t.Fatal("private setting exposed")
	}
}

func TestUpdateGatewayAccessSettingsValidateBeforeWriting(t *testing.T) {
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	w := httptest.NewRecorder()
	UpdateSystemSettings(deps)(w, adminCtxRequest("PUT", "/admin/v1/system/settings", []byte(`{"gateway_public_endpoints":[{"name":"内网","url":"http://customer:8084"}],"gateway_public_url_mode":"current_origin"}`)))
	if w.Code != 200 || repo.settings["gateway_public_endpoints"] != `[{"name":"内网","url":"http://customer:8084/v1"}]` {
		t.Fatal(w.Code, w.Body.String(), repo.settings)
	}
	before := repo.settings["gateway_public_endpoints"]
	w = httptest.NewRecorder()
	UpdateSystemSettings(deps)(w, adminCtxRequest("PUT", "/admin/v1/system/settings", []byte(`{"gateway_public_endpoints":[{"name":"bad","url":"https://user:password@internal/v1"}],"gateway_public_base_url":"https://safe.example/v1"}`)))
	if w.Code != 400 || repo.settings["gateway_public_endpoints"] != before || repo.settings["gateway_public_base_url"] != "" {
		t.Fatal("invalid batch wrote settings", w.Code, repo.settings)
	}
}

func TestGatewayAccessCurrentHostModePreservesAPICoordinates(t *testing.T) {
	settings := map[string]string{"gateway_public_url_mode": "current_host", "gateway_public_base_url": "http://customer.test:8080/v1"}
	if err := normalizeGatewayPublicSettings(settings); err != nil {
		t.Fatal(err)
	}
	sys := newConsoleTestSystemRepo()
	for key, value := range settings {
		sys.Set(context.Background(), key, value)
	}
	base, mode, _, err := portalGatewayAccessSettings(context.Background(), &Dependencies{SystemRepo: sys}, "")
	if err != nil || mode != "current_host" || base != "http://customer.test:8080/v1" {
		t.Fatal(base, mode, err)
	}
}
