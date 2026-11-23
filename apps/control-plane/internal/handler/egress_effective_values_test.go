package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 控制台读到的是实际生效值：库里没有键时返回环境变量折算的值并标来源，库里有键时以库为准。
func TestGetSystemSettingsShowsEffectiveEgressValuesWithSource(t *testing.T) {
	t.Setenv("GATEWAY_FORWARD_PROXY_MODE", "tunnel_audit")
	t.Setenv("PROXY_WHITELIST_FAIL_MODE", "open")
	t.Setenv("JJD_IDP_BLOCK_PRIVATE", "true")
	t.Setenv("JJD_IDP_ALLOW_CIDRS", "10.0.0.0/8")
	t.Setenv("DIRECTORY_LDAP_TARGET_ALLOWLIST", "DC.corp.test")
	repo := &capturingSystemRepo{settings: map[string]string{"proxy_whitelist_fail_mode": "closed"}}
	w := httptest.NewRecorder()
	GetSystemSettings(&Dependencies{SystemRepo: repo}).ServeHTTP(w, adminCtxRequest(http.MethodGet, "/admin/v1/system/settings", nil))
	var data map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &data); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"forward_proxy_unlisted_action": "allow_audit", "proxy_whitelist_fail_mode": "closed",
		"idp_block_private": "true", "idp_allowed_cidrs": `["10.0.0.0/8"]`, "ldap_allowed_targets": `["dc.corp.test:636"]`,
		"forward_proxy_egress_allow_private": "false", "forward_proxy_egress_allowed_cidrs": "[]",
	}
	for key, value := range want {
		if data[key] != value {
			t.Errorf("%s = %v, want %s", key, data[key], value)
		}
	}
	sources, _ := data["egress_setting_sources"].(map[string]any)
	for key, source := range map[string]string{
		"forward_proxy_unlisted_action": "env", "proxy_whitelist_fail_mode": "db", "idp_allowed_cidrs": "env",
		"ldap_allowed_targets": "env", "forward_proxy_egress_allow_private": "default",
	} {
		if sources[key] != source {
			t.Errorf("source[%s] = %v, want %s", key, sources[key], source)
		}
	}
}
