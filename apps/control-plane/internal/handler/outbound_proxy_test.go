package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

func TestNormalizeOutboundProxyURL(t *testing.T) {
	valid, err := normalizeOutboundProxyURL(" https://user:password@proxy.example.test:8443 ")
	if err != nil {
		t.Fatalf("normalize valid proxy: %v", err)
	}
	if valid != "https://user:password@proxy.example.test:8443" {
		t.Fatalf("normalized proxy = %q", valid)
	}

	for _, raw := range []string{"", "socks5://proxy.example.test:1080", "http:///missing-host", "https://proxy.example.test/path", "https://proxy.example.test/?token=secret"} {
		if _, err := normalizeOutboundProxyURL(raw); err == nil {
			t.Errorf("normalizeOutboundProxyURL(%q) succeeded", raw)
		}
	}
}

func TestUpdateSystemSettingsEncryptsAndMasksOutboundProxy(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "outbound-proxy-test-key")
	repo := &capturingSystemRepo{}
	deps := &Dependencies{SystemRepo: repo}
	body, err := json.Marshal(map[string]any{
		"outbound_proxy_enabled": true,
		"outbound_proxy_url":     "http://proxy-user:proxy-password@proxy.customer.test:8080",
	})
	if err != nil {
		t.Fatal(err)
	}
	updateResponse := httptest.NewRecorder()
	UpdateSystemSettings(deps).ServeHTTP(updateResponse, adminCtxRequest(http.MethodPut, "/admin/v1/system/settings", body))
	if updateResponse.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", updateResponse.Code, updateResponse.Body.String())
	}

	ciphertext := repo.settings[outboundProxyURLSettingKey]
	if ciphertext == "" || !strings.HasPrefix(ciphertext, encryptedSecretPrefix) || strings.Contains(ciphertext, "proxy-password") {
		t.Fatalf("outbound proxy was not safely encrypted: %q", ciphertext)
	}
	plaintext, err := secrets.DecryptProviderSecret(ciphertext)
	if err != nil || plaintext != "http://proxy-user:proxy-password@proxy.customer.test:8080" {
		t.Fatalf("decrypt outbound proxy plaintext=%q err=%v", plaintext, err)
	}

	getResponse := httptest.NewRecorder()
	GetSystemSettings(deps).ServeHTTP(getResponse, adminCtxRequest(http.MethodGet, "/admin/v1/system/settings", nil))
	if getResponse.Code != http.StatusOK {
		t.Fatalf("get status=%d body=%s", getResponse.Code, getResponse.Body.String())
	}
	var view map[string]any
	if err := json.NewDecoder(getResponse.Body).Decode(&view); err != nil {
		t.Fatal(err)
	}
	if view[outboundProxyURLSettingKey] != maskedSecretValue || view[outboundProxyEnabledSettingKey] != "true" {
		t.Fatalf("unsafe outbound proxy view: %#v", view)
	}
}
