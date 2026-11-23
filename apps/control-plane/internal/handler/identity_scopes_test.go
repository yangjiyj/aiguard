package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// W9 9.8：scopes 保存即校验（缺 openid / 非法字符 / 超长 → 400），合法值规整后落库。
func TestNormalizeIdentityScopes(t *testing.T) {
	for raw, want := range map[string]string{
		"":                                "openid profile email",
		"   ":                             "openid profile email",
		"openid":                          "openid",
		"  openid   profile\temail ":      "openid profile email",
		"openid profile openid email":     "openid profile email",
		"profile openid offline_access":   "profile openid offline_access",
		"openid https://api.example/read": "openid https://api.example/read",
	} {
		got, msg := normalizeIdentityScopes(raw)
		if msg != "" || got != want {
			t.Fatalf("%q => %q, %q; want %q", raw, got, msg, want)
		}
	}
	for _, raw := range []string{
		"profile email",
		"openid,profile",
		"openid \"x\"",
		"openid a\\b",
		"openid " + strings.Repeat("x", 256),
		"openid\u00a0profile",
	} {
		if _, msg := normalizeIdentityScopes(raw); msg == "" {
			t.Fatalf("%q accepted", raw)
		}
	}
}

func TestSaveDraftRejectsScopesWithoutOpenID(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildIdentityDeps(pool)
	save := func(scopes string) *httptest.ResponseRecorder {
		payload, _ := json.Marshal(map[string]string{
			"display_name": "Enterprise IdP", "issuer_url": "https://idp.example.com", "client_id": "c",
			"client_secret": "s", "scopes": scopes,
		})
		req := withOrgUserCtx(httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft", bytes.NewReader(payload)), tenantID, userID)
		w := httptest.NewRecorder()
		SaveIdentityDraft(deps)(w, req)
		return w
	}
	if w := save("profile email"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "openid") {
		t.Fatalf("missing openid: %d %s", w.Code, w.Body.String())
	}
	w := save("  openid  profile openid groups ")
	if w.Code != http.StatusOK {
		t.Fatalf("valid scopes rejected: %d %s", w.Code, w.Body.String())
	}
	var dto identitySourceDTO
	_ = json.Unmarshal(w.Body.Bytes(), &dto)
	if dto.Scopes != "openid profile groups" {
		t.Fatalf("scopes not normalized: %q", dto.Scopes)
	}
}
