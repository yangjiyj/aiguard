package handler

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// TestSecurityForwardsInternalToken 覆盖控制台「安全检测测试」转发到 security-engine /test/
// 时必须带内部令牌：引擎配置了 JJD_INTERNAL_API_SECRET 后，无令牌请求一律 401。
func TestSecurityForwardsInternalToken(t *testing.T) {
	const token = "internal-secret-for-test"

	var gotToken, gotPath, gotContentType string
	var gotBody map[string]any
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotToken = r.Header.Get(InternalAPISecretHeader)
		gotContentType = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		if gotToken != token {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid internal token"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"findings":[],"action":"allow","latency_ms":1}`))
	}))
	defer engine.Close()

	deps := &Dependencies{
		SecurityEngineURL:           engine.URL,
		SecurityEngineInternalToken: token,
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/security/test", strings.NewReader(`{"text":"hello"}`))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "u_1", TenantID: "t_1"}))
	rec := httptest.NewRecorder()

	TestSecurity(deps)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if gotPath != "/test/" {
		t.Fatalf("engine path = %q, want /test/", gotPath)
	}
	if gotToken != token {
		t.Fatalf("engine got %s = %q, want the configured internal token", InternalAPISecretHeader, gotToken)
	}
	if gotContentType != "application/json" {
		t.Fatalf("engine Content-Type = %q", gotContentType)
	}
	if gotBody["text"] != "hello" {
		t.Fatalf("engine body text = %v", gotBody["text"])
	}
	if !strings.Contains(rec.Body.String(), `"action":"allow"`) {
		t.Fatalf("response not relayed: %s", rec.Body.String())
	}
}
