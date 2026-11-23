package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// r2922 对抗复核：文件类型“禁止”命中被内容例外放开后（引擎把动作降成 audit 并标上例外编号），
// 门户不能再只凭类别拦；无例外时防护模式照拦。
func TestPortalUploadBlockedTypeReleasedByContentException(t *testing.T) {
	for _, tc := range []struct {
		name    string
		finding string
		want    int
	}{
		{name: "exception", finding: `{"type":"file","category":"file_policy_blocked_type","severity":"high","rule_id":"file-policy-blocked-type:pdf","action":"audit","exception_id":"exc-pdf"}`, want: http.StatusOK},
		{name: "no exception", finding: `{"type":"file","category":"file_policy_blocked_type","severity":"high","rule_id":"file-policy-blocked-type:pdf","action":"block"}`, want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/scan-objects/"):
					_, _ = w.Write([]byte(`{"object_id":"obj_1234567890123456789012345678"}`))
				case strings.HasSuffix(r.URL.Path, "/check-input/"):
					_, _ = w.Write([]byte(`{"action":"audit","findings":[` + tc.finding + `]}`))
				case r.Method == http.MethodDelete:
					w.WriteHeader(http.StatusOK)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			t.Cleanup(eng.Close)
			deps := &Dependencies{
				SecurityEngineURL:           eng.URL,
				SecurityEngineInternalToken: "tok",
				SystemRepo:                  &contentConfigSystemRepo{settings: map[string]string{"file_content_dlp_enabled": "false", "security_execution_mode": "protect"}},
			}
			body := []byte("%PDF-1.7\n")
			req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/upload-ingest",
				strings.NewReader(portalUploadPayload(t, "", b64Std(body), shaHex(body))))
			req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
			w := httptest.NewRecorder()

			PortalUploadIngest(deps)(w, req)

			if w.Code != tc.want {
				t.Fatalf("status=%d want %d body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestPortalUploadExplicitTypePolicyBlocksOnlyUnexemptedBlockingHits(t *testing.T) {
	for _, tc := range []struct {
		name    string
		finding map[string]interface{}
		want    bool
	}{
		{"block", map[string]interface{}{"category": "file_policy_blocked_type", "rule_id": "file-policy-blocked-type:pdf", "action": "block"}, true},
		{"quarantine", map[string]interface{}{"category": "file_policy_blocked_type", "action": "quarantine"}, true},
		{"legacy rule id", map[string]interface{}{"rule_id": "file-policy-blocked-type", "action": "block"}, true},
		{"typed rule id", map[string]interface{}{"rule_id": "file-policy-blocked-type:exe", "action": "block"}, true},
		{"exception audit", map[string]interface{}{"category": "file_policy_blocked_type", "action": "audit", "exception_id": "exc"}, false},
		{"exception allow", map[string]interface{}{"category": "file_policy_blocked_type", "action": "allow", "exception_id": "exc"}, false},
		{"block with exception id", map[string]interface{}{"category": "file_policy_blocked_type", "action": "block", "exception_id": "exc"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := portalUploadExplicitTypePolicyBlocks([]map[string]interface{}{tc.finding}); got != tc.want {
				t.Fatalf("portalUploadExplicitTypePolicyBlocks = %v, want %v", got, tc.want)
			}
		})
	}
}
