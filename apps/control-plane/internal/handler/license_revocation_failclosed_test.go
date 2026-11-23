package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	entlicense "github.com/yangjiyj/aiguard/apps/control-plane/internal/license"
)

// 吊销列表 fail-closed：配置了 JJD_LICENSE_REVOCATION_FILE 但不可读/截断/非法 JSON 时，
// 许可证必须判为无效；未配置、可读未吊销、可读已吊销三种情况保持原语义。
func TestLicenseStatusRevocationListFailClosed(t *testing.T) {
	now := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC) // 列表 ValidUntil=2026-06-30，签名有效期内
	token, publicKeys := signedV2HandlerLicense(t, nil)
	marshal := func(revoked bool) []byte {
		list := signedV2HandlerRevocationList(t, func(p *entlicense.RevocationPayload) {
			if revoked {
				p.RevokedLicenses = []entlicense.RevokedLicense{{LicenseID: "lic_v2_handler_unit"}}
			} else {
				p.RevokedLicenses = []entlicense.RevokedLicense{{LicenseID: "lic_other"}}
			}
		})
		data, err := json.Marshal(list)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	valid := marshal(false)
	cases := []struct {
		name        string
		setup       func(t *testing.T) string // 返回 JJD_LICENSE_REVOCATION_FILE；"" 表示未配置
		wantValid   bool
		wantStatus  string
		wantReason  string
		wantRevoked bool
	}{
		{name: "unreadable_mode_0000", setup: func(t *testing.T) string {
			if os.Geteuid() == 0 {
				t.Skip("root ignores file mode 0000")
			}
			path := writeRevocationFile(t, valid, 0o600)
			if err := os.Chmod(path, 0o000); err != nil {
				t.Fatal(err)
			}
			return path
		}, wantValid: false, wantStatus: entlicense.StatusInvalid, wantReason: entlicense.ErrRevocationListUnavailable.Error()},
		{name: "truncated", setup: func(t *testing.T) string {
			return writeRevocationFile(t, valid[:len(valid)/2], 0o600)
		}, wantValid: false, wantStatus: entlicense.StatusInvalid, wantReason: entlicense.ErrRevocationListUnavailable.Error()},
		{name: "invalid_json", setup: func(t *testing.T) string {
			return writeRevocationFile(t, []byte("not-json{"), 0o600)
		}, wantValid: false, wantStatus: entlicense.StatusInvalid, wantReason: entlicense.ErrRevocationListUnavailable.Error()},
		{name: "missing_file", setup: func(t *testing.T) string {
			return t.TempDir() + "/absent.json"
		}, wantValid: false, wantStatus: entlicense.StatusInvalid, wantReason: entlicense.ErrRevocationListUnavailable.Error()},
		{name: "tampered_signature", setup: func(t *testing.T) string {
			list := signedV2HandlerRevocationList(t, nil)
			list.Payload.RevokedLicenses = []entlicense.RevokedLicense{{LicenseID: "lic_other"}}
			data, _ := json.Marshal(list)
			return writeRevocationFile(t, data, 0o600)
		}, wantValid: false, wantStatus: entlicense.StatusInvalid, wantReason: entlicense.ErrRevocationListUnavailable.Error()},
		{name: "expired_list", setup: func(t *testing.T) string {
			list := signedV2HandlerRevocationList(t, func(p *entlicense.RevocationPayload) { p.ValidUntil = "2026-06-21T12:00:00Z" })
			data, _ := json.Marshal(list)
			return writeRevocationFile(t, data, 0o600)
		}, wantValid: false, wantStatus: entlicense.StatusInvalid, wantReason: entlicense.ErrRevocationListUnavailable.Error()},
		{name: "not_configured", setup: func(t *testing.T) string { return "" }, wantValid: true, wantStatus: entlicense.StatusActive},
		{name: "readable_not_revoked", setup: func(t *testing.T) string {
			return writeRevocationFile(t, valid, 0o600)
		}, wantValid: true, wantStatus: entlicense.StatusActive},
		{name: "readable_revoked", setup: func(t *testing.T) string {
			return writeRevocationFile(t, marshal(true), 0o600)
		}, wantValid: false, wantStatus: entlicense.StatusInvalid, wantReason: entlicense.ErrLicenseRevoked.Error(), wantRevoked: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
			t.Setenv("JJD_LICENSE_REVOCATION_FILE", tc.setup(t))
			deps := &Dependencies{SystemRepo: &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: token}}}
			req := licenseAdminRequest(http.MethodGet, "/admin/v1/system/license", nil)
			got := licenseStatusFromStored(req, deps, token, "", now)
			if got.Valid != tc.wantValid || got.Status != tc.wantStatus {
				t.Fatalf("valid=%v status=%q reason=%q, want valid=%v status=%q", got.Valid, got.Status, got.Reason, tc.wantValid, tc.wantStatus)
			}
			if tc.wantReason != "" && !strings.Contains(got.Reason, tc.wantReason) {
				t.Fatalf("reason=%q, want contains %q", got.Reason, tc.wantReason)
			}
			if path := os.Getenv("JJD_LICENSE_REVOCATION_FILE"); path != "" && strings.Contains(got.Reason, path) {
				t.Fatalf("reason leaks revocation file path: %q", got.Reason)
			}
			if tc.wantRevoked && (got.Revocation == nil || !got.Revocation.Revoked) {
				t.Fatalf("revocation=%+v, want revoked", got.Revocation)
			}
		})
	}
}

// LicenseGuard 与 agentSecurityLicensed 经由 status.Valid 自然拒绝，无需旁路。
func TestLicenseGuardAndAgentSecurityRejectUnavailableRevocationList(t *testing.T) {
	token, publicKeys := signedV2HandlerLicense(t, func(p *entlicense.PayloadV2) {
		p.Features = append(p.Features, "agent_security")
	})
	t.Setenv("JJD_LICENSE_ENFORCE", "true")
	t.Setenv("JJD_LICENSE_PUBLIC_KEYS", publicKeys)
	t.Setenv("JJD_LICENSE_REVOCATION_FILE", writeRevocationFile(t, []byte(`{"schemaVersion":"license-rev`), 0o600))
	deps := &Dependencies{SystemRepo: &licenseSystemRepo{settings: map[string]string{LicenseSettingKey: token}}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("next must not be called with unavailable revocation list")
	})
	w := httptest.NewRecorder()
	LicenseGuard(deps)(next).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/admin/v1/users", nil))
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("LicenseGuard status=%d body=%s, want 402", w.Code, w.Body.String())
	}
	licensed, err := agentSecurityLicensed(httptest.NewRequest(http.MethodGet, "/admin/v1/agent/license", nil), deps)
	if err != nil || licensed {
		t.Fatalf("agentSecurityLicensed=%v err=%v, want false,nil", licensed, err)
	}
}

func writeRevocationFile(t *testing.T, data []byte, mode os.FileMode) string {
	t.Helper()
	path := t.TempDir() + "/revocations.json"
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	return path
}
