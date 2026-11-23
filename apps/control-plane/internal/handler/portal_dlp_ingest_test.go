package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionstore"
)

// mockRetentionStore 记录 PutObject 调用次数（验证被阻断文件未写 retention）。
type mockRetentionStore struct {
	puts int
}

func (m *mockRetentionStore) PutObject(ctx context.Context, input retentionstore.PutObjectInput) (retentionstore.ObjectMetadata, error) {
	m.puts++
	return retentionstore.ObjectMetadata{Key: "ref-key"}, nil
}
func (m *mockRetentionStore) GetObject(ctx context.Context, tenantID, key string) (retentionstore.Object, error) {
	return retentionstore.Object{}, nil
}
func (m *mockRetentionStore) DeleteObject(ctx context.Context, tenantID, key string) error {
	return nil
}
func (m *mockRetentionStore) ReapExpired(ctx context.Context, now time.Time) (int, error) {
	return 0, nil
}

// portalUploadPayload 构造门户上传 JSON。
func portalUploadPayload(t *testing.T, text, b64, sha string) string {
	t.Helper()
	decoded, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(map[string]interface{}{
		"user_id":        "u1",
		"filename":       "secret.docx",
		"mime_type":      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"size":           len(decoded),
		"sha256":         sha,
		"bytes_base64":   b64,
		"extracted_text": text,
	})
	return string(b)
}

func TestPortalUploadIngest_DLPBlockedReturns403AndNoRetention(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	// security-engine 返回 block（命中敏感内容）
	var objectIDPosted, base64Posted, consumed bool
	eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/scan-objects/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"object_id":"obj_1234567890123456789012345678","sha256":"x","size":9}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/check-input/") {
			body, _ := io.ReadAll(r.Body)
			objectIDPosted = objectIDPosted || strings.Contains(string(body), `"object_id"`)
			base64Posted = base64Posted || strings.Contains(string(body), `"data_base64"`)
			w.WriteHeader(200)
			w.Write([]byte(`{"action":"block","findings":[{"type":"pii","category":"file_content_phone_cn","severity":"high","rule_id":"phone-cn"}]}`))
			return
		}
		if r.Method == http.MethodDelete {
			consumed = true
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"action":"audit"}`))
	}))
	t.Cleanup(eng.Close)

	rs := &mockRetentionStore{}
	deps := &Dependencies{
		SecurityEngineURL:           eng.URL,
		SecurityEngineInternalToken: "tok",
		RetentionStore:              rs,
		PortalUploadEventRepo:       nil, // 阻断时不写 retention repo 也不崩
		SystemRepo:                  &contentConfigSystemRepo{settings: map[string]string{"file_content_dlp_enabled": "true", "security_execution_mode": "protect"}},
	}
	// sha256 of "docx body"
	body := []byte("docx body")
	sha := shaHex(body)
	req := httptest.NewRequest("PUT", "/admin/v1/portal-integration/upload-ingest",
		strings.NewReader(portalUploadPayload(t, "正文", b64Std(body), sha)))
	req.Header.Set("X-JJDGuard-Tenant", "tenant_default")
	req.Header.Set("X-Portal-API-Secret", "x")
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	PortalUploadIngest(deps)(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}
	if rs.puts != 0 {
		t.Fatalf("被阻断文件不得写 retention store, got %d puts", rs.puts)
	}
	if !objectIDPosted || base64Posted {
		t.Fatalf("门户文件检测必须使用 object_id，不能二次传 base64")
	}
	if !consumed {
		t.Fatalf("检测完成后必须即焚临时对象")
	}
}

func TestPortalUploadIngest_EngineUnavailableRecordsGapInProtectMode(t *testing.T) {
	// 检测引擎不可用属于检测未完成：防护模式下同样放行并留痕为覆盖缺口，不以 403 中断。
	eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	t.Cleanup(eng.Close)
	rs := &mockRetentionStore{}
	deps := &Dependencies{
		SecurityEngineURL: eng.URL, SecurityEngineInternalToken: "tok",
		RetentionStore: rs, SystemRepo: &contentConfigSystemRepo{settings: map[string]string{"file_content_dlp_enabled": "true", "security_execution_mode": "protect"}},
	}
	body := []byte("docx body")
	req := httptest.NewRequest("PUT", "/admin/v1/portal-integration/upload-ingest",
		strings.NewReader(portalUploadPayload(t, "x", b64Std(body), shaHex(body))))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	PortalUploadIngest(deps)(w, req)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"action":"audit"`) {
		t.Fatalf("engine outage is a coverage gap and must be forwarded as audit, got %d body=%s", w.Code, w.Body.String())
	}
	if rs.puts != 0 {
		t.Fatalf("portal ingest must never retain the original file, got %d puts", rs.puts)
	}
}

func TestPortalUploadIngest_AuditOnlyEngineUnavailableAllows(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(eng.Close)

	body := []byte("clean body")
	deps := &Dependencies{
		SecurityEngineURL:           eng.URL,
		SecurityEngineInternalToken: "tok",
		SystemRepo:                  &contentConfigSystemRepo{settings: map[string]string{"file_content_dlp_enabled": "true", "security_audit_only": "true"}},
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/upload-ingest",
		strings.NewReader(portalUploadPayload(t, "clean", b64Std(body), shaHex(body))))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()

	PortalUploadIngest(deps)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("audit-only engine outage must not block upload, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"action":"audit"`) {
		t.Fatalf("audit-only engine outage must be recorded as audit, body=%s", w.Body.String())
	}
}

func TestPortalUploadIngest_ContentDLPDisabledStillScansFileType(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	var attachmentScans, textScans int32
	eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/scan-objects/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"object_id":"obj_1234567890123456789012345678"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/check-input/") {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), `"object_id"`) {
				atomic.AddInt32(&attachmentScans, 1)
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"action":"audit","findings":[{"type":"file","category":"file_policy_not_allowed","severity":"medium","rule_id":"file-policy-not-allowed"}]}`))
				return
			}
			atomic.AddInt32(&textScans, 1)
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"action":"audit"}`))
	}))
	t.Cleanup(eng.Close)
	rs := &mockRetentionStore{}
	deps := &Dependencies{
		SecurityEngineURL: eng.URL, SecurityEngineInternalToken: "tok",
		RetentionStore: rs,
		SystemRepo: &contentConfigSystemRepo{settings: map[string]string{
			"security_audit_only":      "true",
			"content_file_policy_json": `{"allowed_types":["pdf"],"blocked_types":["pe","script"],"review_types":["zip","rar","7z","unknown"],"max_file_mb":20,"max_zip_ratio":100,"max_attachments":10}`,
		}},
	}
	body := []byte("clean body")
	req := httptest.NewRequest("PUT", "/admin/v1/portal-integration/upload-ingest",
		strings.NewReader(portalUploadPayload(t, "clean", b64Std(body), shaHex(body))))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	PortalUploadIngest(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("content DLP disabled upload should succeed in audit mode, got %d body=%s", w.Code, w.Body.String())
	}
	if got := atomic.LoadInt32(&attachmentScans); got != 1 {
		t.Fatalf("file type policy must scan the raw attachment when content DLP is disabled, got %d scans", got)
	}
	if got := atomic.LoadInt32(&textScans); got != 0 {
		t.Fatalf("content DLP disabled must not run the extracted-text scan, got %d scans", got)
	}
	if rs.puts != 0 {
		t.Fatalf("DLP disabled must not retain original file, got %d puts", rs.puts)
	}
}

func TestPortalUploadIngest_ExtractedTextBlockStopsUpload(t *testing.T) {
	var checkCalls int32
	eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/scan-objects/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"object_id":"obj_1234567890123456789012345678"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/check-input/") {
			if atomic.AddInt32(&checkCalls, 1) == 1 {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"action":"audit","findings":[]}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"action":"block","findings":[{"type":"pii","category":"file_text_phone_cn","severity":"high","rule_id":"phone-cn"}]}`))
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(eng.Close)

	deps := &Dependencies{
		SecurityEngineURL:           eng.URL,
		SecurityEngineInternalToken: "tok",
		SystemRepo:                  &contentConfigSystemRepo{settings: map[string]string{"file_content_dlp_enabled": "true", "security_execution_mode": "protect"}},
	}
	body := []byte("clean bytes")
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/upload-ingest",
		strings.NewReader(portalUploadPayload(t, "sensitive extracted text", b64Std(body), shaHex(body))))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()

	PortalUploadIngest(deps)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("block from extracted-text scan must stop upload, got %d body=%s", w.Code, w.Body.String())
	}
	if atomic.LoadInt32(&checkCalls) != 2 {
		t.Fatalf("expected object scan plus extracted-text scan, got %d", checkCalls)
	}
}

func TestPortalUploadIngest_AuditOnlyFileFindingAllows(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/scan-objects/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{\"object_id\":\"obj_1234567890123456789012345678\"}"))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/check-input/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{\"action\":\"audit\",\"findings\":[{\"type\":\"pii\",\"category\":\"phone_cn\",\"severity\":\"medium\",\"rule_id\":\"regex_phone_cn\"}]}"))
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(eng.Close)

	deps := &Dependencies{
		SecurityEngineURL:           eng.URL,
		SecurityEngineInternalToken: "tok",
		SystemRepo:                  &contentConfigSystemRepo{settings: map[string]string{"file_content_dlp_enabled": "true", "security_audit_only": "true"}},
	}
	body := []byte("sensitive bytes")
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/upload-ingest",
		strings.NewReader(portalUploadPayload(t, "sensitive extracted text", b64Std(body), shaHex(body))))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()

	PortalUploadIngest(deps)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("audit-only file finding must allow portal upload, got %d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"action":"audit"`) {
		t.Fatalf("audit-only file finding must be recorded as audit, body=%s", w.Body.String())
	}
}

func TestRecordModeNeverEnforces_PortalExplicitBlockedFileType(t *testing.T) {
	for _, tc := range []struct {
		name     string
		settings map[string]string
		env      string
		want     int
	}{
		{name: "deployment lock", env: "true", settings: map[string]string{"file_content_dlp_enabled": "false", "security_audit_only": "true"}, want: http.StatusOK},
		{name: "console record", env: "false", settings: map[string]string{"file_content_dlp_enabled": "false", "security_execution_mode": "record"}, want: http.StatusOK},
		{name: "console protect", env: "false", settings: map[string]string{"file_content_dlp_enabled": "false", "security_execution_mode": "protect"}, want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", tc.env)
			eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/scan-objects/") {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"object_id":"obj_1234567890123456789012345678"}`))
					return
				}
				if strings.HasSuffix(r.URL.Path, "/check-input/") {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"action":"audit","findings":[{"type":"file","category":"file_policy_blocked_type","severity":"high","rule_id":"file-policy-blocked-type","action":"block"}]}`))
					return
				}
				if r.Method == http.MethodDelete {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			t.Cleanup(eng.Close)

			deps := &Dependencies{
				SecurityEngineURL:           eng.URL,
				SecurityEngineInternalToken: "tok",
				SystemRepo:                  &contentConfigSystemRepo{settings: tc.settings},
			}
			body := []byte("%PDF-1.7\n")
			req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/upload-ingest",
				strings.NewReader(portalUploadPayload(t, "", b64Std(body), shaHex(body))))
			req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
			w := httptest.NewRecorder()

			PortalUploadIngest(deps)(w, req)

			if w.Code != tc.want {
				t.Fatalf("explicit blocked file type status=%d want %d body=%s", w.Code, tc.want, w.Body.String())
			}
			if tc.want == http.StatusOK && !strings.Contains(w.Body.String(), `"action":"audit"`) {
				t.Fatalf("record mode must record the explicit type hit as audit, body=%s", w.Body.String())
			}
		})
	}
}

// policyKeyFailingRepo 只让文件策略键读取失败，模式等其他键照常返回。
type policyKeyFailingRepo struct {
	contentConfigSystemRepo
}

func (r *policyKeyFailingRepo) Get(ctx context.Context, key string) (*repository.SystemSetting, error) {
	if key == contentFilePolicySettingKeyForTenant("tenant_default") {
		return nil, errors.New("policy store down")
	}
	return r.contentConfigSystemRepo.Get(ctx, key)
}

func TestPortalUploadIngest_PolicyStoreFailureRecordsGap(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/scan-objects/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"object_id":"obj_1234567890123456789012345678"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/check-input/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"action":"audit","findings":[]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(eng.Close)
	for name, repo := range map[string]SystemRepo{
		"unavailable": &policyKeyFailingRepo{contentConfigSystemRepo{settings: map[string]string{"security_execution_mode": "protect"}}},
		"invalid":     &contentConfigSystemRepo{settings: map[string]string{"content_file_policy_json": "{not json", "security_execution_mode": "protect"}},
	} {
		t.Run(name, func(t *testing.T) {
			deps := &Dependencies{SecurityEngineURL: eng.URL, SecurityEngineInternalToken: "tok", SystemRepo: repo}
			body := []byte("clean")
			req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/upload-ingest",
				strings.NewReader(portalUploadPayload(t, "", b64Std(body), shaHex(body))))
			req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
			w := httptest.NewRecorder()
			PortalUploadIngest(deps)(w, req)
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"action":"audit"`) {
				t.Fatalf("file policy load failure is a coverage gap, got %d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestPortalUploadIngest_DLPOnCleanFileDoesNotRetainOriginal(t *testing.T) {
	eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"object_id":"obj_1234567890123456789012345678"}`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"action":"allow","findings":[]}`))
	}))
	t.Cleanup(eng.Close)
	rs := &mockRetentionStore{}
	deps := &Dependencies{
		SecurityEngineURL: eng.URL, SecurityEngineInternalToken: "tok",
		RetentionStore: rs, SystemRepo: &contentConfigSystemRepo{settings: map[string]string{"file_content_dlp_enabled": "true"}},
	}
	body := []byte("clean")
	req := httptest.NewRequest("PUT", "/admin/v1/portal-integration/upload-ingest",
		strings.NewReader(portalUploadPayload(t, "clean", b64Std(body), shaHex(body))))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	PortalUploadIngest(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("clean file with DLP on should pass, got %d", w.Code)
	}
	if rs.puts != 0 {
		t.Fatalf("clean file must not retain original after DLP pass, got %d puts", rs.puts)
	}
}

func TestPortalUploadIngest_ContentAuditCarriesRequestID(t *testing.T) {
	var requestIDs []string
	eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/scan-objects/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"object_id":"obj_1234567890123456789012345678"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/check-input/") {
			var payload struct {
				RequestID string `json:"request_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("decode security-engine request: %v", err)
			}
			requestIDs = append(requestIDs, payload.RequestID)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"action":"allow","findings":[]}`))
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(eng.Close)

	body := []byte("clean")
	deps := &Dependencies{
		SecurityEngineURL:           eng.URL,
		SecurityEngineInternalToken: "tok",
		SystemRepo:                  &contentConfigSystemRepo{settings: map[string]string{"file_content_dlp_enabled": "true"}},
	}
	req := httptest.NewRequest("PUT", "/admin/v1/portal-integration/upload-ingest",
		strings.NewReader(portalUploadPayload(t, "clean", b64Std(body), shaHex(body))))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	PortalUploadIngest(deps)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("clean file with DLP on should pass, got %d body=%s", w.Code, w.Body.String())
	}
	if len(requestIDs) != 2 {
		t.Fatalf("expected object scan and text audit requests, got %d", len(requestIDs))
	}
	for i, requestID := range requestIDs {
		if requestID == "" {
			t.Fatalf("security-engine request %d missing request_id", i+1)
		}
	}
}

func TestPortalUploadIngest_DLPOnWithoutEngineURLRecordsGap(t *testing.T) {
	rs := &mockRetentionStore{}
	deps := &Dependencies{RetentionStore: rs, SystemRepo: &contentConfigSystemRepo{settings: map[string]string{"file_content_dlp_enabled": "true", "security_execution_mode": "protect"}}}
	body := []byte("clean")
	req := httptest.NewRequest("PUT", "/admin/v1/portal-integration/upload-ingest",
		strings.NewReader(portalUploadPayload(t, "clean", b64Std(body), shaHex(body))))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()

	PortalUploadIngest(deps)(w, req)

	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"action":"audit"`) {
		t.Fatalf("missing engine configuration is a coverage gap, got %d body=%s", w.Code, w.Body.String())
	}
	if rs.puts != 0 {
		t.Fatalf("portal ingest must never retain the original file, puts=%d", rs.puts)
	}
}

func TestPortalUploadIngest_RejectsFileAboveTenantLimitBeforeDecode(t *testing.T) {
	rs := &mockRetentionStore{}
	deps := &Dependencies{RetentionStore: rs, SystemRepo: &contentConfigSystemRepo{}}
	payload, _ := json.Marshal(map[string]interface{}{
		"user_id":        "u1",
		"filename":       "huge.docx",
		"mime_type":      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"size":           int64(21 * 1024 * 1024),
		"sha256":         "not-evaluated",
		"bytes_base64":   "AAAA",
		"extracted_text": "",
	})
	req := httptest.NewRequest("PUT", "/admin/v1/portal-integration/upload-ingest", strings.NewReader(string(payload)))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()

	PortalUploadIngest(deps)(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("file above default 20MB tenant limit must return 413, got %d body=%s", w.Code, w.Body.String())
	}
	if rs.puts != 0 {
		t.Fatalf("oversized file must be rejected before retention, puts=%d", rs.puts)
	}
}

func shaHex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func b64Std(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// 任务4：门户按动态 system_settings.file_content_dlp_enabled 决定是否做附件内容扫描，
// 无需重启或重建 handler。附件扫描走 scan-objects 上传；DB 从关→开后第二次上传才扫附件。
func TestPortalUploadIngest_RuntimeDBSwitchTogglesScan(t *testing.T) {
	var attachmentScans int32
	eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/scan-objects/") {
			atomic.AddInt32(&attachmentScans, 1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"object_id":"obj_1234567890123456789012345678"}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/check-input/") {
			w.WriteHeader(200)
			w.Write([]byte(`{"action":"audit","findings":[]}`))
			return
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"action":"audit"}`))
	}))
	t.Cleanup(eng.Close)

	// 可变仓储：初始关（无 settings），同一 handler 在运行中改仓储值。
	mutableRepo := &contentConfigSystemRepo{}
	rs := &mockRetentionStore{}
	deps := &Dependencies{
		SecurityEngineURL:           eng.URL,
		SecurityEngineInternalToken: "tok",
		RetentionStore:              rs,
		SystemRepo:                  mutableRepo,
	}
	handler := PortalUploadIngest(deps)

	doUpload := func() {
		body := []byte("clean body")
		req := httptest.NewRequest("PUT", "/admin/v1/portal-integration/upload-ingest",
			strings.NewReader(portalUploadPayload(t, "x", b64Std(body), shaHex(body))))
		req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("upload expected 200, got %d body=%s", w.Code, w.Body.String())
		}
	}

	// 1) 初始 DB 关闭：仍做类型扫描，不做附件正文扫描。
	doUpload()
	if got := atomic.LoadInt32(&attachmentScans); got != 1 {
		t.Fatalf("DB 关闭时仍应扫描附件类型, got %d", got)
	}

	// 2) 运行中 DB 改为开（不重建 handler）：第二次上传继续做类型扫描。
	mutableRepo.settings = map[string]string{"file_content_dlp_enabled": "true"}
	doUpload()
	if got := atomic.LoadInt32(&attachmentScans); got != 2 {
		t.Fatalf("DB 开启后应继续扫描附件类型, got %d", got)
	}

	// 3) 运行中再改回关：第三次上传仍会执行类型扫描。
	mutableRepo.settings = map[string]string{"file_content_dlp_enabled": "false"}
	doUpload()
	if got := atomic.LoadInt32(&attachmentScans); got != 3 {
		t.Fatalf("DB 再次关闭后仍应扫描附件类型, got %d", got)
	}
}

// 审查第 4 项：门户上传时检测失败按 upload_inspection_failure_action 处置。缺省 forward_alert
// 照原样放行并留痕；选 block 时防护模式下拒绝，观察留痕下仍只记录。
func TestPortalUploadIngest_InspectionFailureFollowsConsoleAction(t *testing.T) {
	for _, tc := range []struct {
		name, action, mode string
		failClosed         bool
		wantCode           int
	}{
		{"default_forwards", "", "protect", false, http.StatusOK},
		{"forward_alert_forwards", "forward_alert", "protect", false, http.StatusOK},
		// 审查第三轮第 5 项：只看上传处置，“检测服务不可用即拦”打开也照常放行并留痕。
		{"forward_alert_ignores_detection_fail_closed", "forward_alert", "protect", true, http.StatusOK},
		{"block_rejects_in_protect", "block", "protect", false, http.StatusServiceUnavailable},
		{"block_records_in_record_mode", "block", "record", false, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
			t.Cleanup(eng.Close)
			settings := map[string]string{"file_content_dlp_enabled": "true", "security_execution_mode": tc.mode}
			if tc.failClosed {
				settings["guardrail_fail_closed_enabled"] = "true"
			}
			if tc.action != "" {
				settings["upload_inspection_failure_action"] = tc.action
			}
			deps := &Dependencies{
				SecurityEngineURL: eng.URL, SecurityEngineInternalToken: "tok",
				RetentionStore: &mockRetentionStore{}, SystemRepo: &contentConfigSystemRepo{settings: settings},
			}
			body := []byte("docx body")
			req := httptest.NewRequest("PUT", "/admin/v1/portal-integration/upload-ingest",
				strings.NewReader(portalUploadPayload(t, "x", b64Std(body), shaHex(body))))
			req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
			w := httptest.NewRecorder()
			PortalUploadIngest(deps)(w, req)
			if w.Code != tc.wantCode {
				t.Fatalf("status=%d want %d body=%s", w.Code, tc.wantCode, w.Body.String())
			}
			if tc.wantCode == http.StatusOK && !strings.Contains(w.Body.String(), `"action":"audit"`) {
				t.Fatalf("放行时按检测缺口记 audit：%s", w.Body.String())
			}
			if tc.wantCode != http.StatusOK && !strings.Contains(w.Body.String(), "upload_inspection_unavailable") {
				t.Fatalf("拒绝时写明是检测失败：%s", w.Body.String())
			}
		})
	}
}
