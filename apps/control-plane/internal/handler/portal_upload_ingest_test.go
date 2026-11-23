package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetPortalFilePolicyRequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/policies/file", nil)
	w := httptest.NewRecorder()
	GetPortalFilePolicy(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest || w.Body.String() == "" {
		t.Fatalf("want 400 tenant_required, got %d %s", w.Code, w.Body.String())
	}
}

func TestGetPortalFilePolicyReturnsDefaultWhenNoSetting(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/policies/file?project_id=p1", nil)
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	GetPortalFilePolicy(&Dependencies{SystemRepo: &contentConfigSystemRepo{}})(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "allowed_types") || !strings.Contains(body, "max_file_mb") {
		t.Fatalf("响应应含 allowed_types/max_file_mb，实际 %s", body)
	}
}

func TestGetPortalFilePolicyFailsClosedWhenPolicyStoreUnavailable(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/policies/file?project_id=p1", nil)
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	GetPortalFilePolicy(&Dependencies{})(w, req)
	if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "file_policy_unavailable") {
		t.Fatalf("want safe 503, got %d %s", w.Code, w.Body.String())
	}
}

func TestPortalUploadIngestRequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/upload-ingest", strings.NewReader(`{}`))
	w := httptest.NewRecorder()
	PortalUploadIngest(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 tenant_required, got %d", w.Code)
	}
}

func TestPortalUploadIngestRejectsMissingFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/upload-ingest", strings.NewReader(`{"filename":"x.pdf"}`))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	PortalUploadIngest(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 missing required fields, got %d %s", w.Code, w.Body.String())
	}
}

func TestPortalUploadIngestRejectsMissingUserID(t *testing.T) {
	body := `{"filename":"x.pdf","mime_type":"application/pdf","size":100,"sha256":"abc","bytes_base64":"AAAA","extracted_text":"hi"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/upload-ingest", strings.NewReader(body))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	PortalUploadIngest(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "user_id") {
		t.Fatalf("want 400 user_id required, got %d %s", w.Code, w.Body.String())
	}
}

func TestPortalUploadResultBlocksOnlyEnforcingActions(t *testing.T) {
	if portalUploadResultBlocks("audit", []map[string]interface{}{{"category": "file_archive", "action": "audit"}}) {
		t.Fatal("an audit-only archive finding must not become a portal block")
	}
	if !portalUploadResultBlocks("audit", []map[string]interface{}{{"category": "file_policy_blocked_type", "action": "block"}}) {
		t.Fatal("an explicit block finding must stop the portal upload")
	}
	if portalUploadResultBlocks("mask", []map[string]interface{}{{"category": "phone_cn", "action": "mask"}}) {
		t.Fatal("mask is a rewrite, not a block; the portal cannot rewrite a file and must record it")
	}
	if !portalUploadResultBlocks("deny", nil) {
		t.Fatal("deny belongs to the single blocking set")
	}
}

func TestPortalUploadIngestRejectsBadBase64(t *testing.T) {
	body := `{"user_id":"u1","filename":"x.pdf","mime_type":"application/pdf","size":3,"sha256":"abc","bytes_base64":"!!!not-base64!!!","extracted_text":"hi"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/upload-ingest", strings.NewReader(body))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	PortalUploadIngest(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400 invalid base64, got %d %s", w.Code, w.Body.String())
	}
}
