package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPortalIntegrationAPIMiddlewareFailsClosedWithoutSecret(t *testing.T) {
	mw := PortalIntegrationAPIMiddleware("", &Dependencies{})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
}

func TestPortalIntegrationAPIMiddlewareAllowsBearer(t *testing.T) {
	mw := PortalIntegrationAPIMiddleware("portal-secret", &Dependencies{})
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/health", nil)
	req.Header.Set("Authorization", "Bearer portal-secret")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", w.Code)
	}
}

func TestCreatePortalKeyRequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/keys", strings.NewReader(`{"project_id":"p1","scopes":["chat"]}`))
	w := httptest.NewRecorder()
	CreatePortalKey(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "tenant") {
		t.Fatalf("want 400 tenant_required, got %d %s", w.Code, w.Body.String())
	}
}

func TestCreatePortalKeyRequiresExplicitScopes(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/portal-integration/keys", strings.NewReader(`{"project_id":"p1"}`))
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	CreatePortalKey(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "scopes") {
		t.Fatalf("want 400 scopes_required, got %d %s", w.Code, w.Body.String())
	}
}

func TestPortalAuditEventsRequireTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/audit-events", nil)
	w := httptest.NewRecorder()
	ListPortalAuditEvents(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestPortalAuditEventsRejectInvalidLimit(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/audit-events?limit=501", nil)
	req.Header.Set("X-JJDGuard-Tenant-Id", "tenant_default")
	w := httptest.NewRecorder()
	ListPortalAuditEvents(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}
