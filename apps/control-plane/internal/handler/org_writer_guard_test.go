package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// okHandler is a trivial handler that writes 200 OK when the guard lets it through.
var okHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// injectUser injects a *repository.User into the request context at auth.UserKey.
func injectUser(r *http.Request, role string) *http.Request {
	u := &repository.User{
		ID:       "test-user-id",
		TenantID: "test-tenant-id",
		Role:     role,
		Status:   "active",
	}
	return r.WithContext(context.WithValue(r.Context(), auth.UserKey, u))
}

func TestOrgWriterGuard_Developer_Returns403(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/teams", nil)
	req = injectUser(req, "developer")
	rr := httptest.NewRecorder()

	OrgWriterGuard(okHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestOrgWriterGuard_TenantOwner_Returns200(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/teams", nil)
	req = injectUser(req, "tenant_owner")
	rr := httptest.NewRecorder()

	OrgWriterGuard(okHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestOrgWriterGuard_PlatformAdmin_Returns200(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/teams", nil)
	req = injectUser(req, "platform_admin")
	rr := httptest.NewRecorder()

	OrgWriterGuard(okHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

func TestOrgWriterGuard_NoUser_Returns401(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/teams", nil)
	// intentionally no user injected
	rr := httptest.NewRecorder()

	OrgWriterGuard(okHandler).ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
}
