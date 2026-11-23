package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

// W4: before this change CreateUserGrant / DeleteUserGrant had no role check at
// all, so any signed-in user could grant themselves platform_admin.
func TestUserGrantsRequireSystemAdmin(t *testing.T) {
	for _, role := range []string{"developer", "viewer", "dept_manager", "tenant_admin", "tenant_owner", "auditor", "security_officer"} {
		u := &repository.User{ID: "u1", TenantID: "t1", Role: role}

		body := `{"scope_type":"tenant","scope_id":"t1","role":"tenant_owner"}`
		req := withUserContext(httptest.NewRequest(http.MethodPost, "/admin/v1/users/u1/grants", strings.NewReader(body)), u)
		rec := httptest.NewRecorder()
		CreateUserGrant(&Dependencies{})(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("CreateUserGrant as %s: code %d want 403", role, rec.Code)
		}

		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", "u1")
		rctx.URLParams.Add("grant_id", "g1")
		dreq := withUserContext(httptest.NewRequest(http.MethodDelete, "/admin/v1/users/u1/grants/g1", nil), u)
		dreq = dreq.WithContext(context.WithValue(dreq.Context(), chi.RouteCtxKey, rctx))
		drec := httptest.NewRecorder()
		DeleteUserGrant(&Dependencies{})(drec, dreq)
		if drec.Code != http.StatusForbidden {
			t.Errorf("DeleteUserGrant as %s: code %d want 403", role, drec.Code)
		}
	}
}

func TestUserGrantsRejectOfficerRoles(t *testing.T) {
	admin := &repository.User{ID: "a1", TenantID: repository.SystemTenantID, Role: "platform_admin", DepartmentAssignmentMode: "emergency"}
	for _, role := range []string{"platform_admin", "admin", "security_officer", "auditor"} {
		body := `{"scope_type":"tenant","scope_id":"t1","role":"` + role + `"}`
		req := withUserContext(httptest.NewRequest(http.MethodPost, "/admin/v1/users/u2/grants", strings.NewReader(body)), admin)
		rec := httptest.NewRecorder()
		CreateUserGrant(&Dependencies{})(rec, req)
		if rec.Code == http.StatusCreated || rec.Code == http.StatusOK || !strings.Contains(rec.Body.String(), "invalid_role") {
			t.Errorf("granting %s: code %d body %s, want invalid_role", role, rec.Code, rec.Body.String())
		}
	}
}

func TestGrantHelpers(t *testing.T) {
	if !canManageGrants(&repository.User{Role: "platform_admin", DepartmentAssignmentMode: "emergency"}) {
		t.Error("emergency platform_admin must manage grants")
	}
	if !canManageGrants(&repository.User{Role: "admin"}) {
		t.Error("legacy admin must manage grants")
	}
	if canManageGrants(nil) || canManageGrants(&repository.User{Role: "tenant_owner"}) {
		t.Error("only the system administrator manages grants")
	}
	for _, r := range []string{"tenant_owner", "team_owner", "project_viewer"} {
		if !isGrantableScopedRole(r) {
			t.Errorf("%s should be grantable", r)
		}
	}
	if isGrantableScopedRole("") {
		t.Error("empty role must not be grantable")
	}
}

func TestListLoginHistoryAuditOnlyAuditor(t *testing.T) {
	// Decision 2026-10-01: the system administrator reads login history too,
	// so platform_admin/admin pass the role gate (503 with the repo absent,
	// same as the auditor); every other role stays at 403.
	for _, role := range []string{"platform_admin", "admin"} {
		req := withUserContext(httptest.NewRequest(http.MethodGet, "/admin/v1/audit/login-history", nil), &repository.User{ID: "u1", Role: role})
		rec := httptest.NewRecorder()
		ListLoginHistoryAudit(&Dependencies{})(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: code %d want 503 (role gate passed, repo absent)", role, rec.Code)
		}
	}
	for _, role := range []string{"security_officer", "tenant_owner", "developer"} {
		req := withUserContext(httptest.NewRequest(http.MethodGet, "/admin/v1/audit/login-history", nil), &repository.User{ID: "u1", Role: role})
		rec := httptest.NewRecorder()
		ListLoginHistoryAudit(&Dependencies{})(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: code %d want 403", role, rec.Code)
		}
	}
	// The auditor passes the role gate (the missing repo then yields 503, not 403).
	req := withUserContext(httptest.NewRequest(http.MethodGet, "/admin/v1/audit/login-history", nil), &repository.User{ID: "a", Role: "auditor"})
	rec := httptest.NewRecorder()
	ListLoginHistoryAudit(&Dependencies{})(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("auditor: code %d want 503 (role gate passed, repo absent)", rec.Code)
	}
}
