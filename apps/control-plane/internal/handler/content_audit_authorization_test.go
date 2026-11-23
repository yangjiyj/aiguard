package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func contentAuditAuthRequest(role string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/content/session-a", nil)
	user := &repository.User{ID: "user-a", TenantID: "tenant-a", Role: role, DepartmentAssignmentMode: "manual"}
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	ctx = context.WithValue(ctx, auth.SessionKey, &repository.Session{UserID: user.ID, TenantID: user.TenantID})
	return req.WithContext(ctx)
}

func TestRequireFullTenantContentEvidenceHidesObjectsFromDepartmentManager(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	recorder := httptest.NewRecorder()

	RequireFullTenantContentEvidence(next).ServeHTTP(recorder, contentAuditAuthRequest("dept_manager"))

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", recorder.Code)
	}
	if called {
		t.Fatal("protected handler must not be called")
	}
}

func TestRequireFullTenantContentEvidenceAllowsFullTenantRoles(t *testing.T) {
	for _, role := range []string{"platform_admin", "tenant_owner", "tenant_admin", "auditor"} {
		t.Run(role, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			})
			recorder := httptest.NewRecorder()
			RequireFullTenantContentEvidence(next).ServeHTTP(recorder, contentAuditAuthRequest(role))
			if !called || recorder.Code != http.StatusNoContent {
				t.Fatalf("called=%v status=%d", called, recorder.Code)
			}
		})
	}
}

func TestRequireFullTenantContentEvidenceRejectsEmergencyBeforeRole(t *testing.T) {
	req := contentAuditAuthRequest("tenant_admin")
	user := auth.GetUser(req.Context())
	user.DepartmentAssignmentMode = "emergency"
	recorder := httptest.NewRecorder()
	RequireFullTenantContentEvidence(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("emergency user must not reach content evidence")
	})).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestListContentAuditRejectsEmergencyBeforeFeatureLookup(t *testing.T) {
	req := contentAuditAuthRequest("tenant_admin")
	auth.GetUser(req.Context()).DepartmentAssignmentMode = "emergency"
	recorder := httptest.NewRecorder()
	ListContentAudit(&Dependencies{}).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestRequireFullTenantContentEvidenceRejectsMissingOrMixedSession(t *testing.T) {
	base := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/content/session-a", nil)
	user := &repository.User{ID: "user-a", TenantID: "tenant-a", Role: "tenant_admin", DepartmentAssignmentMode: "manual"}
	cases := []struct {
		name    string
		session *repository.Session
	}{
		{name: "missing"},
		{name: "wrong tenant", session: &repository.Session{UserID: user.ID, TenantID: "tenant-b"}},
		{name: "wrong user", session: &repository.Session{UserID: "user-b", TenantID: user.TenantID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(base.Context(), auth.UserKey, user)
			if tc.session != nil {
				ctx = context.WithValue(ctx, auth.SessionKey, tc.session)
			}
			recorder := httptest.NewRecorder()
			RequireFullTenantContentEvidence(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("invalid session must not reach content evidence")
			})).ServeHTTP(recorder, base.WithContext(ctx))
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestRequireFullTenantContentEvidenceAcceptsLegacyEmptySessionTenant(t *testing.T) {
	req := contentAuditAuthRequest("tenant_admin")
	session := auth.GetSession(req.Context())
	session.TenantID = ""
	recorder := httptest.NewRecorder()
	RequireFullTenantContentEvidence(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestDispositionMutationRoleContract(t *testing.T) {
	for _, role := range []string{"platform_admin", "tenant_owner", "tenant_admin"} {
		user := &repository.User{Role: role, DepartmentAssignmentMode: "manual"}
		if !canMutateAuditDisposition(user) {
			t.Fatalf("%s must be allowed to mutate dispositions", role)
		}
	}
	for _, user := range []*repository.User{
		{Role: "auditor", DepartmentAssignmentMode: "manual"},
		{Role: "dept_manager", DepartmentAssignmentMode: "manual"},
		{Role: "tenant_admin", DepartmentAssignmentMode: "emergency"},
	} {
		if canMutateAuditDisposition(user) {
			t.Fatalf("unexpected disposition mutation access: %+v", user)
		}
	}
}

func TestScopedContentAlertMetadataNeverSearchesBodyText(t *testing.T) {
	allowed := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/content?alert_only=true&user_id=user-a&category=secret_leak", nil)
	if !scopedContentAlertMetadataRequestAllowed(allowed) {
		t.Fatal("metadata-only user/category filters should be allowed")
	}
	keyword := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/content?alert_only=true&keyword=secret", nil)
	if scopedContentAlertMetadataRequestAllowed(keyword) {
		t.Fatal("department-scoped callers must not infer body text through keyword hits")
	}
}
