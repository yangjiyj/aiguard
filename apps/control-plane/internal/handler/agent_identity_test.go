package handler

import (
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIdentityManagementRejectsUnprivilegedAndEmergency(t *testing.T) {
	for _, role := range []string{"auditor", "dept_manager", "user", "tenant_admin"} {
		for _, method := range []string{"GET", "POST"} {
			r := contentAuditAuthRequest(role)
			r.Method = method
			if role == "tenant_admin" {
				auth.GetUser(r.Context()).DepartmentAssignmentMode = "emergency"
			}
			w := httptest.NewRecorder()
			AgentIdentityManagement(&Dependencies{})(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s %s: %d", role, method, w.Code)
			}
		}
	}
}
func TestIdentityManagementRejectsMismatchedTenant(t *testing.T) {
	r := contentAuditAuthRequest("tenant_admin")
	auth.GetSession(r.Context()).TenantID = "other"
	w := httptest.NewRecorder()
	AgentIdentityManagement(&Dependencies{})(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatal(w.Code)
	}
}
