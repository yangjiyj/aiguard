package handler

import (
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

func scopedContentAlertMetadataRequestAllowed(r *http.Request) bool {
	if r == nil || !parseBoolParam(r.URL.Query().Get("alert_only")) {
		return false
	}
	return strings.TrimSpace(r.URL.Query().Get("session_id")) == "" &&
		strings.TrimSpace(r.URL.Query().Get("keyword")) == ""
}

func authenticatedContentEvidenceUser(w http.ResponseWriter, r *http.Request) (*repository.User, bool) {
	user := auth.GetUser(r.Context())
	session := auth.GetSession(r.Context())
	if user == nil || session == nil ||
		user.ID == "" || session.UserID != user.ID ||
		user.TenantID == "" || (session.TenantID != "" && session.TenantID != user.TenantID) {
		writeUnauthorized(w, "invalid authentication context")
		return nil, false
	}
	return user, true
}

func canReadFullTenantContentEvidence(user *repository.User) bool {
	if user == nil || user.DepartmentAssignmentMode == "emergency" {
		return false
	}
	switch user.Role {
	case "platform_admin", "tenant_owner", "tenant_admin", "auditor", roles.SecurityOfficer:
		return true
	default:
		return false
	}
}

func canMutateAuditDisposition(user *repository.User) bool {
	if user == nil || user.DepartmentAssignmentMode == "emergency" {
		return false
	}
	switch user.Role {
	case "platform_admin", "tenant_owner", "tenant_admin", roles.SecurityOfficer:
		return true
	default:
		return false
	}
}

// RequireFullTenantContentEvidence prevents department-scoped readers from
// probing retained content objects. Collection metadata has its own row scope.
func RequireFullTenantContentEvidence(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedContentEvidenceUser(w, r)
		if !ok {
			return
		}
		if !canReadFullTenantContentEvidence(user) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "content evidence not found")
			return
		}
		next.ServeHTTP(w, r)
	})
}
