package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func statusAuthorizationRequest(actor *repository.User, userID string) *http.Request {
	req := httptest.NewRequest(http.MethodPatch, "/admin/v1/users/"+userID+"/status", strings.NewReader(`{"status":"active"}`))
	if actor != nil {
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, actor))
	}
	route := chi.NewRouteContext()
	route.URLParams.Add("id", userID)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
}

func TestToggleUserStatusEnforcesCallerAndTargetTenantAuthorization(t *testing.T) {
	users := map[string]*repository.User{
		"same": {
			ID: "same", TenantID: "tenant-1", Role: "viewer", Status: "active",
			DepartmentAssignmentMode: "emergency",
		},
		"cross": {
			ID: "cross", TenantID: "tenant-2", Role: "viewer", Status: "active",
			DepartmentAssignmentMode: "emergency",
		},
		"system": {
			ID: "system", TenantID: repository.SystemTenantID, Role: "viewer", Status: "active",
			DepartmentAssignmentMode: "emergency",
		},
	}
	tests := []struct {
		name       string
		actor      *repository.User
		targetID   string
		wantStatus int
		wantCode   string
	}{
		{
			name: "unauthenticated", targetID: "same",
			wantStatus: http.StatusUnauthorized, wantCode: "unauthorized",
		},
		{
			name:     "ordinary user",
			actor:    &repository.User{ID: "viewer", TenantID: "tenant-1", Role: "viewer"},
			targetID: "same", wantStatus: http.StatusForbidden, wantCode: "forbidden",
		},
		{
			name:     "tenant admin same tenant",
			actor:    &repository.User{ID: "tenant-admin", TenantID: "tenant-1", Role: "tenant_admin"},
			targetID: "same", wantStatus: http.StatusOK,
		},
		{
			name:     "tenant admin cross tenant",
			actor:    &repository.User{ID: "tenant-admin", TenantID: "tenant-1", Role: "tenant_admin"},
			targetID: "cross", wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
		{
			name:     "platform admin cross tenant",
			actor:    &repository.User{ID: "platform-admin", TenantID: "tenant-1", Role: "platform_admin"},
			targetID: "cross", wantStatus: http.StatusOK,
		},
		{
			name:     "platform admin system tenant target",
			actor:    &repository.User{ID: "platform-admin", TenantID: "tenant-1", Role: "platform_admin"},
			targetID: "system", wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
		{
			name:     "platform admin missing target",
			actor:    &repository.User{ID: "platform-admin", TenantID: "tenant-1", Role: "platform_admin"},
			targetID: "missing", wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &licenseUserStore{users: users}
			w := httptest.NewRecorder()
			ToggleUserStatus(&Dependencies{UserStore: store}).ServeHTTP(w, statusAuthorizationRequest(tc.actor, tc.targetID))
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantCode != "" && decodeErrorCode(t, w.Body.String()) != tc.wantCode {
				t.Fatalf("error.code=%q want=%q body=%s", decodeErrorCode(t, w.Body.String()), tc.wantCode, w.Body.String())
			}
			if tc.wantStatus != http.StatusOK && store.updated != nil {
				t.Fatalf("unauthorized request updated target: %+v", store.updated)
			}
		})
	}
}

func updateUserAuthorizationRequest(actor *repository.User, userID string) *http.Request {
	req := httptest.NewRequest(http.MethodPatch, "/admin/v1/users/"+userID, strings.NewReader(`{}`))
	if actor != nil {
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, actor))
	}
	route := chi.NewRouteContext()
	route.URLParams.Add("id", userID)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
}

func TestUpdateUserEnforcesPlatformAdminAndHidesProtectedTargets(t *testing.T) {
	users := map[string]*repository.User{
		"cross": {
			ID: "cross", TenantID: "tenant-2", Role: "viewer", Status: "active",
			DepartmentAssignmentMode: "manual",
		},
		"system": {
			ID: "system", TenantID: repository.SystemTenantID, Role: "viewer", Status: "active",
			DepartmentAssignmentMode: "manual",
		},
	}
	tests := []struct {
		name       string
		actor      *repository.User
		targetID   string
		wantStatus int
		wantCode   string
	}{
		{
			name: "unauthenticated", targetID: "cross",
			wantStatus: http.StatusUnauthorized, wantCode: "unauthorized",
		},
		{
			name:     "ordinary user",
			actor:    &repository.User{ID: "viewer", TenantID: "tenant-1", Role: "viewer"},
			targetID: "cross", wantStatus: http.StatusForbidden, wantCode: "forbidden",
		},
		{
			name:     "tenant admin",
			actor:    &repository.User{ID: "tenant-admin", TenantID: "tenant-2", Role: "tenant_admin"},
			targetID: "cross", wantStatus: http.StatusForbidden, wantCode: "forbidden",
		},
		{
			name:     "platform admin business tenant target",
			actor:    &repository.User{ID: "platform-admin", TenantID: "tenant-1", Role: "platform_admin"},
			targetID: "cross", wantStatus: http.StatusOK,
		},
		{
			name:     "platform admin system tenant target",
			actor:    &repository.User{ID: "platform-admin", TenantID: "tenant-1", Role: "platform_admin"},
			targetID: "system", wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
		{
			name:     "platform admin missing target",
			actor:    &repository.User{ID: "platform-admin", TenantID: "tenant-1", Role: "platform_admin"},
			targetID: "missing", wantStatus: http.StatusNotFound, wantCode: "not_found",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := &licenseUserStore{users: users}
			w := httptest.NewRecorder()
			UpdateUser(&Dependencies{UserStore: store}).ServeHTTP(w, updateUserAuthorizationRequest(tc.actor, tc.targetID))
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.wantCode != "" && decodeErrorCode(t, w.Body.String()) != tc.wantCode {
				t.Fatalf("error.code=%q want=%q body=%s", decodeErrorCode(t, w.Body.String()), tc.wantCode, w.Body.String())
			}
			if store.updated != nil {
				t.Fatalf("authorization test unexpectedly updated target: %+v", store.updated)
			}
		})
	}
}
