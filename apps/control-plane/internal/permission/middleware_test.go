package permission

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type previewReadPermissionChecker struct{}

func (previewReadPermissionChecker) rolesHavePermission(_ context.Context, roles map[string]bool, resource, action string) (bool, error) {
	return roles["auditor"] && resource == "security_events" && action == "read", nil
}

// TestMiddlewareSkipPaths verifies that skip paths bypass middleware
func TestMiddlewareSkipPaths(t *testing.T) {
	paths := []string{
		"/admin/v1/captcha",
		"/admin/v1/login",
		"/health",
		"/admin/v1/me",
		"/admin/v1/me/permissions",
		"/admin/v1/me/change-password",
		"/admin/v1/internal/tools/config",
	}

	for _, path := range paths {
		if skipPaths[path] {
			continue // exact match is fine
		}
		// Check prefix match
		found := false
		for _, prefix := range skipPathPrefixes {
			if len(path) >= len(prefix) && path[:len(prefix)] == prefix {
				found = true
				break
			}
		}
		if !found && !skipPaths[path] {
			t.Errorf("path %q should be skipped but is not", path)
		}
	}
}

// TestSkipPathsMap verifies the static skip map
func TestSkipPathsMap(t *testing.T) {
	if !skipPaths["/admin/v1/login"] {
		t.Error("login path should be in skip map")
	}
	if !skipPaths["/admin/v1/captcha"] {
		t.Error("captcha path should be in skip map")
	}
	if !skipPaths["/health"] {
		t.Error("health path should be in skip map")
	}
}

// TestSkipPathPrefixes verifies prefix skip list
func TestSkipPathPrefixes(t *testing.T) {
	for _, prefix := range skipPathPrefixes {
		r := httptest.NewRequest(http.MethodGet, prefix+"/something", nil)
		path := r.URL.Path
		found := false
		for _, p := range skipPathPrefixes {
			if len(path) >= len(p) && path[:len(p)] == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("prefix %q not matched for path %q", prefix, path)
		}
	}
}

// TestGenerateID verifies ID generation is non-empty
func TestGenerateID(t *testing.T) {
	id1 := generateID()
	id2 := generateID()
	if id1 == "" {
		t.Error("expected non-empty ID")
	}
	if id1 == id2 {
		t.Log("IDs might collide at same nanosecond, this is acceptable in test")
	}
}

func TestMiddlewareEnforceDeniedRequestReturnsForbidden(t *testing.T) {
	cache := NewGrantsCache()
	checker := NewChecker(nil, cache)
	user := &repository.User{ID: "user-denied", TenantID: "tenant-1", Status: "active"}
	cache.Set(user.ID, nil)

	nextCalled := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true })
	h := Middleware(checker, nil, false)(next)
	r := httptest.NewRequest(http.MethodGet, "/admin/v1/users", nil)
	r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, user))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusForbidden {
		t.Fatalf("enforce mode must return 403 for missing grant, got %d: %s", w.Code, w.Body.String())
	}
	if nextCalled {
		t.Fatal("denied request must not reach the protected handler")
	}
}

func TestPolicyPreviewAuthorizationUsesSecurityEventsReadGrant(t *testing.T) {
	for _, tc := range []struct {
		name       string
		grants     []Grant
		wantStatus int
		wantNext   bool
	}{
		{
			name: "auditor read grant",
			grants: []Grant{{
				UserID: "auditor-a", TenantID: "tenant-a",
				ScopeType: "tenant", ScopeID: "tenant-a", Role: "auditor",
			}},
			wantStatus: http.StatusNoContent,
			wantNext:   true,
		},
		{name: "missing read grant", wantStatus: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache := NewGrantsCache()
			cache.Set("auditor-a", tc.grants)
			checker := NewChecker(nil, cache)
			checker.systemPermCheck = previewReadPermissionChecker{}
			nextCalled := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusNoContent)
			})
			handler := Middleware(checker, nil, false)(next)
			request := httptest.NewRequest(http.MethodPost, "/admin/v1/security/policies/preview", nil)
			request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{
				ID: "auditor-a", TenantID: "tenant-a", Role: "auditor", Status: "active",
			}))
			recorder := httptest.NewRecorder()

			handler.ServeHTTP(recorder, request)

			if recorder.Code != tc.wantStatus || nextCalled != tc.wantNext {
				t.Fatalf("status=%d next=%v, want status=%d next=%v body=%s", recorder.Code, nextCalled, tc.wantStatus, tc.wantNext, recorder.Body.String())
			}
		})
	}
}
func TestRBACEnforceEnabledReadsUAGEnv(t *testing.T) {
	t.Setenv("UAG_RBAC_ENFORCE", "true")
	if !RBACEnforceEnabled() {
		t.Fatal("UAG_RBAC_ENFORCE=true must enable enforce mode")
	}
	t.Setenv("UAG_RBAC_ENFORCE", "TRUE")
	if !RBACEnforceEnabled() {
		t.Fatal("UAG_RBAC_ENFORCE=TRUE must enable enforce mode")
	}
	t.Setenv("UAG_RBAC_ENFORCE", "false")
	if RBACEnforceEnabled() {
		t.Fatal("UAG_RBAC_ENFORCE=false must keep dry-run mode")
	}
}

func TestMiddlewareAllowsAuthenticatedSystemSettingsProjectionWithoutGrant(t *testing.T) {
	cache := NewGrantsCache()
	checker := NewChecker(nil, cache)
	user := &repository.User{ID: "user-viewer", TenantID: "tenant-1", Role: "viewer", Status: "active"}
	cache.Set(user.ID, nil)

	nextCalled := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(checker, nil, false)(next)
	r := httptest.NewRequest(http.MethodGet, "/admin/v1/system/settings", nil)
	r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, user))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !nextCalled {
		t.Fatalf("authenticated projection request was blocked: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMiddlewareDoesNotBypassSystemSettingsPut(t *testing.T) {
	cache := NewGrantsCache()
	checker := NewChecker(nil, cache)
	user := &repository.User{ID: "user-viewer", TenantID: "tenant-1", Role: "viewer", Status: "active"}
	cache.Set(user.ID, nil)
	nextCalled := false
	h := Middleware(checker, nil, false)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { nextCalled = true }))
	r := httptest.NewRequest(http.MethodPut, "/admin/v1/system/settings", nil)
	r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, user))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden || nextCalled {
		t.Fatalf("PUT authorization was bypassed: status=%d next=%v", w.Code, nextCalled)
	}
}

func TestMiddlewareSelfLogoutIsExactAuthenticatedPostOnly(t *testing.T) {
	for _, route := range []struct {
		method, path  string
		authenticated bool
		want          int
	}{
		{"POST", "/admin/v1/logout", true, http.StatusNoContent},
		{"GET", "/admin/v1/logout", true, http.StatusForbidden},
		{"DELETE", "/admin/v1/logout", true, http.StatusForbidden},
		{"POST", "/admin/v1/logout/other", true, http.StatusForbidden},
		{"POST", "/admin/v1/logout-extra", true, http.StatusForbidden},
		{"POST", "/admin/v1/logout", false, http.StatusForbidden},
		{"GET", "/admin/v1/users", true, http.StatusForbidden},
	} {
		t.Run(route.method+" "+route.path+fmt.Sprint(route.authenticated), func(t *testing.T) {
			cache := NewGrantsCache()
			cache.Set("chat-self", nil)
			request := httptest.NewRequest(route.method, route.path, nil)
			if route.authenticated {
				request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{ID: "chat-self", TenantID: "tenant", Role: "chat_user", Status: "active"}))
			}
			response := httptest.NewRecorder()
			Middleware(NewChecker(nil, cache), nil, false)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(response, request)
			if response.Code != route.want {
				t.Fatalf("got status=%d want=%d body=%s", response.Code, route.want, response.Body.String())
			}
		})
	}
}
