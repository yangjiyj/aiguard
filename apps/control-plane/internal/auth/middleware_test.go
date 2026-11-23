package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type fakeSessionReader struct {
	session *repository.Session
}

func (f fakeSessionReader) Get(context.Context, string) (*repository.Session, error) {
	return f.session, nil
}

func (f fakeSessionReader) Extend(context.Context, string) error { return nil }

type fakeUserReader struct {
	user *repository.User
}

func (f fakeUserReader) GetByID(context.Context, string) (*repository.User, error) {
	return f.user, nil
}

func TestMiddlewareAllowsPublicAuthenticationEndpoints(t *testing.T) {
	for _, path := range []string{"/admin/v1/captcha", "/admin/v1/login", "/admin/v1/employee-login"} {
		t.Run(path, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				called = true
				w.WriteHeader(http.StatusNoContent)
			})

			recorder := httptest.NewRecorder()
			request := httptest.NewRequest(http.MethodGet, path, nil)
			Middleware(nil, nil)(next).ServeHTTP(recorder, request)

			if !called || recorder.Code != http.StatusNoContent {
				t.Fatalf("public endpoint did not bypass auth: called=%v status=%d", called, recorder.Code)
			}
		})
	}
}

func TestMiddlewareInjectsMatchingUserAndSessionIntoProtectedRoute(t *testing.T) {
	session := &repository.Session{ID: "session-a", UserID: "user-a", TenantID: "tenant-a", Role: "tenant_admin"}
	user := &repository.User{ID: "user-a", TenantID: "tenant-a", Role: "tenant_admin", Status: "active"}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if GetSession(r.Context()) != session || GetUser(r.Context()) != user {
			t.Fatal("protected route did not receive both auth context values")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/content/session-a", nil)
	req.Header.Set("Authorization", "Bearer session-a")
	recorder := httptest.NewRecorder()
	Middleware(fakeSessionReader{session: session}, fakeUserReader{user: user})(next).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestMiddlewareRejectsSessionUserTenantMismatch(t *testing.T) {
	session := &repository.Session{ID: "session-a", UserID: "user-a", TenantID: "tenant-old"}
	user := &repository.User{ID: "user-a", TenantID: "tenant-current", Role: "tenant_admin", Status: "active"}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/content/session-a", nil)
	req.Header.Set("Authorization", "Bearer session-a")
	recorder := httptest.NewRecorder()
	Middleware(fakeSessionReader{session: session}, fakeUserReader{user: user})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("mixed tenant auth context must not reach protected route")
	})).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestMiddlewareAcceptsLegacyEmptySessionTenant(t *testing.T) {
	session := &repository.Session{ID: "session-a", UserID: "user-a", Role: "tenant_admin"}
	user := &repository.User{ID: "user-a", TenantID: "tenant-current", Role: "tenant_admin", Status: "active"}
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/content/session-a", nil)
	req.Header.Set("Authorization", "Bearer session-a")
	recorder := httptest.NewRecorder()
	Middleware(fakeSessionReader{session: session}, fakeUserReader{user: user})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if GetUser(r.Context()).TenantID != "tenant-current" {
			t.Fatal("current user tenant must remain authoritative")
		}
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestChatOnlyRoleCannotUseManagementAPIsEvenBeforeRBAC(t *testing.T) {
	session := &repository.Session{ID: "s", UserID: "u", TenantID: "t", Role: "chat_user"}
	user := &repository.User{ID: "u", TenantID: "t", Role: "chat_user", Status: "active", MustChangePassword: true}
	for _, path := range []string{"/admin/v1/users", "/admin/v1/stats/overview", "/admin/v1/system/settings", "/admin/v1/me/anything", "/admin/v1/providers", "/admin/v1/me/chat-login/"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, path, nil)
			r.Header.Set("Authorization", "Bearer s")
			Middleware(fakeSessionReader{session}, fakeUserReader{user})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("chat_user reached management downstream") })).ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status=%d want 403 body=%s", w.Code, w.Body.String())
			}
		})
	}
}
func TestLegacyChatPasswordSessionCannotUseConsoleSelfService(t *testing.T) {
	session := &repository.Session{ID: "s", UserID: "u", TenantID: "t", Role: "chat_user"}
	user := &repository.User{ID: "u", TenantID: "t", Role: "chat_user", Status: "active", MustChangePassword: true}
	for _, route := range []struct{ method, path string }{
		{"GET", "/admin/v1/me"}, {"POST", "/admin/v1/me/change-password"}, {"POST", "/admin/v1/logout"},
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(route.method, route.path, nil)
		r.Header.Set("Authorization", "Bearer s")
		Middleware(fakeSessionReader{session}, fakeUserReader{user})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("%s %s status=%d body=%s", route.method, route.path, w.Code, w.Body.String())
		}
	}
}

func TestMiddlewareRejectsOldNonAdministratorSessionsAndRolePromotion(t *testing.T) {
	for _, tc := range []struct{ current, snapshot string }{
		{"chat_user", "chat_user"}, {"developer", "developer"}, {"viewer", "viewer"},
		{"dept_manager", "dept_manager"}, {"operator", "operator"},
		// 三员（security_officer、auditor）是控制台角色：它们的会话被接受，见 TestMiddlewareAcceptsThreeOfficerConsoleSessions。
		// 但「角色被改成三员后仍拿旧的非管理员会话」依然必须拒绝（会话快照与当前角色都要是控制台角色）。
		{"security_officer", "developer"}, {"auditor", "viewer"}, {"developer", "security_officer"}, {"viewer", "auditor"},
		{"tenant_admin", "developer"}, {"developer", "tenant_admin"},
	} {
		t.Run(tc.current+"_"+tc.snapshot, func(t *testing.T) {
			s := &repository.Session{ID: "s", UserID: "u", TenantID: "t", Role: tc.snapshot}
			u := &repository.User{ID: "u", TenantID: "t", Role: tc.current, Status: "active"}
			r := httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil)
			r.Header.Set("Authorization", "Bearer s")
			w := httptest.NewRecorder()
			Middleware(fakeSessionReader{s}, fakeUserReader{u})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("nonadministrator management session accepted") })).ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status=%d", w.Code)
			}
		})
	}
}

// 三员分立：security_officer、auditor 是控制台角色，会话被接受（授权仍由 permission 中间件与 SoD 把关）。
func TestMiddlewareAcceptsThreeOfficerConsoleSessions(t *testing.T) {
	for _, role := range []string{"platform_admin", "security_officer", "auditor", "tenant_admin"} {
		t.Run(role, func(t *testing.T) {
			s := &repository.Session{ID: "s", UserID: "u", TenantID: "t", Role: role}
			u := &repository.User{ID: "u", TenantID: "t", Role: role, Status: "active"}
			r := httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil)
			r.Header.Set("Authorization", "Bearer s")
			w := httptest.NewRecorder()
			Middleware(fakeSessionReader{s}, fakeUserReader{u})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(w, r)
			if w.Code != http.StatusNoContent {
				t.Fatalf("%s 的控制台会话应被接受: %d %s", role, w.Code, w.Body.String())
			}
		})
	}
}

func TestMiddlewarePreservesPlatformConnectorMachineSession(t *testing.T) {
	s := &repository.Session{ID: "s", UserID: "u", TenantID: "t", Role: "platform_connector"}
	u := &repository.User{ID: "u", TenantID: "t", Role: "platform_connector", Status: "active"}
	r := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/authorization-context", nil)
	r.Header.Set("Authorization", "Bearer s")
	w := httptest.NewRecorder()
	Middleware(fakeSessionReader{s}, fakeUserReader{u})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status=%d", w.Code)
	}
}

// M-1：控制台角色之间互换后，旧会话不得继续带着新角色的权限。
// 原先中间件只要求 session.Role 与 user.Role 都属于登录档，所以 auditor 被改成 tenant_admin 或 security_officer 后，
// 旧会话直接拥有新角色权限，不必重新登录也不必重新过 TOTP。现在要求两者一致，否则 401 并提示重新登录。
func TestMiddlewareRejectsSessionsWhoseRoleNoLongerMatchesTheUser(t *testing.T) {
	roles := []string{"platform_admin", "security_officer", "auditor", "tenant_admin", "tenant_owner"}
	for _, snapshot := range roles {
		for _, current := range roles {
			if snapshot == current {
				continue
			}
			t.Run(snapshot+"_to_"+current, func(t *testing.T) {
				s := &repository.Session{ID: "s", UserID: "u", TenantID: "t", Role: snapshot}
				u := &repository.User{ID: "u", TenantID: "t", Role: current, Status: "active"}
				r := httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil)
				r.Header.Set("Authorization", "Bearer s")
				w := httptest.NewRecorder()
				Middleware(fakeSessionReader{s}, fakeUserReader{u})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
					t.Fatalf("角色已从 %s 改为 %s，旧会话不得放行", snapshot, current)
				})).ServeHTTP(w, r)
				if w.Code != http.StatusUnauthorized {
					t.Fatalf("status=%d want 401 body=%s", w.Code, w.Body.String())
				}
				if !strings.Contains(w.Body.String(), "sign in again") && !strings.Contains(w.Body.String(), "重新登录") {
					t.Fatalf("应提示重新登录: %s", w.Body.String())
				}
			})
		}
	}
}

// 角色没变（含历史别名 admin 与 platform_admin 等同）的会话照常放行。
func TestMiddlewareAcceptsSessionsWhoseRoleStillMatches(t *testing.T) {
	for _, tc := range []struct{ snapshot, current string }{
		{"platform_admin", "platform_admin"}, {"security_officer", "security_officer"}, {"auditor", "auditor"},
		{"tenant_admin", "tenant_admin"}, {"tenant_owner", "tenant_owner"},
		{"admin", "platform_admin"}, {"platform_admin", "admin"}, {"admin", "admin"},
	} {
		t.Run(tc.snapshot+"_"+tc.current, func(t *testing.T) {
			s := &repository.Session{ID: "s", UserID: "u", TenantID: "t", Role: tc.snapshot}
			u := &repository.User{ID: "u", TenantID: "t", Role: tc.current, Status: "active"}
			r := httptest.NewRequest(http.MethodGet, "/admin/v1/me", nil)
			r.Header.Set("Authorization", "Bearer s")
			w := httptest.NewRecorder()
			Middleware(fakeSessionReader{s}, fakeUserReader{u})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			})).ServeHTTP(w, r)
			if w.Code != http.StatusNoContent {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
