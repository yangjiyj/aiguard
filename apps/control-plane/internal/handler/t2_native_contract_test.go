package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type t2PolicyList struct {
	AgentGuardPolicyRepo
	rows []*repository.AgentGuardPolicy
	err  error
}

func (s *t2PolicyList) ListPolicies(context.Context, string) ([]*repository.AgentGuardPolicy, error) {
	return s.rows, s.err
}

type t2Sessions struct {
	SessionStore
	session *repository.Session
	err     error
}

func (s *t2Sessions) Get(context.Context, string) (*repository.Session, error) {
	return s.session, s.err
}

type t2Users struct {
	UserStore
	user *repository.User
	err  error
}

func (s *t2Users) GetByID(context.Context, string) (*repository.User, error) { return s.user, s.err }

func TestT2AgentGuardPolicyListAlwaysReturnsArray(t *testing.T) {
	for _, kind := range []string{"nil", "empty", "nonempty", "error"} {
		t.Run(kind, func(t *testing.T) {
			repo := &t2PolicyList{}
			if kind == "empty" {
				repo.rows = []*repository.AgentGuardPolicy{}
			}
			if kind == "nonempty" {
				repo.rows = []*repository.AgentGuardPolicy{{ID: "unit-policy"}}
			}
			if kind == "error" {
				repo.err = errors.New("unit repository error")
			}
			req := httptest.NewRequest("GET", "/admin/v1/agentguard/policies", nil)
			req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "unit-user", TenantID: "unit-tenant"}))
			response := httptest.NewRecorder()
			ListAgentGuardPolicies(&Dependencies{AgentGuardPolicyRepo: repo})(response, req)
			if kind == "error" {
				if response.Code == 200 {
					t.Fatal("repo failure returned success")
				}
				return
			}
			var body map[string]interface{}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			rows, ok := body["data"].([]interface{})
			if !ok {
				t.Fatalf("data is not an array: %s", response.Body.String())
			}
			want := 0
			if kind == "nonempty" {
				want = 1
			}
			if len(rows) != want {
				t.Fatal("existing policy response changed")
			}
		})
	}
}

func t2LegacyRouter(deps *Dependencies, called *bool) http.Handler {
	router := chi.NewRouter()
	router.Group(func(r chi.Router) {
		r.Use(PortalIntegrationAPIMiddleware("unit-legacy-secret", deps))
		for _, path := range []string{"/admin/v1/portal-integration/projects", "/admin/v1/portal-integration/audit-events", "/admin/v1/portal-integration/policies/model", "/admin/v1/portal-integration/projects/{id}"} {
			r.Get(path, func(w http.ResponseWriter, _ *http.Request) { *called = true; w.WriteHeader(204) })
		}
		r.Post("/admin/v1/portal-integration/keys", func(w http.ResponseWriter, _ *http.Request) { *called = true; w.WriteHeader(204) })
	})
	router.Group(func(r chi.Router) {
		r.Use(EvalIntegrationAPIMiddleware("unit-legacy-secret", deps))
		r.Get("/admin/v1/eval-integration/audit-events", func(w http.ResponseWriter, _ *http.Request) { *called = true; w.WriteHeader(204) })
	})
	return router
}

func TestT2LegacyActualRoutesDenyCurrentSealedSessionBeforeSharedSecret(t *testing.T) {
	session := &repository.Session{ID: "unit-native-token", UserID: "unit-user", TenantID: "unit-tenant", ExpiresAt: time.Now().Add(time.Hour)}
	user := &repository.User{ID: "unit-user", TenantID: "unit-tenant", Role: "platform_connector", Status: "active"}
	for _, route := range []struct{ method, path string }{{"GET", "/admin/v1/portal-integration/projects"}, {"GET", "/admin/v1/portal-integration/audit-events"}, {"GET", "/admin/v1/portal-integration/policies/model"}, {"GET", "/admin/v1/eval-integration/audit-events"}, {"GET", "/admin/v1/portal-integration/projects/unit-project"}, {"POST", "/admin/v1/portal-integration/keys"}} {
		for _, withSecret := range []bool{false, true} {
			t.Run(route.method+route.path+map[bool]string{false: "-bearer", true: "-with-secret"}[withSecret], func(t *testing.T) {
				called := false
				router := t2LegacyRouter(&Dependencies{SessionRepo: &t2Sessions{session: session}, UserStore: &t2Users{user: user}}, &called)
				request := httptest.NewRequest(route.method, route.path, nil)
				request.Header.Set("Authorization", "Bearer unit-native-token")
				if withSecret {
					request.Header.Set(InternalAPISecretHeader, "unit-legacy-secret")
				}
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)
				if response.Code != 403 || called {
					t.Fatalf("status=%d legacy called=%v body=%s", response.Code, called, response.Body.String())
				}
			})
		}
	}
}

func TestT2LegacySessionBoundaryUnknownExpiredInactiveTenantAndStoreFailure(t *testing.T) {
	for _, kind := range []string{"unknown", "expired", "inactive", "tenant", "role_changed", "session_error", "user_error", "missing_user"} {
		t.Run(kind, func(t *testing.T) {
			sessions := &t2Sessions{session: &repository.Session{ID: "unit-native-token", UserID: "unit-user", TenantID: "unit-tenant", ExpiresAt: time.Now().Add(time.Hour)}}
			users := &t2Users{user: &repository.User{ID: "unit-user", TenantID: "unit-tenant", Role: "platform_connector", Status: "active"}}
			expected := 401
			switch kind {
			case "unknown":
				sessions.session = nil
			case "expired":
				sessions.session.ExpiresAt = time.Now().Add(-time.Minute)
			case "inactive":
				users.user.Status = "disabled"
			case "tenant":
				sessions.session.TenantID = "other-tenant"
			case "role_changed":
				users.user.Role = "viewer"
			case "session_error":
				sessions.err = errors.New("unit session unavailable")
				expected = 503
			case "user_error":
				users.err = errors.New("unit user unavailable")
				expected = 503
			case "missing_user":
				users.user = nil
			}
			called := false
			router := t2LegacyRouter(&Dependencies{SessionRepo: sessions, UserStore: users}, &called)
			request := httptest.NewRequest("GET", "/admin/v1/portal-integration/projects", nil)
			request.Header.Set("Authorization", "Bearer unit-native-token")
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != expected || called {
				t.Fatalf("status=%d want=%d called=%v", response.Code, expected, called)
			}
		})
	}
}

func TestT2LegacyOrdinarySharedSecretRetainsOriginalContract(t *testing.T) {
	for _, header := range []string{"Authorization", InternalAPISecretHeader} {
		t.Run(header, func(t *testing.T) {
			called := false
			router := t2LegacyRouter(&Dependencies{}, &called)
			request := httptest.NewRequest("GET", "/admin/v1/portal-integration/projects", nil)
			value := "unit-legacy-secret"
			if header == "Authorization" {
				value = "Bearer " + value
			}
			request.Header.Set(header, value)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != 204 || !called {
				t.Fatalf("status=%d called=%v", response.Code, called)
			}
		})
	}
}

// An independent legacy secret must not depend on native session storage.
// Attached native cookies must still be checked, even when masked by a bearer.
type t2TokenSessions struct {
	SessionStore
	sessions map[string]*repository.Session
	err      error
	calls    int
}

func (s *t2TokenSessions) Get(_ context.Context, token string) (*repository.Session, error) {
	s.calls++
	return s.sessions[token], s.err
}

func TestT2LegacyCredentialCombinationsAndSessionFault(t *testing.T) {
	for _, tc := range []struct {
		name, bearer, cookie, extraCookie, internal string
		fault, missing                              bool
		want                                        int
		calls                                       int
	}{
		{"secret_bearer_store_fault", "unit-legacy-secret", "", "", "", true, false, 204, 0},
		{"secret_header_store_fault", "", "", "", "unit-legacy-secret", true, false, 204, 0},
		{"wrong_secret_bearer", "wrong", "", "", "", false, false, 401, 1},
		{"wrong_secret_header", "", "", "", "wrong", true, false, 401, 0},
		{"secret_bearer_native_cookie", "unit-legacy-secret", "native", "", "", false, false, 403, 1},
		{"unknown_bearer_native_cookie", "unknown", "native", "", "unit-legacy-secret", false, false, 403, 2},
		{"native_bearer_secret_header", "native", "", "", "unit-legacy-secret", false, false, 403, 1},
		{"native_cookie_secret_header", "", "native", "", "unit-legacy-secret", false, false, 403, 1},
		{"native_cookie_wrong_header", "", "native", "", "wrong", false, false, 403, 1},
		{"native_cookie_store_fault", "unit-legacy-secret", "native", "", "", true, false, 503, 1},
		{"native_bearer_store_fault", "native", "", "", "unit-legacy-secret", true, false, 503, 1},
		{"native_cookie_missing_store", "unit-legacy-secret", "native", "", "", false, true, 503, 0},
		{"secret_bearer_missing_store", "unit-legacy-secret", "", "", "", false, true, 204, 0},
		{"unknown_cookie_legitimate_secret", "unit-legacy-secret", "unknown", "", "", false, false, 204, 1},
		{"duplicate_native_cookie", "unit-legacy-secret", "unknown", "native", "", false, false, 403, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sessions := &t2TokenSessions{sessions: map[string]*repository.Session{
				"native": {ID: "native", UserID: "unit-user", TenantID: "unit-tenant", ExpiresAt: time.Now().Add(time.Hour)},
			}}
			if tc.fault {
				sessions.err = errors.New("session fault")
			}
			deps := &Dependencies{SessionRepo: sessions, UserStore: &t2Users{user: &repository.User{
				ID: "unit-user", TenantID: "unit-tenant", Role: "platform_connector", Status: "active",
			}}}
			if tc.missing {
				deps.SessionRepo = nil
			}
			called := false
			req := httptest.NewRequest("GET", "/admin/v1/portal-integration/projects", nil)
			if tc.bearer != "" {
				req.Header.Set("Authorization", "Bearer "+tc.bearer)
			}
			if tc.internal != "" {
				req.Header.Set(InternalAPISecretHeader, tc.internal)
			}
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "session_token", Value: tc.cookie})
			}
			if tc.extraCookie != "" {
				req.AddCookie(&http.Cookie{Name: "session_token", Value: tc.extraCookie})
			}
			response := httptest.NewRecorder()
			t2LegacyRouter(deps, &called).ServeHTTP(response, req)
			if response.Code != tc.want || called != (tc.want == 204) || sessions.calls != tc.calls {
				t.Fatalf("status=%d want=%d called=%v session lookups=%d want=%d", response.Code, tc.want, called, sessions.calls, tc.calls)
			}
		})
	}
}
