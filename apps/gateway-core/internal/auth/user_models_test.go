package auth

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelaccess"
)

func TestUserModelAuthorizationUsesTrustedIdentityAndRefreshes(t *testing.T) {
	access := &modelaccess.Access{Policy: modelaccess.Policy{Mode: "allowlist", ModelNames: []string{"model-a"}}, Role: "developer", Version: 1, ChatAllowed: true, EffectiveModels: []string{"model-a"}}
	loads, calls := 0, 0
	gate := UserModelAuthorization(func(_ context.Context, tenant, user string) (*modelaccess.Access, error) {
		if tenant != "tenant-a" || user != "user-a" {
			t.Fatalf("untrusted identity: %q %q", tenant, user)
		}
		loads++
		return access, nil
	})
	next := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !UserModelAllowed(r.Context(), r.URL.Query().Get("model")) {
			w.WriteHeader(403)
			return
		}
		calls++
		w.WriteHeader(200)
	}))
	request := func(model string) int {
		r := httptest.NewRequest("POST", "/v1/chat/completions?model="+model, nil)
		r.Header.Set("X-User-ID", "different-user")
		ctx := context.WithValue(r.Context(), TenantKey, "tenant-a")
		ctx = context.WithValue(ctx, UserKey, "user-a")
		w := httptest.NewRecorder()
		next.ServeHTTP(w, r.WithContext(ctx))
		return w.Code
	}
	if request("model-a") != 200 || request("model-b") != 403 {
		t.Fatal("personal allowlist was not enforced")
	}
	access.EffectiveModels = []string{}
	access.Version++
	if request("model-a") != 403 || calls != 1 || loads != 3 {
		t.Fatalf("old key must observe revocation, calls=%d loads=%d", calls, loads)
	}
}

func TestUserModelAuthorizationStorageFailureDoesNotCallUpstream(t *testing.T) {
	gate := UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) {
		return nil, errors.New("sensitive database detail")
	})
	calls := 0
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	ctx := context.WithValue(r.Context(), TenantKey, "tenant-a")
	ctx = context.WithValue(ctx, UserKey, "user-a")
	w := httptest.NewRecorder()
	gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ })).ServeHTTP(w, r.WithContext(ctx))
	if w.Code != 503 || calls != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, calls)
	}
	if w.Body.String() == "sensitive database detail" {
		t.Fatal("storage detail leaked")
	}
}

func TestUserModelAuthorizationLeavesUnownedServiceKeysOnExistingContract(t *testing.T) {
	gate := UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) {
		t.Fatal("must not resolve a synthetic user")
		return nil, nil
	})
	calls := 0
	r := httptest.NewRequest("GET", "/v1/models", nil)
	w := httptest.NewRecorder()
	gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ })).ServeHTTP(w, r)
	if calls != 1 {
		t.Fatal("legacy service key contract changed")
	}
}

func TestEveryOwnedKeyHasMandatoryModelAuthorization(t *testing.T) {
	for _, role := range []string{"developer", "viewer", "dept_manager", "tenant_admin", "platform_admin", "security_admin", "auditor", "chat_user"} {
		t.Run(role, func(t *testing.T) {
			calls := 0
			gate := UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) {
				return &modelaccess.Access{Role: role, ChatAllowed: true, EffectiveModels: []string{"department-model"}}, nil
			})
			next := gate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !UserModelAllowed(r.Context(), "outside-department") {
					w.WriteHeader(403)
					return
				}
				calls++
				w.WriteHeader(200)
			}))
			r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
			ctx := context.WithValue(r.Context(), TenantKey, "tenant-a")
			ctx = context.WithValue(ctx, UserKey, "user-a")
			w := httptest.NewRecorder()
			next.ServeHTTP(w, r.WithContext(ctx))
			if w.Code != 403 || calls != 0 {
				t.Fatalf("role=%s status=%d upstream=%d", role, w.Code, calls)
			}
		})
	}
}

func TestEmergencyOwnedKeyIsDeniedBeforeUpstream(t *testing.T) {
	calls := 0
	gate := UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) {
		return &modelaccess.Access{Role: "platform_admin", ChatAllowed: false}, nil
	})
	r := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	ctx := context.WithValue(r.Context(), TenantKey, "tenant-a")
	ctx = context.WithValue(ctx, UserKey, "emergency-user")
	w := httptest.NewRecorder()
	gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ })).ServeHTTP(w, r.WithContext(ctx))
	if w.Code != 403 || calls != 0 {
		t.Fatalf("status=%d upstream=%d", w.Code, calls)
	}
}

func TestReviewMissingOwnerIsForbidden(t *testing.T) {
	gate := UserModelAuthorization(func(context.Context, string, string) (*modelaccess.Access, error) { return nil, pgx.ErrNoRows })
	req := httptest.NewRequest("POST", "/v1/chat/completions", nil)
	ctx := context.WithValue(req.Context(), UserKey, "deleted-owner")
	w := httptest.NewRecorder()
	gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("upstream called") })).ServeHTTP(w, req.WithContext(ctx))
	if w.Code != 403 {
		t.Fatalf("missing owner status=%d body=%s", w.Code, w.Body.String())
	}
}
