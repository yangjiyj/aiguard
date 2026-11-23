package permission

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

func TestSecurityPostureRouteUsesSecurityConfigReadPermission(t *testing.T) {
	for _, path := range []string{"/admin/v1/security/posture", "/api/security/posture"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, path+"?tenant_id=forged", nil)
			resolved := Resolve(r)
			if resolved.Resource != "system_config" || resolved.Action != "read" || resolved.ScopeType != "tenant" || resolved.RequirePlatformAdmin {
				t.Fatalf("posture read route has no tenant-scoped permission: %+v", resolved)
			}
			if class, ok := sodRouteTable["GET "+path]; !ok || class != SoDSecurityConfigRead {
				t.Fatalf("posture read route has incorrect separation of duties: %v found=%v", class, ok)
			}
			for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
				if _, ok := routeTable[method+" "+path]; ok {
					t.Fatalf("read-only posture route admits %s", method)
				}
			}
		})
	}
}

func TestSecurityPostureAliasesEnforceSameSoDOverHTTP(t *testing.T) {
	for _, path := range []string{"/admin/v1/security/posture", "/api/security/posture"} {
		for _, tc := range []struct {
			role string
			want int
		}{{"security_officer", http.StatusOK}, {"auditor", http.StatusForbidden}} {
			t.Run(path+"/"+tc.role, func(t *testing.T) {
				router := chi.NewRouter()
				router.Use(SoDGuard(nil))
				router.Use(Middleware(nil, nil, false))
				router.Get(path, func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("X-Tenant", auth.GetUser(r.Context()).TenantID)
					w.WriteHeader(http.StatusOK)
				})
				r := httptest.NewRequest(http.MethodGet, path+"?tenant_id=forged", nil)
				r.Header.Set("X-Tenant-ID", "forged")
				r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: "posture-reader", Role: tc.role, TenantID: "tenant-authenticated"}))
				w := httptest.NewRecorder()
				router.ServeHTTP(w, r)
				if w.Code != tc.want {
					t.Fatalf("SoD status = %d, want %d: %s", w.Code, tc.want, w.Body.String())
				}
				if tc.want == http.StatusOK && w.Header().Get("X-Tenant") != "tenant-authenticated" {
					t.Fatal("query or header changed the authenticated tenant")
				}
			})
		}
	}
}
