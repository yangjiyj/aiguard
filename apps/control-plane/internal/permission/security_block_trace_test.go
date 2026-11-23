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

func TestBlockTraceRouteKeepsSecurityRecordReadPermissionAndSoD(t *testing.T) {
	const route = "/admin/v1/security/block-records/{block_id}/trace"
	for _, tc := range []struct {
		role string
		want int
	}{{"platform_admin", 200}, {"security_officer", 200}, {"auditor", 200}} {
		t.Run(tc.role, func(t *testing.T) {
			router := chi.NewRouter()
			router.Use(SoDGuard(nil))
			router.Get(route, func(w http.ResponseWriter, r *http.Request) {
				resolved := Resolve(r)
				if resolved.Resource != "security_events" || resolved.Action != "read" || resolved.ScopeType != "tenant" {
					t.Fatalf("trace permission: %+v", resolved)
				}
				if auth.GetUser(r.Context()).TenantID != "tenant-authenticated" {
					t.Fatalf("tenant: %+v", resolved)
				}
				w.WriteHeader(200)
			})
			r := httptest.NewRequest(http.MethodGet, "/admin/v1/security/block-records/evt-one/trace?tenant_id=forged", nil)
			r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: "user-one", Role: tc.role, TenantID: "tenant-authenticated"}))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d %s", w.Code, tc.want, w.Body.String())
			}
		})
	}
	if class := SoDClassFor(http.MethodGet, route); class != SoDSecurityRecordRead {
		t.Fatalf("trace SoD class=%v", class)
	}
}
