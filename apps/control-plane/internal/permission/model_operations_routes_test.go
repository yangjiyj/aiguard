package permission

import (
	"context"
	"github.com/go-chi/chi/v5"
	"net/http/httptest"
	"testing"
)

func TestModelOperationsRoutesRequireScopedModelsPermission(t *testing.T) {
	for _, tc := range []struct{ method, path, pattern, action string }{
		{"GET", "/admin/v1/model-operations/overview", "/admin/v1/model-operations/overview", "read"},
		{"GET", "/admin/v1/model-operations/sla", "/admin/v1/model-operations/sla", "read"},
		{"GET", "/admin/v1/model-operations/sla/export", "/admin/v1/model-operations/sla/export", "read"},
		{"GET", "/admin/v1/model-operations/targets", "/admin/v1/model-operations/targets", "read"},
		{"GET", "/admin/v1/model-operations/history", "/admin/v1/model-operations/history", "read"},
		{"GET", "/admin/v1/model-operations/quality", "/admin/v1/model-operations/quality", "read"},
		{"GET", "/admin/v1/model-operations/alerts", "/admin/v1/model-operations/alerts", "read"},
		{"GET", "/admin/v1/model-operations/config", "/admin/v1/model-operations/config", "read"},
		{"PUT", "/admin/v1/model-operations/config", "/admin/v1/model-operations/config", "write"},
		{"POST", "/admin/v1/model-operations/test", "/admin/v1/model-operations/test", "write"},
		{"GET", "/admin/v1/model-operations/jobs/job-1", "/admin/v1/model-operations/jobs/{id}", "read"},
		{"POST", "/admin/v1/model-operations/jobs/job-1/cancel", "/admin/v1/model-operations/jobs/{id}/cancel", "write"},
		{"POST", "/admin/v1/model-operations/alerts/alert-1/ack", "/admin/v1/model-operations/alerts/{id}/ack", "write"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rctx := chi.NewRouteContext()
			rctx.RoutePatterns = []string{tc.pattern}
			req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
			got := Resolve(req)
			if got.Resource != "models" || got.Action != tc.action || got.ScopeType != "tenant" || got.RequirePlatformAdmin {
				t.Fatalf("permission = %+v", got)
			}
			class := SoDClassFor(tc.method, tc.pattern)
			if class != SoDSystem || DecideSoD("security_officer", class, false) != SoDDeny || DecideSoD("auditor", class, false) != SoDDeny {
				t.Fatalf("model operations escaped system duty: %s", class)
			}
		})
	}
}
