package permission

import (
	"context"
	"github.com/go-chi/chi/v5"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRecordDeletionPermissions(t *testing.T) {
	for _, c := range []struct{ path, resource, action string }{
		{"/admin/v1/keys/key-1", "api_keys", "delete"},
		{"/admin/v1/portal-integration/customer-keys/key-1", "api_keys", "delete"},
		{"/admin/v1/billing/redemptions/code-1", "billing", "write"},
	} {
		request := httptest.NewRequest("DELETE", c.path, nil)
		rctx := chi.NewRouteContext()
		pattern := strings.ReplaceAll(strings.ReplaceAll(c.path, "key-1", "{id}"), "code-1", "{id}")
		rctx.RoutePatterns = []string{pattern}
		request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, rctx))
		got := Resolve(request)
		if got.Resource != c.resource || got.Action != c.action || got.ScopeType != "tenant" {
			t.Fatalf("%s permission %+v", c.path, got)
		}
	}
}
