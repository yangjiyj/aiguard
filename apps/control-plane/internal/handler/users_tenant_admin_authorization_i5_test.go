package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// Tenant administrators may list their own tenant for model access and account merges.
// Profile writes/deletion remain platform-admin-only.
func TestUsersResourcesScopeTenantAdminReadsAndRejectWrites(t *testing.T) {
	tenantAdmin := &repository.User{
		ID:       "ta-1",
		TenantID: "tenant-1",
		Role:     "tenant_admin",
		Status:   "active",
	}
	store := &licenseUserStore{users: map[string]*repository.User{
		"u-target": {ID: "u-target", TenantID: "tenant-1", Role: "viewer", Status: "active"},
		"u-other":  {ID: "u-other", TenantID: "tenant-2", Role: "viewer", Status: "active"},
	}}
	deps := &Dependencies{UserStore: store}

	withActor := func(req *http.Request, actor *repository.User) *http.Request {
		return req.WithContext(context.WithValue(req.Context(), auth.UserKey, actor))
	}
	withChiID := func(req *http.Request, id string) *http.Request {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", id)
		return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	}

	t.Run("ListUsers exposes only the administrator tenant", func(t *testing.T) {
		req := withActor(httptest.NewRequest(http.MethodGet, "/admin/v1/users", nil), tenantAdmin)
		w := httptest.NewRecorder()
		ListUsers(deps).ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("scoped user list status=%d", w.Code)
		}
		var payload struct {
			Data []struct {
				ID       string `json:"id"`
				TenantID string `json:"tenant_id"`
			}
			Total int `json:"total"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Total != 1 || len(payload.Data) != 1 || payload.Data[0].ID != "u-target" || payload.Data[0].TenantID != "tenant-1" {
			t.Fatal("other tenant leaked into user list")
		}
	})

	t.Run("UpdateUser rejects tenant_admin", func(t *testing.T) {
		req := withActor(httptest.NewRequest(http.MethodPut, "/admin/v1/users/u-target", nil), tenantAdmin)
		req = withChiID(req, "u-target")
		w := httptest.NewRecorder()
		UpdateUser(deps).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("UpdateUser tenant_admin status = %d, want 403; body=%s", w.Code, w.Body.String())
		}
		if code := decodeErrorCode(t, w.Body.String()); code != "forbidden" {
			t.Fatalf("UpdateUser tenant_admin code = %q, want forbidden", code)
		}
	})

	t.Run("DeleteUser rejects tenant_admin", func(t *testing.T) {
		req := withActor(httptest.NewRequest(http.MethodDelete, "/admin/v1/users/u-target", nil), tenantAdmin)
		req = withChiID(req, "u-target")
		w := httptest.NewRecorder()
		DeleteUser(deps).ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Fatalf("DeleteUser tenant_admin status = %d, want 403; body=%s", w.Code, w.Body.String())
		}
		if code := decodeErrorCode(t, w.Body.String()); code != "forbidden" {
			t.Fatalf("DeleteUser tenant_admin code = %q, want forbidden", code)
		}
	})
}
