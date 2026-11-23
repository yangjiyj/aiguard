package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestGetVersionInfoReadsConfiguredVersion(t *testing.T) {
	t.Setenv("JJD_VERSION", "9.8.7-test")
	t.Setenv("JJD_COMMIT", "abc1234")
	t.Setenv("JJD_BUILT_AT", "2026-06-24T01:02:03Z")

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/system/version", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_version",
		TenantID: "tenant_version",
		Role:     "viewer",
		Status:   "active",
	}))
	w := httptest.NewRecorder()

	GetVersionInfo(&Dependencies{}).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if got["version"] != "9.8.7-test" {
		t.Fatalf("version = %#v, want configured version", got["version"])
	}
	if got["commit"] != "abc1234" || got["built_at"] != "2026-06-24T01:02:03Z" {
		t.Fatalf("build metadata not returned: %#v", got)
	}
	if _, ok := got["build_time"]; ok {
		t.Fatalf("version response must not expose legacy build_time: %#v", got)
	}
}

func TestGetProductInfo(t *testing.T) {
	t.Setenv("JJD_VERSION", "2.6.10-engine")
	t.Setenv("JJD_COMMIT", "abc1234")
	cases := []struct {
		name, profile, productName, productVersion string
		wantProfile, wantName, wantVersion         string
	}{
		{name: "gateway defaults", wantProfile: "gateway", wantName: "JJDGuard", wantVersion: "2.6.10-engine"},
		{name: "gateway cannot override identity", profile: "gateway", productName: "Acme Guard", productVersion: "1.2.3", wantProfile: "gateway", wantName: "JJDGuard", wantVersion: "2.6.10-engine"},
		{name: "agent platform defaults", profile: "agent-platform", wantProfile: "agent-platform", wantName: "JJDGuard Agent Platform", wantVersion: "1.0.0"},
		{name: "agent platform custom product", profile: "agent-platform", productName: "Acme Guard", productVersion: "1.2.3", wantProfile: "agent-platform", wantName: "Acme Guard", wantVersion: "1.2.3"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PRODUCT_PROFILE", tc.profile)
			t.Setenv("PRODUCT_NAME", tc.productName)
			t.Setenv("PRODUCT_VERSION", tc.productVersion)
			req := httptest.NewRequest(http.MethodGet, "/admin/v1/system/product", nil)
			req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
				ID: "user_product", TenantID: "tenant_product", Role: "viewer", Status: "active",
			}))
			w := httptest.NewRecorder()
			GetProductInfo(&Dependencies{}).ServeHTTP(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			if got := w.Header().Get("Content-Type"); got != "application/json" {
				t.Fatalf("content type = %q", got)
			}
			var got map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if len(got) != 5 || got["product_profile"] != tc.wantProfile || got["product_name"] != tc.wantName || got["product_version"] != tc.wantVersion || got["engine_version"] != "2.6.10-engine" || got["engine_commit"] != "abc1234" {
				t.Fatalf("product response = %#v", got)
			}
		})
	}
}

func TestGetProductInfoRequiresUser(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/system/product", nil)
	w := httptest.NewRecorder()
	GetProductInfo(&Dependencies{}).ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
}
