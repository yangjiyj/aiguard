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

type integrationProjectFixture struct {
	IntegrationRepo
	selectedTenant string
	projects       map[string][]repository.IntegrationProject
}

func (f *integrationProjectFixture) ListProjects(_ context.Context, tenant string) ([]repository.IntegrationProject, error) {
	f.selectedTenant = tenant
	return f.projects[tenant], nil
}

func TestIntegrationProjectsUseSessionTenantAndMinimalProjection(t *testing.T) {
	fixture := &integrationProjectFixture{projects: map[string][]repository.IntegrationProject{
		"tenant-a": {{ID: "project-a", Name: "Project A", Status: "active"}},
		"tenant-b": {{ID: "project-b", Name: "Foreign Project", Status: "active"}},
	}}
	deps := &Dependencies{IntegrationRepo: fixture}
	r := httptest.NewRequest("GET", "/admin/v1/integration/projects?tenant_id=tenant-b", nil)
	r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: "connector", TenantID: "tenant-a", Role: "platform_connector"}))
	w := httptest.NewRecorder()
	ListIntegrationProjects(deps).ServeHTTP(w, r)
	if w.Code != 200 || fixture.selectedTenant != "tenant-a" {
		t.Fatalf("status=%d tenant=%q", w.Code, fixture.selectedTenant)
	}
	var body struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if len(body.Data) != 1 || len(body.Data[0]) != 3 || body.Data[0]["id"] != "project-a" || body.Data[0]["name"] != "Project A" || body.Data[0]["status"] != "active" {
		t.Fatalf("projection=%v", body.Data)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("project projection must not be cached across sessions")
	}
	for _, role := range []string{"tenant_owner", "developer", "auditor"} {
		r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: "ordinary-user", TenantID: "tenant-b", Role: role}))
		w = httptest.NewRecorder()
		ListIntegrationProjects(deps).ServeHTTP(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("role=%s status=%d", role, w.Code)
		}
	}
}

func TestIntegrationGatewayAdvertisementUsesConfiguredHTTPSAndAliases(t *testing.T) {
	t.Setenv("GATEWAY_PUBLIC_BASE_URL", "https://192.0.2.20:28880/v1?token=fixture")
	t.Setenv("GATEWAY_PUBLIC_ALIASES", "https://tls-edge:28880,https://192.0.2.20:28880/v1, file:///tmp/fixture,http://untrusted.test")
	primary, aliases := integrationGatewayURLs("https://tls-edge:28880")
	if primary != "https://192.0.2.20:28880/v1" || len(aliases) != 2 || aliases[1] != "https://tls-edge:28880" {
		t.Fatalf("primary=%q aliases=%v", primary, aliases)
	}
	t.Setenv("GATEWAY_PUBLIC_BASE_URL", "http://192.0.2.20:28880")
	if primary, _ = integrationGatewayURLs("https://tls-edge:28880"); primary != "" {
		t.Fatal("HTTP transport URL must not masquerade as public HTTPS")
	}
}
