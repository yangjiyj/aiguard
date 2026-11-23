package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type billingModelRepoFake struct {
	ModelRepo
	models    []*repository.Model
	err       error
	tenantIDs []string
}

func (f *billingModelRepoFake) List(_ context.Context, tenantID string) ([]*repository.Model, error) {
	f.tenantIDs = append(f.tenantIDs, tenantID)
	return f.models, f.err
}

type billingProviderRepoFake struct {
	ProviderRepo
	providers []*repository.Provider
	err       error
	tenantIDs []string
}

func (f *billingProviderRepoFake) List(_ context.Context, tenantID string) ([]*repository.Provider, error) {
	f.tenantIDs = append(f.tenantIDs, tenantID)
	return f.providers, f.err
}

func billingModelsRequest(role, target string, deps *Dependencies) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, target, nil)
	request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{
		ID: "billing-admin", TenantID: "platform", Role: role, Status: "active",
	}))
	response := httptest.NewRecorder()
	ListBillingModels(deps).ServeHTTP(response, request)
	return response
}

func TestBillingModelsRequiresPlatformAdminAndTenant(t *testing.T) {
	models := &billingModelRepoFake{}
	providers := &billingProviderRepoFake{}
	deps := &Dependencies{ModelRepo: models, ProviderRepo: providers}

	response := billingModelsRequest("tenant_admin", "/admin/v1/billing/models?tenant_id=tenant-a", deps)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-platform admin: want 403, got %d %s", response.Code, response.Body.String())
	}
	if len(models.tenantIDs) != 0 || len(providers.tenantIDs) != 0 {
		t.Fatalf("repositories must not run before platform-admin authorization")
	}

	response = billingModelsRequest("platform_admin", "/admin/v1/billing/models", deps)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing tenant: want 400, got %d %s", response.Code, response.Body.String())
	}
	if len(models.tenantIDs) != 0 || len(providers.tenantIDs) != 0 {
		t.Fatalf("repositories must not run without target tenant")
	}
}

func TestBillingModelsUsesSelectedTenantAndReturnsSanitizedCatalog(t *testing.T) {
	models := &billingModelRepoFake{models: []*repository.Model{
		{ID: "model-z-internal", ProviderID: "provider-a", ModelName: "z-model", ModelLabel: "模型 Z", UpstreamModelID: "upstream-secret-z", Status: "disabled"},
		{ID: "model-a-internal", ProviderID: "provider-a", ModelName: "a-model", ModelLabel: "模型 A", UpstreamModelID: "upstream-secret-a", Status: "active"},
		{ID: "model-empty", ProviderID: "provider-a", ModelName: "  ", Status: "active"},
		{ID: "model-cross", ProviderID: "provider-b", ModelName: "cross-model", Status: "active"},
	}}
	providers := &billingProviderRepoFake{providers: []*repository.Provider{
		{ID: "provider-a", TenantID: "tenant-a", Name: "供应商甲", ProviderType: "openai", BaseURL: "https://internal-a.example", Status: "active"},
		{ID: "provider-b", TenantID: "tenant-b", Name: "供应商乙", ProviderType: "anthropic", BaseURL: "https://internal-b.example", Status: "active"},
	}}
	response := billingModelsRequest(
		"platform_admin",
		"/admin/v1/billing/models?tenant_id=tenant-a",
		&Dependencies{ModelRepo: models, ProviderRepo: providers},
	)
	if response.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", response.Code, response.Body.String())
	}
	if len(models.tenantIDs) != 1 || models.tenantIDs[0] != "tenant-a" ||
		len(providers.tenantIDs) != 1 || providers.tenantIDs[0] != "tenant-a" {
		t.Fatalf("repositories did not receive the selected tenant: models=%v providers=%v", models.tenantIDs, providers.tenantIDs)
	}
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Data) != 2 || payload.Data[0]["model_name"] != "a-model" || payload.Data[1]["model_name"] != "z-model" {
		t.Fatalf("unexpected sorted tenant catalog: %#v", payload.Data)
	}
	for _, item := range payload.Data {
		if len(item) != 5 {
			t.Fatalf("catalog item must contain five public fields only: %#v", item)
		}
		for _, field := range []string{"model_name", "model_label", "provider_name", "provider_type", "status"} {
			if _, ok := item[field]; !ok {
				t.Fatalf("catalog item missing %q: %#v", field, item)
			}
		}
	}
	for _, forbidden := range []string{"model-z-internal", "provider-a", "upstream-secret", "internal-a.example", "credential"} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("catalog leaked internal field %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestBillingModelsSanitizesRepositoryErrors(t *testing.T) {
	models := &billingModelRepoFake{err: errors.New("postgres://db.internal/?password=leak-canary")}
	providers := &billingProviderRepoFake{}
	response := billingModelsRequest(
		"platform_admin",
		"/admin/v1/billing/models?tenant_id=tenant-a",
		&Dependencies{ModelRepo: models, ProviderRepo: providers},
	)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("want 500, got %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "postgres") || strings.Contains(response.Body.String(), "leak-canary") {
		t.Fatalf("repository error leaked infrastructure details: %s", response.Body.String())
	}
}
