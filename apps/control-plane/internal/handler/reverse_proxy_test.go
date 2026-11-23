package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type mockReverseProxyRouteRepo struct {
	entries map[string]*repository.ReverseProxyRoute
}

func newMockReverseProxyRouteRepo() *mockReverseProxyRouteRepo {
	return &mockReverseProxyRouteRepo{
		entries: make(map[string]*repository.ReverseProxyRoute),
	}
}

func (m *mockReverseProxyRouteRepo) GetByID(ctx context.Context, tenantID, id string) (*repository.ReverseProxyRoute, error) {
	entry, ok := m.entries[id]
	if !ok || entry.TenantID != tenantID {
		return nil, nil
	}
	return entry, nil
}

func (m *mockReverseProxyRouteRepo) List(ctx context.Context, tenantID string) ([]repository.ReverseProxyRoute, error) {
	result := make([]repository.ReverseProxyRoute, 0, len(m.entries))
	for _, entry := range m.entries {
		if entry.TenantID == tenantID {
			result = append(result, *entry)
		}
	}
	return result, nil
}

func (m *mockReverseProxyRouteRepo) Create(ctx context.Context, entry *repository.ReverseProxyRoute) error {
	entry.ID = "rpr_test_001"
	entry.CreatedAt = time.Now()
	entry.UpdatedAt = time.Now()
	m.entries[entry.ID] = entry
	return nil
}

func (m *mockReverseProxyRouteRepo) Update(ctx context.Context, entry *repository.ReverseProxyRoute) error {
	entry.UpdatedAt = time.Now()
	m.entries[entry.ID] = entry
	return nil
}

func (m *mockReverseProxyRouteRepo) Delete(ctx context.Context, tenantID, id string) error {
	delete(m.entries, id)
	return nil
}

func reverseProxyTestRequest(method, path, body string, user *repository.User) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if user == nil {
		return req
	}
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	return req.WithContext(ctx)
}

func TestListReverseProxyRoutes_Success(t *testing.T) {
	repo := newMockReverseProxyRouteRepo()
	repo.entries["rpr_001"] = &repository.ReverseProxyRoute{
		ID:               "rpr_001",
		TenantID:         "tenant_demo",
		Name:             "doubao",
		PathPrefix:       "/proxy/doubao",
		TargetURL:        "https://ark.cn-beijing.volces.com",
		TargetPathPrefix: "/api/v3",
		SecurityEnabled:  true,
		StatsEnabled:     true,
		Status:           "active",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}
	repo.entries["rpr_002"] = &repository.ReverseProxyRoute{
		ID:               "rpr_002",
		TenantID:         "tenant_other",
		Name:             "other",
		PathPrefix:       "/proxy/other",
		TargetURL:        "https://example.com",
		TargetPathPrefix: "",
		SecurityEnabled:  false,
		StatsEnabled:     false,
		Status:           "disabled",
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	deps := &Dependencies{
		ReverseProxyRouteRepo: repo,
	}

	req := reverseProxyTestRequest(http.MethodGet, "/admin/v1/reverse-proxy/routes", "", &repository.User{
		ID:       "user_1",
		TenantID: "tenant_demo",
		Role:     "developer",
	})
	w := httptest.NewRecorder()

	ListReverseProxyRoutes(deps).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Data  []map[string]interface{} `json:"data"`
		Total int                      `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Total != 1 {
		t.Fatalf("expected total=1, got %d", resp.Total)
	}
	if len(resp.Data) != 1 {
		t.Fatalf("expected 1 route, got %d", len(resp.Data))
	}
	if resp.Data[0]["path_prefix"] != "/proxy/doubao" {
		t.Fatalf("expected path_prefix /proxy/doubao, got %v", resp.Data[0]["path_prefix"])
	}
}

func TestCreateReverseProxyRoute_RejectsInvalidPathPrefix(t *testing.T) {
	deps := &Dependencies{
		ReverseProxyRouteRepo: newMockReverseProxyRouteRepo(),
		SystemRepo:            &MockSystemRepo{},
	}

	req := reverseProxyTestRequest(http.MethodPost, "/admin/v1/reverse-proxy/routes", `{
		"name":"doubao",
		"path_prefix":"proxy/doubao",
		"target_url":"https://ark.cn-beijing.volces.com",
		"security_enabled":true,
		"stats_enabled":true,
		"status":"active"
	}`, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	w := httptest.NewRecorder()

	CreateReverseProxyRoute(deps).ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d body=%s", w.Code, w.Body.String())
	}

	var resp map[string]map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp["error"]["code"] != "invalid_request" {
		t.Fatalf("expected error code invalid_request, got %s", resp["error"]["code"])
	}
}
