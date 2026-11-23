package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// --- Mock ProxyWhitelistRepository ---

type MockProxyWhitelistRepo struct {
	entries map[string]*repository.ProxyWhitelist
	nextID  int
}

func newMockProxyWhitelistRepo() *MockProxyWhitelistRepo {
	return &MockProxyWhitelistRepo{
		entries: make(map[string]*repository.ProxyWhitelist),
		nextID:  1,
	}
}

func (m *MockProxyWhitelistRepo) GetByID(ctx context.Context, tenantID, id string) (*repository.ProxyWhitelist, error) {
	e, ok := m.entries[id]
	if !ok || e.TenantID != tenantID {
		return nil, nil
	}
	return e, nil
}

func (m *MockProxyWhitelistRepo) List(ctx context.Context, tenantID string) ([]repository.ProxyWhitelist, error) {
	var result []repository.ProxyWhitelist
	for _, e := range m.entries {
		if e.TenantID == tenantID {
			result = append(result, *e)
		}
	}
	return result, nil
}

func (m *MockProxyWhitelistRepo) Create(ctx context.Context, entry *repository.ProxyWhitelist) error {
	m.nextID++
	entry.ID = "pw_test_" + strings.Repeat("0", 4-len(string(rune(m.nextID)))) + string(rune(m.nextID))
	entry.CreatedAt = time.Now()
	entry.UpdatedAt = time.Now()
	m.entries[entry.ID] = entry
	return nil
}

func (m *MockProxyWhitelistRepo) Update(ctx context.Context, entry *repository.ProxyWhitelist) error {
	if _, ok := m.entries[entry.ID]; !ok {
		return fmt.Errorf("not found")
	}
	entry.UpdatedAt = time.Now()
	m.entries[entry.ID] = entry
	return nil
}

func (m *MockProxyWhitelistRepo) Delete(ctx context.Context, tenantID, id string) error {
	delete(m.entries, id)
	return nil
}

// Need fmt for the mock

// --- Mock SystemRepo for audit logging ---

type MockSystemRepo struct{}

func (m *MockSystemRepo) Get(ctx context.Context, key string) (*repository.SystemSetting, error) {
	return nil, nil
}

func (m *MockSystemRepo) GetAll(ctx context.Context) ([]*repository.SystemSetting, error) {
	return []*repository.SystemSetting{}, nil
}

func (m *MockSystemRepo) Set(ctx context.Context, key, value string) error {
	return nil
}

func (m *MockSystemRepo) SetMultiple(ctx context.Context, settings map[string]string) error {
	return nil
}

func (m *MockSystemRepo) CreateAuditOperation(ctx context.Context, op *repository.AuditOperation) error {
	return nil
}

func (m *MockSystemRepo) ListAuditOperations(ctx context.Context, limit, offset int, userID string) ([]*repository.AuditOperation, int, error) {
	return []*repository.AuditOperation{}, 0, nil
}

func (m *MockSystemRepo) GetBool(ctx context.Context, key string) (bool, error) {
	return false, nil
}

// --- Unit Tests ---

func TestMapProxyWhitelistToInfo(t *testing.T) {
	now := time.Now()
	entry := &repository.ProxyWhitelist{
		ID:           "pw_123",
		TenantID:     "tenant_demo",
		HostPattern:  "*.example.com",
		Port:         443,
		AuditEnabled: true,
		Description:  "test entry",
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	info := mapProxyWhitelistToInfo(entry)

	if info.ID != "pw_123" {
		t.Errorf("expected ID=pw_123, got %s", info.ID)
	}
	if info.HostPattern != "*.example.com" {
		t.Errorf("expected HostPattern=*.example.com, got %s", info.HostPattern)
	}
	if info.Port != 443 {
		t.Errorf("expected Port=443, got %d", info.Port)
	}
	if !info.AuditEnabled {
		t.Errorf("expected AuditEnabled=true")
	}
	if info.TenantID != "tenant_demo" {
		t.Errorf("expected TenantID=tenant_demo, got %s", info.TenantID)
	}
}

func TestGetProxyWhitelist_Unauthorized(t *testing.T) {
	deps := &Dependencies{
		ProxyWhitelistRepo: newMockProxyWhitelistRepo(),
	}
	handler := GetProxyWhitelist(deps)

	req := httptest.NewRequest("GET", "/admin/v1/proxy/whitelist", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestGetProxyWhitelist_Success(t *testing.T) {
	mockRepo := newMockProxyWhitelistRepo()
	mockRepo.entries["pw_001"] = &repository.ProxyWhitelist{
		ID:           "pw_001",
		TenantID:     "tenant_demo",
		HostPattern:  "*.openai.com",
		Port:         443,
		AuditEnabled: true,
		Description:  "OpenAI",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	mockRepo.entries["pw_002"] = &repository.ProxyWhitelist{
		ID:           "pw_002",
		TenantID:     "tenant_demo",
		HostPattern:  "api.deepseek.com",
		Port:         443,
		AuditEnabled: false,
		Description:  "DeepSeek",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	deps := &Dependencies{
		ProxyWhitelistRepo: mockRepo,
	}
	handler := GetProxyWhitelist(deps)

	req := httptest.NewRequest("GET", "/admin/v1/proxy/whitelist", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	data, ok := resp["data"].([]interface{})
	if !ok || len(data) != 2 {
		t.Errorf("expected 2 entries, got %v", resp["data"])
	}
}

func TestGetProxyWhitelist_TenantIsolation(t *testing.T) {
	mockRepo := newMockProxyWhitelistRepo()
	mockRepo.entries["pw_001"] = &repository.ProxyWhitelist{
		ID:           "pw_001",
		TenantID:     "tenant_demo",
		HostPattern:  "*.openai.com",
		Port:         443,
		AuditEnabled: true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	mockRepo.entries["pw_002"] = &repository.ProxyWhitelist{
		ID:           "pw_002",
		TenantID:     "tenant_other",
		HostPattern:  "*.other.com",
		Port:         443,
		AuditEnabled: true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	deps := &Dependencies{
		ProxyWhitelistRepo: mockRepo,
	}
	handler := GetProxyWhitelist(deps)

	req := httptest.NewRequest("GET", "/admin/v1/proxy/whitelist", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_demo",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)

	data, _ := resp["data"].([]interface{})
	if len(data) != 1 {
		t.Errorf("expected 1 entry (tenant isolation), got %d", len(data))
	}
}

func TestCreateProxyWhitelist_Unauthorized(t *testing.T) {
	deps := &Dependencies{
		ProxyWhitelistRepo: newMockProxyWhitelistRepo(),
	}
	handler := CreateProxyWhitelist(deps)

	req := httptest.NewRequest("POST", "/admin/v1/proxy/whitelist", strings.NewReader(`{"host_pattern":"*.test.com"}`))
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestCreateProxyWhitelist_ForbiddenForNonAdmin(t *testing.T) {
	deps := &Dependencies{
		ProxyWhitelistRepo: newMockProxyWhitelistRepo(),
	}
	handler := CreateProxyWhitelist(deps)

	req := httptest.NewRequest("POST", "/admin/v1/proxy/whitelist", strings.NewReader(`{"host_pattern":"*.test.com"}`))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_dev",
		TenantID: "tenant_demo",
		Role:     "developer",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func TestCreateProxyWhitelist_MissingHostPattern(t *testing.T) {
	deps := &Dependencies{
		ProxyWhitelistRepo: newMockProxyWhitelistRepo(),
	}
	handler := CreateProxyWhitelist(deps)

	req := httptest.NewRequest("POST", "/admin/v1/proxy/whitelist", strings.NewReader(`{"port":443}`))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing host_pattern, got %d", w.Code)
	}
}

func TestCreateProxyWhitelist_Success(t *testing.T) {
	mockRepo := newMockProxyWhitelistRepo()
	mockSystemRepo := &MockSystemRepo{}
	deps := &Dependencies{
		ProxyWhitelistRepo: mockRepo,
		SystemRepo:         mockSystemRepo,
	}
	handler := CreateProxyWhitelist(deps)

	body := `{"host_pattern":"*.newapi.com","port":8443,"audit_enabled":true,"description":"NewAPI"}`
	req := httptest.NewRequest("POST", "/admin/v1/proxy/whitelist", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("expected 201, got %d: %s", w.Code, w.Body.String())
	}

	var resp ProxyWhitelistInfo
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.HostPattern != "*.newapi.com" {
		t.Errorf("expected host_pattern=*.newapi.com, got %s", resp.HostPattern)
	}
	if resp.Port != 8443 {
		t.Errorf("expected port=8443, got %d", resp.Port)
	}
	if !resp.AuditEnabled {
		t.Errorf("expected audit_enabled=true")
	}
}

func TestCreateProxyWhitelist_DefaultPort(t *testing.T) {
	mockRepo := newMockProxyWhitelistRepo()
	mockSystemRepo := &MockSystemRepo{}
	deps := &Dependencies{
		ProxyWhitelistRepo: mockRepo,
		SystemRepo:         mockSystemRepo,
	}
	handler := CreateProxyWhitelist(deps)

	body := `{"host_pattern":"*.default.com","audit_enabled":false}`
	req := httptest.NewRequest("POST", "/admin/v1/proxy/whitelist", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	var resp ProxyWhitelistInfo
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.Port != 443 {
		t.Errorf("expected default port=443 when port=0, got %d", resp.Port)
	}
}

func TestCreateProxyWhitelist_InvalidJSON(t *testing.T) {
	deps := &Dependencies{
		ProxyWhitelistRepo: newMockProxyWhitelistRepo(),
	}
	handler := CreateProxyWhitelist(deps)

	req := httptest.NewRequest("POST", "/admin/v1/proxy/whitelist", strings.NewReader(`not json`))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestUpdateProxyWhitelist_NotFound(t *testing.T) {
	mockRepo := newMockProxyWhitelistRepo()
	mockSystemRepo := &MockSystemRepo{}
	deps := &Dependencies{
		ProxyWhitelistRepo: mockRepo,
		SystemRepo:         mockSystemRepo,
	}

	r := chi.NewRouter()
	r.Put("/admin/v1/proxy/whitelist/{id}", UpdateProxyWhitelist(deps))

	body := `{"host_pattern":"*.updated.com"}`
	req := httptest.NewRequest("PUT", "/admin/v1/proxy/whitelist/pw_nonexistent", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Handler uses writeError (400) but error code is "not_found"
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errDetail := resp["error"].(map[string]interface{})
	if errDetail["code"] != "not_found" {
		t.Errorf("expected error code 'not_found', got %v", errDetail["code"])
	}
}

func TestUpdateProxyWhitelist_Success(t *testing.T) {
	mockRepo := newMockProxyWhitelistRepo()
	mockRepo.entries["pw_001"] = &repository.ProxyWhitelist{
		ID:           "pw_001",
		TenantID:     "tenant_demo",
		HostPattern:  "*.old.com",
		Port:         443,
		AuditEnabled: true,
		Description:  "old desc",
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	mockSystemRepo := &MockSystemRepo{}
	deps := &Dependencies{
		ProxyWhitelistRepo: mockRepo,
		SystemRepo:         mockSystemRepo,
	}

	r := chi.NewRouter()
	r.Put("/admin/v1/proxy/whitelist/{id}", UpdateProxyWhitelist(deps))

	body := `{"host_pattern":"*.new.com","audit_enabled":false,"description":"updated"}`
	req := httptest.NewRequest("PUT", "/admin/v1/proxy/whitelist/pw_001", strings.NewReader(body))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp ProxyWhitelistInfo
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.HostPattern != "*.new.com" {
		t.Errorf("expected host_pattern=*.new.com, got %s", resp.HostPattern)
	}
	if resp.AuditEnabled {
		t.Errorf("expected audit_enabled=false after update")
	}
}

func TestUpdateProxyWhitelist_CrossTenant(t *testing.T) {
	mockRepo := newMockProxyWhitelistRepo()
	mockRepo.entries["pw_001"] = &repository.ProxyWhitelist{
		ID:           "pw_001",
		TenantID:     "tenant_other",
		HostPattern:  "*.other.com",
		Port:         443,
		AuditEnabled: true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	mockSystemRepo := &MockSystemRepo{}
	deps := &Dependencies{
		ProxyWhitelistRepo: mockRepo,
		SystemRepo:         mockSystemRepo,
	}

	r := chi.NewRouter()
	r.Put("/admin/v1/proxy/whitelist/{id}", UpdateProxyWhitelist(deps))

	req := httptest.NewRequest("PUT", "/admin/v1/proxy/whitelist/pw_001", strings.NewReader(`{"host_pattern":"*.hacked.com"}`))
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Handler uses writeError (400) but error code is "not_found"
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for cross-tenant update, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errDetail := resp["error"].(map[string]interface{})
	if errDetail["code"] != "not_found" {
		t.Errorf("expected error code 'not_found' for cross-tenant, got %v", errDetail["code"])
	}
}

func TestDeleteProxyWhitelist_Success(t *testing.T) {
	mockRepo := newMockProxyWhitelistRepo()
	mockRepo.entries["pw_001"] = &repository.ProxyWhitelist{
		ID:           "pw_001",
		TenantID:     "tenant_demo",
		HostPattern:  "*.delete.com",
		Port:         443,
		AuditEnabled: true,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	mockSystemRepo := &MockSystemRepo{}
	deps := &Dependencies{
		ProxyWhitelistRepo: mockRepo,
		SystemRepo:         mockSystemRepo,
	}

	r := chi.NewRouter()
	r.Delete("/admin/v1/proxy/whitelist/{id}", DeleteProxyWhitelist(deps))

	req := httptest.NewRequest("DELETE", "/admin/v1/proxy/whitelist/pw_001", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}

	if _, exists := mockRepo.entries["pw_001"]; exists {
		t.Errorf("entry should be deleted")
	}
}

func TestDeleteProxyWhitelist_NotFound(t *testing.T) {
	mockRepo := newMockProxyWhitelistRepo()
	mockSystemRepo := &MockSystemRepo{}
	deps := &Dependencies{
		ProxyWhitelistRepo: mockRepo,
		SystemRepo:         mockSystemRepo,
	}

	r := chi.NewRouter()
	r.Delete("/admin/v1/proxy/whitelist/{id}", DeleteProxyWhitelist(deps))

	req := httptest.NewRequest("DELETE", "/admin/v1/proxy/whitelist/pw_nonexistent", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_admin",
		TenantID: "tenant_demo",
		Role:     "platform_admin",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	// Handler uses writeError (400) but error code is "not_found"
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}

	var resp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &resp)
	errDetail := resp["error"].(map[string]interface{})
	if errDetail["code"] != "not_found" {
		t.Errorf("expected error code 'not_found', got %v", errDetail["code"])
	}
}

func TestDeleteProxyWhitelist_NonAdminForbidden(t *testing.T) {
	deps := &Dependencies{
		ProxyWhitelistRepo: newMockProxyWhitelistRepo(),
	}

	r := chi.NewRouter()
	r.Delete("/admin/v1/proxy/whitelist/{id}", DeleteProxyWhitelist(deps))

	req := httptest.NewRequest("DELETE", "/admin/v1/proxy/whitelist/pw_001", nil)
	ctx := context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_dev",
		TenantID: "tenant_demo",
		Role:     "developer",
	})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for non-admin, got %d", w.Code)
	}
}

func (m *MockSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, m.Get, keys)
}
