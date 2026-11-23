package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
	"github.com/go-chi/chi/v5"
)

// Mock implementations for testing the production SyncModels handler

type MockProviderRepository struct {
	Providers         map[string]*repository.Provider
	Credentials       map[string]*repository.ProviderCredential
	CredentialHistory map[string][]*repository.ProviderCredential
}

func (m *MockProviderRepository) GetByID(ctx context.Context, tenantID, id string) (*repository.Provider, error) {
	provider, ok := m.Providers[id]
	if !ok || provider.TenantID != tenantID {
		return nil, nil
	}
	return provider, nil
}

func (m *MockProviderRepository) List(ctx context.Context, tenantID string) ([]*repository.Provider, error) {
	providers := make([]*repository.Provider, 0, len(m.Providers))
	for _, provider := range m.Providers {
		if tenantID == "" || provider.TenantID == tenantID {
			providers = append(providers, provider)
		}
	}
	return providers, nil
}

func (m *MockProviderRepository) Create(ctx context.Context, provider *repository.Provider) error {
	return nil
}

func (m *MockProviderRepository) Update(ctx context.Context, provider *repository.Provider) error {
	return nil
}

func (m *MockProviderRepository) GetCredential(ctx context.Context, providerID string) (*repository.ProviderCredential, error) {
	cred, ok := m.Credentials[providerID]
	if !ok {
		return nil, fmt.Errorf("credential not found")
	}
	return cred, nil
}

func (m *MockProviderRepository) ListCredentialHistory(ctx context.Context, providerID string) ([]*repository.ProviderCredential, error) {
	if m.CredentialHistory != nil {
		if history, ok := m.CredentialHistory[providerID]; ok {
			return history, nil
		}
	}
	cred, ok := m.Credentials[providerID]
	if !ok {
		return []*repository.ProviderCredential{}, nil
	}
	return []*repository.ProviderCredential{cred}, nil
}

func (m *MockProviderRepository) CreateCredential(ctx context.Context, cred *repository.ProviderCredential) error {
	return nil
}

func (m *MockProviderRepository) CreateWithCredential(ctx context.Context, provider *repository.Provider, cred *repository.ProviderCredential) error {
	return nil
}

func (m *MockProviderRepository) UpdateWithCredential(ctx context.Context, provider *repository.Provider, cred *repository.ProviderCredential) error {
	return nil
}

func (m *MockProviderRepository) Delete(ctx context.Context, tenantID, id string) error {
	return nil
}

func (m *MockProviderRepository) RecentProviderMetrics(ctx context.Context, tenantID string, windowMinutes int) (map[string]repository.ProviderRecentMetrics, error) {
	return map[string]repository.ProviderRecentMetrics{}, nil
}

type UpsertResult struct {
	Created bool
	Err     error
}

type MockModelRepository struct {
	ReplaceCalls []struct {
		TenantID                     string
		ProviderID                   string
		ExpectedCredentialID         string
		ExpectedProviderConfigDigest string
		Desired                      []repository.VerifiedProviderModel
	}
	ReplaceResult repository.VerifiedModelSyncResult
	ReplaceError  error
	UpsertResults map[string]UpsertResult
	UpsertCalls   []struct {
		ProviderID     string
		ModelName      string
		Capabilities   map[string]interface{}
		MessagesProbed bool
	}
	Models                  map[string]*repository.Model
	ModelsByProviderAndName map[string]*repository.Model
	DeleteBatchResult       repository.ModelBatchDeleteResult
	DeleteBatchErr          error
	DeleteBatchCalls        int
	DeleteBatchTenantID     string
	DeleteBatchIDs          []string
	UpdateCapabilitiesCalls []struct {
		ModelID          string
		CapabilitiesJSON string
	}
	RecordProtocolProbeCalls []struct {
		TenantID     string
		ProviderID   string
		ModelID      string
		Capabilities map[string]interface{}
		Record       repository.ModelProtocolProbeRecord
	}
	CapabilityOverrideCalls []struct {
		TenantID, ActorUserID, ModelID, CapabilitiesJSON, Reason string
		Protocols                                                map[string]interface{}
		Clear                                                    []string
	}
}

func (m *MockModelRepository) GetByID(ctx context.Context, id string) (*repository.Model, error) {
	if m.Models == nil {
		return nil, nil
	}
	model, ok := m.Models[id]
	if !ok {
		return nil, nil
	}
	return model, nil
}

func (m *MockModelRepository) GetByName(ctx context.Context, modelName string) (*repository.Model, error) {
	return nil, nil
}

func (m *MockModelRepository) GetByProviderAndName(ctx context.Context, providerID, modelName string) (*repository.Model, error) {
	if m.ModelsByProviderAndName == nil {
		return nil, nil
	}
	return m.ModelsByProviderAndName[providerID+"::"+modelName], nil
}

func (m *MockModelRepository) List(ctx context.Context, tenantID string) ([]*repository.Model, error) {
	if m.Models == nil {
		return nil, nil
	}
	result := make([]*repository.Model, 0, len(m.Models))
	for _, model := range m.Models {
		result = append(result, model)
	}
	return result, nil
}

func (m *MockModelRepository) Create(ctx context.Context, model *repository.Model) error {
	return nil
}

func (m *MockModelRepository) Update(ctx context.Context, model *repository.Model) error {
	return nil
}

func (m *MockModelRepository) UpsertByProviderAndName(ctx context.Context, model *repository.Model) (bool, error) {
	if model.ID == "" {
		model.ID = fmt.Sprintf("model_%d", len(m.UpsertCalls)+1)
	}
	m.UpsertCalls = append(m.UpsertCalls, struct {
		ProviderID     string
		ModelName      string
		Capabilities   map[string]interface{}
		MessagesProbed bool
	}{model.ProviderID, model.ModelName, model.Capabilities, model.NativeMessagesProbed})

	if result, ok := m.UpsertResults[model.ModelName]; ok {
		return result.Created, result.Err
	}
	return true, nil
}

type successfulMessagesProber struct {
	calls []catalog.ModelProbeRequest
}

func (p *successfulMessagesProber) Probe(_ context.Context, request catalog.ModelProbeRequest) catalog.ModelProbeResult {
	p.calls = append(p.calls, request)
	return catalog.ModelProbeResult{OK: true}
}

type failedMessagesProber struct{}

func (failedMessagesProber) Probe(context.Context, catalog.ModelProbeRequest) catalog.ModelProbeResult {
	return catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorUpstream}
}

func (m *MockModelRepository) UpdatePricing(ctx context.Context, modelID string, pricingJSON string) error {
	return nil
}

func (m *MockModelRepository) UpdateCapabilities(ctx context.Context, modelID string, capabilitiesJSON string) error {
	m.UpdateCapabilitiesCalls = append(m.UpdateCapabilitiesCalls, struct {
		ModelID          string
		CapabilitiesJSON string
	}{ModelID: modelID, CapabilitiesJSON: capabilitiesJSON})
	if m.Models != nil {
		if model, ok := m.Models[modelID]; ok {
			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(capabilitiesJSON), &parsed); err != nil {
				return err
			}
			model.Capabilities = parsed
		}
	}
	return nil
}

func (m *MockModelRepository) RecordProtocolProbe(_ context.Context, tenantID, providerID, modelID string, capabilities map[string]interface{}, record repository.ModelProtocolProbeRecord) error {
	m.RecordProtocolProbeCalls = append(m.RecordProtocolProbeCalls, struct {
		TenantID     string
		ProviderID   string
		ModelID      string
		Capabilities map[string]interface{}
		Record       repository.ModelProtocolProbeRecord
	}{TenantID: tenantID, ProviderID: providerID, ModelID: modelID, Capabilities: capabilities, Record: record})
	if m.Models != nil {
		if model, ok := m.Models[modelID]; ok {
			model.Capabilities = capabilities
		}
	}
	return nil
}

func (m *MockModelRepository) UpdateCapabilitiesAndOverrides(_ context.Context, tenantID, actorUserID, modelID, capabilitiesJSON, reason string, protocols map[string]interface{}, clear []string) error {
	m.CapabilityOverrideCalls = append(m.CapabilityOverrideCalls, struct {
		TenantID, ActorUserID, ModelID, CapabilitiesJSON, Reason string
		Protocols                                                map[string]interface{}
		Clear                                                    []string
	}{tenantID, actorUserID, modelID, capabilitiesJSON, reason, protocols, clear})
	return nil
}

func TestCreateModelPersistsExplicitProtocolAsEffectiveOverride(t *testing.T) {
	providerRepo := &MockProviderRepository{Providers: map[string]*repository.Provider{
		"provider-anthropic": {ID: "provider-anthropic", TenantID: "tenant-1", ProviderType: "anthropic", BaseURL: "https://api.anthropic.com", Status: "active"},
	}}
	modelRepo := &MockModelRepository{}
	deps := &Dependencies{ProviderRepo: providerRepo, ModelRepo: modelRepo}
	body := bytes.NewBufferString(`{"provider_id":"provider-anthropic","model_name":"claude-prod","upstream_model_id":"claude-sonnet-4","protocols":["anthropic_messages"]}`)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/models", body)
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user-1", TenantID: "tenant-1"}))
	recorder := httptest.NewRecorder()
	CreateModel(deps)(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(modelRepo.CapabilityOverrideCalls) != 1 {
		t.Fatalf("explicit protocol override calls=%d", len(modelRepo.CapabilityOverrideCalls))
	}
	call := modelRepo.CapabilityOverrideCalls[0]
	if call.Protocols["anthropic_messages"] != true || call.ActorUserID != "user-1" || call.Reason == "" {
		t.Fatalf("explicit protocol override=%+v", call)
	}
}

func (m *MockModelRepository) UpdateStatus(ctx context.Context, modelID string, status string) error {
	if m.Models != nil {
		if model, ok := m.Models[modelID]; ok {
			model.Status = status
		}
	}
	return nil
}

func (m *MockModelRepository) UpdateProxyConfig(ctx context.Context, modelID string, proxyConfigJSON string) error {
	return nil
}

func (m *MockModelRepository) Delete(ctx context.Context, id string) error {
	return nil
}

func (m *MockModelRepository) DeleteBatch(ctx context.Context, tenantID string, ids []string) (repository.ModelBatchDeleteResult, error) {
	m.DeleteBatchCalls++
	m.DeleteBatchTenantID = tenantID
	m.DeleteBatchIDs = append([]string(nil), ids...)

	return m.DeleteBatchResult, m.DeleteBatchErr
}

func (m *MockModelRepository) MergeVerifiedProviderModels(
	ctx context.Context,
	tenantID, providerID, expectedCredentialID, expectedProviderConfigDigest string,
	desired []repository.VerifiedProviderModel,
) (repository.VerifiedModelSyncResult, error) {
	m.ReplaceCalls = append(m.ReplaceCalls, struct {
		TenantID                     string
		ProviderID                   string
		ExpectedCredentialID         string
		ExpectedProviderConfigDigest string
		Desired                      []repository.VerifiedProviderModel
	}{
		TenantID:                     tenantID,
		ProviderID:                   providerID,
		ExpectedCredentialID:         expectedCredentialID,
		ExpectedProviderConfigDigest: expectedProviderConfigDigest,
		Desired:                      append([]repository.VerifiedProviderModel(nil), desired...),
	})
	return m.ReplaceResult, m.ReplaceError
}

type MockCatalogClient struct {
	Models     []types.ProviderCatalogModel
	Err        error
	FetchCalls []struct {
		BaseURL string
		APIKey  string
	}
}

func (m *MockCatalogClient) FetchModels(ctx context.Context, baseURL, apiKey string) ([]types.ProviderCatalogModel, error) {
	m.FetchCalls = append(m.FetchCalls, struct {
		BaseURL string
		APIKey  string
	}{baseURL, apiKey})
	return m.Models, m.Err
}

type MockCatalogFactory struct {
	Client catalog.Client
}

func (m *MockCatalogFactory) GetClient(providerType string) (catalog.Client, error) {
	return m.Client, nil
}

func withModelRouteParam(req *http.Request, modelID string) *http.Request {
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", modelID)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
}

func withProviderRouteParam(req *http.Request, providerID string) *http.Request {
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", providerID)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx))
}

func TestSyncModelsSuccess(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_123": {
				ID:           "prov_123",
				TenantID:     "tenant_456",
				ProviderType: "openai",
				BaseURL:      "https://api.openai.com",
				Status:       "active",
			},
		},
		Credentials: map[string]*repository.ProviderCredential{
			"prov_123": {
				ID:               "cred_1",
				ProviderID:       "prov_123",
				SecretCiphertext: "test-api-key",
				Status:           "active",
			},
		},
	}

	mockModelRepo := &MockModelRepository{
		UpsertResults: map[string]UpsertResult{
			"gpt-4":         {Created: true, Err: nil},
			"gpt-3.5-turbo": {Created: false, Err: nil},
		},
		Models: map[string]*repository.Model{
			"model_stale": {ID: "model_stale", ProviderID: "prov_123", ModelName: "gpt-legacy", Status: "active"},
		},
	}

	mockCatalogClient := &MockCatalogClient{
		Models: []types.ProviderCatalogModel{
			{ID: "gpt-4", Object: "model"},
			{ID: "gpt-3.5-turbo", Object: "model"},
		},
	}

	mockCatalogFactory := &MockCatalogFactory{
		Client: mockCatalogClient,
	}

	deps := &Dependencies{
		ProviderRepo:   mockProviderRepo,
		ModelRepo:      mockModelRepo,
		CatalogFactory: mockCatalogFactory,
	}

	handler := SyncModels(deps)

	reqBody := types.SyncModelsRequest{ProviderID: "prov_123"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/admin/v1/models/sync", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp types.SyncModelsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.ProviderID != "prov_123" {
		t.Errorf("Expected provider_id='prov_123', got '%s'", resp.ProviderID)
	}
	if resp.TotalSeen != 2 {
		t.Errorf("Expected total_seen=2, got %d", resp.TotalSeen)
	}
	if resp.Created != 1 {
		t.Errorf("Expected created=1, got %d", resp.Created)
	}
	if resp.Updated != 1 {
		t.Errorf("Expected updated=1, got %d", resp.Updated)
	}
	if resp.Deactivated != 1 {
		t.Errorf("Expected deactivated=1, got %d", resp.Deactivated)
	}
	if mockModelRepo.Models["model_stale"].Status != "disabled" {
		t.Errorf("Expected stale model to be disabled, got %s", mockModelRepo.Models["model_stale"].Status)
	}

	// Verify FetchModels was called with correct params
	if len(mockCatalogClient.FetchCalls) != 1 {
		t.Errorf("Expected 1 FetchModels call, got %d", len(mockCatalogClient.FetchCalls))
	}
	if mockCatalogClient.FetchCalls[0].BaseURL != "https://api.openai.com" {
		t.Errorf("Expected baseURL='https://api.openai.com', got '%s'", mockCatalogClient.FetchCalls[0].BaseURL)
	}
	if mockCatalogClient.FetchCalls[0].APIKey != "test-api-key" {
		t.Errorf("Expected APIKey='test-api-key', got '%s'", mockCatalogClient.FetchCalls[0].APIKey)
	}
}

func TestSyncModelsKeepsAliasedModelActiveByUpstreamID(t *testing.T) {
	prober := &createModelProbeStub{results: map[string]catalog.ModelProbeResult{
		"chat_completions": {OK: true},
		"responses":        {OK: true},
	}}
	providerRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_123": {ID: "prov_123", TenantID: "tenant_456", ProviderType: "newapi", BaseURL: "https://relay.example", Status: "active"},
		},
		Credentials: map[string]*repository.ProviderCredential{
			"prov_123": {ID: "cred_1", ProviderID: "prov_123", SecretCiphertext: "test-api-key", Status: "active"},
		},
	}
	modelRepo := &MockModelRepository{
		UpsertResults: map[string]UpsertResult{"GPT 5.6 Sol": {Created: false}},
		Models: map[string]*repository.Model{
			"model_alias": {
				ID: "model_alias", ProviderID: "prov_123", ModelName: "GPT 5.6 Sol",
				UpstreamModelID: "gpt-5.6-sol", Status: "active",
			},
		},
	}
	deps := &Dependencies{
		ProviderRepo: providerRepo,
		ModelRepo:    modelRepo,
		ModelProber:  prober,
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{Models: []types.ProviderCatalogModel{
			{ID: "gpt-5.6-sol", Name: "GPT 5.6 Sol", Object: "model"},
		}}},
	}

	body, _ := json.Marshal(types.SyncModelsRequest{ProviderID: "prov_123"})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/models/sync", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"}))
	recorder := httptest.NewRecorder()
	SyncModels(deps)(recorder, req)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var response types.SyncModelsResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Deactivated != 0 || modelRepo.Models["model_alias"].Status != "active" {
		t.Fatalf("aliased model was incorrectly deactivated: response=%+v status=%q", response, modelRepo.Models["model_alias"].Status)
	}
	if response.Verified != 1 || response.VerificationFailed != 0 || len(prober.calls) != 2 || len(modelRepo.RecordProtocolProbeCalls) != 1 {
		t.Fatalf("catalog model was not protocol verified: response=%+v probes=%d records=%d", response, len(prober.calls), len(modelRepo.RecordProtocolProbeCalls))
	}
	if got := prober.calls[0].DeploymentName; got != "gpt-5.6-sol" {
		t.Fatalf("probe used display name instead of upstream model id: %q", got)
	}
}

func TestSyncModelsProbesClaudeMessagesAndMarksOnlySuccessfulProof(t *testing.T) {
	prober := &successfulMessagesProber{}
	modelRepo := &MockModelRepository{UpsertResults: map[string]UpsertResult{"claude-opus-4-8": {Created: true}}}
	deps := &Dependencies{
		ProviderRepo: &MockProviderRepository{
			Providers:   map[string]*repository.Provider{"prov_claude": {ID: "prov_claude", TenantID: "tenant_456", ProviderType: "custom", BaseURL: "https://relay.example.test/v1", AuthMode: "bearer", Status: "active"}},
			Credentials: map[string]*repository.ProviderCredential{"prov_claude": {ID: "cred_1", ProviderID: "prov_claude", SecretCiphertext: "test-api-key", Status: "active"}},
		},
		ModelRepo: modelRepo,
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{Models: []types.ProviderCatalogModel{
			{ID: "claude-opus-4-8", Object: "model"}, {ID: "gpt-5", Object: "model"},
		}}},
		ModelProber: prober,
	}
	body, _ := json.Marshal(types.SyncModelsRequest{ProviderID: "prov_claude"})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/models/sync", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"}))
	rec := httptest.NewRecorder()

	SyncModels(deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	messageProbeCalls := 0
	for _, call := range prober.calls {
		if call.Protocol != "messages" {
			continue
		}
		messageProbeCalls++
		if call.DeploymentName != "claude-opus-4-8" {
			t.Fatalf("non-Claude model received a native Messages probe: %#v", call)
		}
	}
	if messageProbeCalls == 0 {
		t.Fatalf("Claude model was not probed with native Messages: %#v", prober.calls)
	}
	if len(modelRepo.UpsertCalls) != 2 {
		t.Fatalf("upserts=%#v", modelRepo.UpsertCalls)
	}
	protocols, _ := modelRepo.UpsertCalls[0].Capabilities["protocols"].(map[string]interface{})
	if protocols["anthropic_messages"] != true {
		t.Fatalf("Claude native Messages proof was not persisted in model capabilities: %#v", modelRepo.UpsertCalls[0].Capabilities)
	}
	if !modelRepo.UpsertCalls[0].MessagesProbed {
		t.Fatalf("Claude native Messages fact must require a real probe")
	}
	otherProtocols, _ := modelRepo.UpsertCalls[1].Capabilities["protocols"].(map[string]interface{})
	if otherProtocols["anthropic_messages"] == true {
		t.Fatalf("non-Claude catalog model must not inherit Messages capability: %#v", otherProtocols)
	}
}

func TestSyncedCatalogModelCapabilitiesDoesNotTrustClaudeNameWhenProbeFails(t *testing.T) {
	capabilities, probed := syncedCatalogModelCapabilities(
		context.Background(),
		failedMessagesProber{},
		&repository.Provider{ProviderType: "custom", BaseURL: "https://relay.example.test/v1", AuthMode: "bearer"},
		"test-api-key",
		"claude-opus-4-8",
	)
	if probed {
		t.Fatal("failed native Messages probe must not create an automatic proof")
	}
	protocols, _ := capabilities["protocols"].(map[string]interface{})
	if protocols["anthropic_messages"] == true {
		t.Fatalf("failed native Messages probe must not mark capability supported: %#v", capabilities)
	}
}

func TestSyncModelsCrossTenantForbidden(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_123": {
				ID:           "prov_123",
				TenantID:     "tenant_other",
				ProviderType: "openai",
				BaseURL:      "https://api.openai.com",
				Status:       "active",
			},
		},
	}

	deps := &Dependencies{
		ProviderRepo:   mockProviderRepo,
		ModelRepo:      &MockModelRepository{},
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{}},
	}

	handler := SyncModels(deps)

	reqBody := types.SyncModelsRequest{ProviderID: "prov_123"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/admin/v1/models/sync", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for cross-tenant, got %d", w.Code)
	}
}

func TestSyncModelsProviderNotFound(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{},
	}

	deps := &Dependencies{
		ProviderRepo:   mockProviderRepo,
		ModelRepo:      &MockModelRepository{},
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{}},
	}

	handler := SyncModels(deps)

	reqBody := types.SyncModelsRequest{ProviderID: "prov_nonexistent"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/admin/v1/models/sync", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403 for provider not found, got %d", w.Code)
	}
}

func TestSyncModelsMissingProviderID(t *testing.T) {
	deps := &Dependencies{
		ProviderRepo:   &MockProviderRepository{},
		ModelRepo:      &MockModelRepository{},
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{}},
	}

	handler := SyncModels(deps)

	reqBody := types.SyncModelsRequest{ProviderID: ""}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/admin/v1/models/sync", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for missing provider_id, got %d", w.Code)
	}
}

func TestSyncModelsUnsupportedProvider(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_123": {
				ID:           "prov_123",
				TenantID:     "tenant_456",
				ProviderType: "anthropic",
				BaseURL:      "https://api.anthropic.com",
				Status:       "active",
			},
		},
		Credentials: map[string]*repository.ProviderCredential{
			"prov_123": {
				ID:               "cred_1",
				ProviderID:       "prov_123",
				SecretCiphertext: "test-api-key",
				Status:           "active",
			},
		},
	}

	mockCatalogClient := &MockCatalogClient{
		Err: catalog.ErrProviderUnsupported,
	}

	mockCatalogFactory := &MockCatalogFactory{
		Client: mockCatalogClient,
	}

	deps := &Dependencies{
		ProviderRepo:   mockProviderRepo,
		ModelRepo:      &MockModelRepository{},
		CatalogFactory: mockCatalogFactory,
	}

	handler := SyncModels(deps)

	reqBody := types.SyncModelsRequest{ProviderID: "prov_123"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/admin/v1/models/sync", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for unsupported provider, got %d", w.Code)
	}

	respBody := w.Body.String()
	if !bytes.Contains([]byte(respBody), []byte("provider_unsupported")) {
		t.Errorf("Expected error code 'provider_unsupported', got: %s", respBody)
	}
}

func TestSyncModelsUpstreamFailure(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_123": {
				ID:           "prov_123",
				TenantID:     "tenant_456",
				ProviderType: "openai",
				BaseURL:      "https://api.openai.com",
				Status:       "active",
			},
		},
		Credentials: map[string]*repository.ProviderCredential{
			"prov_123": {
				ID:               "cred_1",
				ProviderID:       "prov_123",
				SecretCiphertext: "test-api-key",
				Status:           "active",
			},
		},
	}

	mockCatalogClient := &MockCatalogClient{
		Err: fmt.Errorf("network error"),
	}

	mockCatalogFactory := &MockCatalogFactory{
		Client: mockCatalogClient,
	}

	deps := &Dependencies{
		ProviderRepo:   mockProviderRepo,
		ModelRepo:      &MockModelRepository{},
		CatalogFactory: mockCatalogFactory,
	}

	handler := SyncModels(deps)

	reqBody := types.SyncModelsRequest{ProviderID: "prov_123"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/admin/v1/models/sync", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusBadGateway {
		t.Errorf("Expected status 502 for upstream failure, got %d", w.Code)
	}

	respBody := w.Body.String()
	if !bytes.Contains([]byte(respBody), []byte("catalog_unavailable")) {
		t.Errorf("Expected error code 'catalog_unavailable', got: %s", respBody)
	}
}

func TestSyncModelsNoCredentials(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_123": {
				ID:           "prov_123",
				TenantID:     "tenant_456",
				ProviderType: "openai",
				BaseURL:      "https://api.openai.com",
				Status:       "active",
			},
		},
		Credentials: map[string]*repository.ProviderCredential{},
	}

	deps := &Dependencies{
		ProviderRepo:   mockProviderRepo,
		ModelRepo:      &MockModelRepository{},
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{}},
	}

	handler := SyncModels(deps)

	reqBody := types.SyncModelsRequest{ProviderID: "prov_123"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/admin/v1/models/sync", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400 for no credentials, got %d", w.Code)
	}
}

func TestSyncModelsRejectsDisabledProvider(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_123": {ID: "prov_123", TenantID: "tenant_456", ProviderType: "openai", BaseURL: "https://api.openai.com/v1", Status: "disabled"},
		},
		Credentials: map[string]*repository.ProviderCredential{
			"prov_123": {ProviderID: "prov_123", SecretCiphertext: "legacy-plain-text-secret", Status: "active"},
		},
	}
	mockModelRepo := &MockModelRepository{Models: map[string]*repository.Model{}}
	mockFactory := &MockCatalogFactory{Client: &MockCatalogClient{}}
	deps := &Dependencies{
		ProviderRepo:   mockProviderRepo,
		ModelRepo:      mockModelRepo,
		CatalogFactory: mockFactory,
		SystemRepo:     &MockSystemRepo{},
	}

	handler := SyncModels(deps)
	reqBody := types.SyncModelsRequest{ProviderID: "prov_123"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/admin/v1/models/sync", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400 for disabled provider, got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("provider must be active to sync models")) {
		t.Fatalf("Expected disabled provider error, got: %s", w.Body.String())
	}
}

func TestSyncModelsSkipsNonModelObjects(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_123": {
				ID:           "prov_123",
				TenantID:     "tenant_456",
				ProviderType: "openai",
				BaseURL:      "https://api.openai.com",
				Status:       "active",
			},
		},
		Credentials: map[string]*repository.ProviderCredential{
			"prov_123": {
				ID:               "cred_1",
				ProviderID:       "prov_123",
				SecretCiphertext: "test-api-key",
				Status:           "active",
			},
		},
	}

	mockModelRepo := &MockModelRepository{
		UpsertResults: map[string]UpsertResult{
			"gpt-4": {Created: true, Err: nil},
		},
	}

	mockCatalogClient := &MockCatalogClient{
		Models: []types.ProviderCatalogModel{
			{ID: "gpt-4", Object: "model"},
			{ID: "organization", Object: "organization"},
			{ID: "file", Object: "file"},
		},
	}

	mockCatalogFactory := &MockCatalogFactory{
		Client: mockCatalogClient,
	}

	deps := &Dependencies{
		ProviderRepo:   mockProviderRepo,
		ModelRepo:      mockModelRepo,
		CatalogFactory: mockCatalogFactory,
	}

	handler := SyncModels(deps)

	reqBody := types.SyncModelsRequest{ProviderID: "prov_123"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/admin/v1/models/sync", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp types.SyncModelsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.TotalSeen != 3 {
		t.Errorf("Expected total_seen=3, got %d", resp.TotalSeen)
	}
	if resp.Created != 1 {
		t.Errorf("Expected created=1, got %d", resp.Created)
	}
	if resp.Skipped != 2 {
		t.Errorf("Expected skipped=2 (non-model objects), got %d", resp.Skipped)
	}
}

func TestSyncModelsUpsertErrorSkipped(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_123": {
				ID:           "prov_123",
				TenantID:     "tenant_456",
				ProviderType: "openai",
				BaseURL:      "https://api.openai.com",
				Status:       "active",
			},
		},
		Credentials: map[string]*repository.ProviderCredential{
			"prov_123": {
				ID:               "cred_1",
				ProviderID:       "prov_123",
				SecretCiphertext: "test-api-key",
				Status:           "active",
			},
		},
	}

	mockModelRepo := &MockModelRepository{
		UpsertResults: map[string]UpsertResult{
			"gpt-4":         {Created: true, Err: nil},
			"gpt-3.5-turbo": {Created: false, Err: fmt.Errorf("db error")},
		},
	}

	mockCatalogClient := &MockCatalogClient{
		Models: []types.ProviderCatalogModel{
			{ID: "gpt-4", Object: "model"},
			{ID: "gpt-3.5-turbo", Object: "model"},
		},
	}

	mockCatalogFactory := &MockCatalogFactory{
		Client: mockCatalogClient,
	}

	deps := &Dependencies{
		ProviderRepo:   mockProviderRepo,
		ModelRepo:      mockModelRepo,
		CatalogFactory: mockCatalogFactory,
	}

	handler := SyncModels(deps)

	reqBody := types.SyncModelsRequest{ProviderID: "prov_123"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("POST", "/admin/v1/models/sync", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp types.SyncModelsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to parse response: %v", err)
	}

	if resp.Created != 1 {
		t.Errorf("Expected created=1, got %d", resp.Created)
	}
	if resp.Skipped != 1 {
		t.Errorf("Expected skipped=1 (upsert error), got %d", resp.Skipped)
	}
}

func TestUpdateModelRoutingSuccessSetFallbackProvider(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_primary":  {ID: "prov_primary", TenantID: "tenant_456", Status: "active", HasCredential: true},
			"prov_fallback": {ID: "prov_fallback", TenantID: "tenant_456", Status: "active", HasCredential: true},
		},
	}
	mockModelRepo := &MockModelRepository{
		Models: map[string]*repository.Model{
			"model_123": {ID: "model_123", ProviderID: "prov_primary", ModelName: "deepseek-chat", Capabilities: map[string]interface{}{}},
		},
		ModelsByProviderAndName: map[string]*repository.Model{
			"prov_fallback::deepseek-chat": {ID: "model_fb", ProviderID: "prov_fallback", ModelName: "deepseek-chat", Status: "active"},
		},
	}
	deps := &Dependencies{ProviderRepo: mockProviderRepo, ModelRepo: mockModelRepo, SystemRepo: &MockSystemRepo{}}

	handler := UpdateModelRouting(deps)
	reqBody := types.UpdateModelRoutingRequest{FallbackProviderID: "prov_fallback"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("PATCH", "/admin/v1/models/model_123/routing", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = withModelRouteParam(httpReq, "model_123")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(mockModelRepo.UpdateCapabilitiesCalls) != 1 {
		t.Fatalf("Expected one UpdateCapabilities call, got %d", len(mockModelRepo.UpdateCapabilitiesCalls))
	}
	routing, ok := mockModelRepo.Models["model_123"].Capabilities["routing"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected routing capabilities to be present")
	}
	if routing["fallback_provider_id"] != "prov_fallback" {
		t.Fatalf("Expected fallback_provider_id=prov_fallback, got %v", routing["fallback_provider_id"])
	}
}

func TestUpdateModelRoutingSuccessClearFallbackProvider(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_primary": {ID: "prov_primary", TenantID: "tenant_456", Status: "active"},
		},
	}
	mockModelRepo := &MockModelRepository{
		Models: map[string]*repository.Model{
			"model_123": {
				ID:         "model_123",
				ProviderID: "prov_primary",
				ModelName:  "deepseek-chat",
				Capabilities: map[string]interface{}{
					"routing": map[string]interface{}{"fallback_provider_id": "prov_old"},
				},
			},
		},
	}
	deps := &Dependencies{ProviderRepo: mockProviderRepo, ModelRepo: mockModelRepo, SystemRepo: &MockSystemRepo{}}

	handler := UpdateModelRouting(deps)
	reqBody := types.UpdateModelRoutingRequest{FallbackProviderID: ""}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("PATCH", "/admin/v1/models/model_123/routing", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = withModelRouteParam(httpReq, "model_123")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	if _, ok := mockModelRepo.Models["model_123"].Capabilities["routing"]; ok {
		t.Fatalf("Expected routing block to be removed when clearing fallback provider")
	}
}

func TestUpdateModelRoutingRejectsSameAsPrimary(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_primary": {ID: "prov_primary", TenantID: "tenant_456", Status: "active"},
		},
	}
	mockModelRepo := &MockModelRepository{
		Models: map[string]*repository.Model{
			"model_123": {ID: "model_123", ProviderID: "prov_primary", ModelName: "deepseek-chat"},
		},
	}
	deps := &Dependencies{ProviderRepo: mockProviderRepo, ModelRepo: mockModelRepo, SystemRepo: &MockSystemRepo{}}

	handler := UpdateModelRouting(deps)
	reqBody := types.UpdateModelRoutingRequest{FallbackProviderID: "prov_primary"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("PATCH", "/admin/v1/models/model_123/routing", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = withModelRouteParam(httpReq, "model_123")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
	if len(mockModelRepo.UpdateCapabilitiesCalls) != 0 {
		t.Fatalf("Did not expect UpdateCapabilities to be called")
	}
}

func TestUpdateModelRoutingRejectsFallbackProviderNotFoundOrCrossTenant(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_primary":      {ID: "prov_primary", TenantID: "tenant_456", Status: "active"},
			"prov_other_tenant": {ID: "prov_other_tenant", TenantID: "tenant_other", Status: "active"},
		},
	}
	mockModelRepo := &MockModelRepository{
		Models: map[string]*repository.Model{
			"model_123": {ID: "model_123", ProviderID: "prov_primary", ModelName: "deepseek-chat"},
		},
	}
	deps := &Dependencies{ProviderRepo: mockProviderRepo, ModelRepo: mockModelRepo, SystemRepo: &MockSystemRepo{}}

	for _, providerID := range []string{"prov_missing", "prov_other_tenant"} {
		handler := UpdateModelRouting(deps)
		reqBody := types.UpdateModelRoutingRequest{FallbackProviderID: providerID}
		body, _ := json.Marshal(reqBody)

		httpReq := httptest.NewRequest("PATCH", "/admin/v1/models/model_123/routing", bytes.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq = withModelRouteParam(httpReq, "model_123")
		ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"})
		httpReq = httpReq.WithContext(ctx)

		w := httptest.NewRecorder()
		handler(w, httpReq)

		// Handler returns 400 with not_found code for missing/cross-tenant fallback provider.
		if w.Code != http.StatusBadRequest {
			t.Fatalf("Expected status 400 for fallback provider %s, got %d: %s", providerID, w.Code, w.Body.String())
		}
		if !bytes.Contains(w.Body.Bytes(), []byte("fallback provider not found")) {
			t.Fatalf("Expected 'fallback provider not found' error for %s, got: %s", providerID, w.Body.String())
		}
	}
}

func TestUpdateModelRoutingRejectsInactiveFallbackProvider(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_primary":  {ID: "prov_primary", TenantID: "tenant_456", Status: "active"},
			"prov_inactive": {ID: "prov_inactive", TenantID: "tenant_456", Status: "disabled"},
		},
	}
	mockModelRepo := &MockModelRepository{
		Models: map[string]*repository.Model{
			"model_123": {ID: "model_123", ProviderID: "prov_primary", ModelName: "deepseek-chat"},
		},
	}
	deps := &Dependencies{ProviderRepo: mockProviderRepo, ModelRepo: mockModelRepo, SystemRepo: &MockSystemRepo{}}

	handler := UpdateModelRouting(deps)
	reqBody := types.UpdateModelRoutingRequest{FallbackProviderID: "prov_inactive"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("PATCH", "/admin/v1/models/model_123/routing", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = withModelRouteParam(httpReq, "model_123")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
	if len(mockModelRepo.UpdateCapabilitiesCalls) != 0 {
		t.Fatalf("Did not expect UpdateCapabilities to be called")
	}
}

func TestUpdateModelRoutingRejectsFallbackProviderWithoutCredential(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_primary":       {ID: "prov_primary", TenantID: "tenant_456", Status: "active", HasCredential: true},
			"prov_no_credential": {ID: "prov_no_credential", TenantID: "tenant_456", Status: "active", HasCredential: false},
		},
	}
	mockModelRepo := &MockModelRepository{
		Models: map[string]*repository.Model{
			"model_123": {ID: "model_123", ProviderID: "prov_primary", ModelName: "deepseek-chat"},
		},
	}
	deps := &Dependencies{ProviderRepo: mockProviderRepo, ModelRepo: mockModelRepo, SystemRepo: &MockSystemRepo{}}

	handler := UpdateModelRouting(deps)
	reqBody := types.UpdateModelRoutingRequest{FallbackProviderID: "prov_no_credential"}
	body, _ := json.Marshal(reqBody)

	httpReq := httptest.NewRequest("PATCH", "/admin/v1/models/model_123/routing", bytes.NewReader(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq = withModelRouteParam(httpReq, "model_123")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("fallback provider must have active credentials")) {
		t.Fatalf("Expected missing credential error, got: %s", w.Body.String())
	}
	if len(mockModelRepo.UpdateCapabilitiesCalls) != 0 {
		t.Fatalf("Did not expect UpdateCapabilities to be called")
	}
}

func TestUpdateModelRoutingRejectsFallbackProviderWithoutSameActiveModel(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_primary":  {ID: "prov_primary", TenantID: "tenant_456", Status: "active", HasCredential: true},
			"prov_fallback": {ID: "prov_fallback", TenantID: "tenant_456", Status: "active", HasCredential: true},
		},
	}

	t.Run("missing same model", func(t *testing.T) {
		mockModelRepo := &MockModelRepository{
			Models: map[string]*repository.Model{
				"model_123": {ID: "model_123", ProviderID: "prov_primary", ModelName: "deepseek-chat"},
			},
		}
		deps := &Dependencies{ProviderRepo: mockProviderRepo, ModelRepo: mockModelRepo, SystemRepo: &MockSystemRepo{}}

		handler := UpdateModelRouting(deps)
		reqBody := types.UpdateModelRoutingRequest{FallbackProviderID: "prov_fallback"}
		body, _ := json.Marshal(reqBody)

		httpReq := httptest.NewRequest("PATCH", "/admin/v1/models/model_123/routing", bytes.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq = withModelRouteParam(httpReq, "model_123")
		ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"})
		httpReq = httpReq.WithContext(ctx)

		w := httptest.NewRecorder()
		handler(w, httpReq)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d: %s", w.Code, w.Body.String())
		}
		if !bytes.Contains(w.Body.Bytes(), []byte("fallback provider must have the same active model configured")) {
			t.Fatalf("Expected same active model error, got: %s", w.Body.String())
		}
	})

	t.Run("same model disabled", func(t *testing.T) {
		mockModelRepo := &MockModelRepository{
			Models: map[string]*repository.Model{
				"model_123": {ID: "model_123", ProviderID: "prov_primary", ModelName: "deepseek-chat"},
			},
			ModelsByProviderAndName: map[string]*repository.Model{
				"prov_fallback::deepseek-chat": {ID: "model_fb", ProviderID: "prov_fallback", ModelName: "deepseek-chat", Status: "disabled"},
			},
		}
		deps := &Dependencies{ProviderRepo: mockProviderRepo, ModelRepo: mockModelRepo, SystemRepo: &MockSystemRepo{}}

		handler := UpdateModelRouting(deps)
		reqBody := types.UpdateModelRoutingRequest{FallbackProviderID: "prov_fallback"}
		body, _ := json.Marshal(reqBody)

		httpReq := httptest.NewRequest("PATCH", "/admin/v1/models/model_123/routing", bytes.NewReader(body))
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq = withModelRouteParam(httpReq, "model_123")
		ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"})
		httpReq = httpReq.WithContext(ctx)

		w := httptest.NewRecorder()
		handler(w, httpReq)

		if w.Code != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d: %s", w.Code, w.Body.String())
		}
		if !bytes.Contains(w.Body.Bytes(), []byte("fallback provider must have the same active model configured")) {
			t.Fatalf("Expected same active model error, got: %s", w.Body.String())
		}
	})
}

func TestGetProviderCredentialHistorySuccess(t *testing.T) {
	rotatedAt := nowPtr()
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"prov_123": {ID: "prov_123", TenantID: "tenant_456", Status: "active"},
		},
		CredentialHistory: map[string][]*repository.ProviderCredential{
			"prov_123": {
				{ID: "cred_new", ProviderID: "prov_123", CredentialName: "updated", Status: "active", CreatedAt: mustTime("2026-05-04T10:00:00Z")},
				{ID: "cred_old", ProviderID: "prov_123", CredentialName: "default", Status: "rotated", RotatedAt: rotatedAt, CreatedAt: mustTime("2026-05-03T10:00:00Z")},
			},
		},
	}
	deps := &Dependencies{ProviderRepo: mockProviderRepo, SystemRepo: &MockSystemRepo{}}

	handler := GetProviderCredentialHistory(deps)
	httpReq := httptest.NewRequest("GET", "/admin/v1/providers/prov_123/credentials/history", nil)
	httpReq = withProviderRouteParam(httpReq, "prov_123")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp types.ProviderCredentialHistoryResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Total != 2 || len(resp.Data) != 2 {
		t.Fatalf("Expected 2 history items, got total=%d len=%d", resp.Total, len(resp.Data))
	}
	if resp.Data[0].ID != "cred_new" || resp.Data[0].Status != "active" {
		t.Fatalf("Unexpected newest credential entry: %#v", resp.Data[0])
	}
	if resp.Data[1].ID != "cred_old" || resp.Data[1].RotatedAt == "" {
		t.Fatalf("Expected rotated credential with rotated_at, got %#v", resp.Data[1])
	}
}

func TestGetProviderCredentialHistoryNotFound(t *testing.T) {
	mockProviderRepo := &MockProviderRepository{
		Providers: map[string]*repository.Provider{},
	}
	deps := &Dependencies{ProviderRepo: mockProviderRepo, SystemRepo: &MockSystemRepo{}}

	handler := GetProviderCredentialHistory(deps)
	httpReq := httptest.NewRequest("GET", "/admin/v1/providers/prov_missing/credentials/history", nil)
	httpReq = withProviderRouteParam(httpReq, "prov_missing")
	ctx := context.WithValue(httpReq.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"})
	httpReq = httpReq.WithContext(ctx)

	w := httptest.NewRecorder()
	handler(w, httpReq)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("provider not found")) {
		t.Fatalf("Expected provider not found error, got: %s", w.Body.String())
	}
}

func mustTime(value string) time.Time {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		panic(err)
	}
	return t
}

func nowPtr() *time.Time {
	t := mustTime("2026-05-03T12:00:00Z")
	return &t
}

type azureSyncProviderRepo struct {
	provider             *repository.Provider
	credentialFetchCalls int
}

func (r *azureSyncProviderRepo) GetByID(_ context.Context, tenantID, providerID string) (*repository.Provider, error) {
	if r.provider != nil && r.provider.TenantID == tenantID && r.provider.ID == providerID {
		return r.provider, nil
	}
	return nil, nil
}

func (r *azureSyncProviderRepo) GetCredential(context.Context, string) (*repository.ProviderCredential, error) {
	r.credentialFetchCalls++
	return nil, fmt.Errorf("credential fetch must not be called")
}

func (r *azureSyncProviderRepo) ListCredentialHistory(context.Context, string) ([]*repository.ProviderCredential, error) {
	return nil, nil
}
func (r *azureSyncProviderRepo) List(context.Context, string) ([]*repository.Provider, error) {
	return nil, nil
}
func (r *azureSyncProviderRepo) CreateWithCredential(context.Context, *repository.Provider, *repository.ProviderCredential) error {
	return nil
}
func (r *azureSyncProviderRepo) UpdateWithCredential(context.Context, *repository.Provider, *repository.ProviderCredential) error {
	return nil
}
func (r *azureSyncProviderRepo) Delete(context.Context, string, string) error { return nil }
func (r *azureSyncProviderRepo) RecentProviderMetrics(context.Context, string, int) (map[string]repository.ProviderRecentMetrics, error) {
	return map[string]repository.ProviderRecentMetrics{}, nil
}

type azureSyncModelRepo struct{ writeCalls int }

func (r *azureSyncModelRepo) GetByID(context.Context, string) (*repository.Model, error) {
	return nil, nil
}
func (r *azureSyncModelRepo) GetByProviderAndName(context.Context, string, string) (*repository.Model, error) {
	return nil, nil
}
func (r *azureSyncModelRepo) UpsertByProviderAndName(context.Context, *repository.Model) (bool, error) {
	r.writeCalls++
	return false, fmt.Errorf("model upsert must not be called")
}
func (r *azureSyncModelRepo) List(context.Context, string) ([]*repository.Model, error) {
	return nil, nil
}
func (r *azureSyncModelRepo) UpdatePricing(context.Context, string, string) error {
	r.writeCalls++
	return fmt.Errorf("model pricing update must not be called")
}
func (r *azureSyncModelRepo) UpdateCapabilities(context.Context, string, string) error {
	r.writeCalls++
	return fmt.Errorf("model capabilities update must not be called")
}
func (r *azureSyncModelRepo) RecordProtocolProbe(context.Context, string, string, string, map[string]interface{}, repository.ModelProtocolProbeRecord) error {
	r.writeCalls++
	return fmt.Errorf("model protocol probe record must not be called")
}
func (r *azureSyncModelRepo) UpdateStatus(context.Context, string, string) error {
	r.writeCalls++
	return fmt.Errorf("model status update must not be called")
}
func (r *azureSyncModelRepo) UpdateProxyConfig(context.Context, string, string) error {
	r.writeCalls++
	return fmt.Errorf("model proxy config update must not be called")
}
func (r *azureSyncModelRepo) Delete(context.Context, string) error {
	r.writeCalls++
	return fmt.Errorf("model delete must not be called")
}
func (r *azureSyncModelRepo) DeleteBatch(context.Context, string, []string) (repository.ModelBatchDeleteResult, error) {
	r.writeCalls++
	return repository.ModelBatchDeleteResult{}, fmt.Errorf("model batch delete must not be called")
}

func (r *azureSyncModelRepo) MergeVerifiedProviderModels(context.Context, string, string, string, string, []repository.VerifiedProviderModel) (repository.VerifiedModelSyncResult, error) {
	r.writeCalls++
	return repository.VerifiedModelSyncResult{}, fmt.Errorf("verified model replacement must not be called")
}

type azureSyncCatalogFactory struct{ getClientCalls int }

func (f *azureSyncCatalogFactory) GetClient(string) (catalog.Client, error) {
	f.getClientCalls++
	return nil, fmt.Errorf("catalog factory must not be called")
}

func TestSyncModelsAzureRequiresVerifiedSelection(t *testing.T) {
	providerRepo := &azureSyncProviderRepo{provider: &repository.Provider{
		ID: "provider_azure", TenantID: "tenant_456", ProviderType: "azure",
		BaseURL: "https://example.openai.azure.com", Status: "active",
	}}
	modelRepo := &azureSyncModelRepo{}
	catalogFactory := &azureSyncCatalogFactory{}
	handler := SyncModels(&Dependencies{ProviderRepo: providerRepo, ModelRepo: modelRepo, CatalogFactory: catalogFactory})

	body, err := json.Marshal(types.SyncModelsRequest{ProviderID: "provider_azure"})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/models/sync", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user_1", TenantID: "tenant_456"}))
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", w.Code, http.StatusConflict, w.Body.String())
	}
	var response struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if response.Error.Code != "selection_required" {
		t.Fatalf("error code = %q, want selection_required", response.Error.Code)
	}
	if providerRepo.credentialFetchCalls != 0 {
		t.Fatalf("credential fetch calls = %d, want 0", providerRepo.credentialFetchCalls)
	}
	if catalogFactory.getClientCalls != 0 {
		t.Fatalf("catalog factory calls = %d, want 0", catalogFactory.getClientCalls)
	}
	if modelRepo.writeCalls != 0 {
		t.Fatalf("model repository write calls = %d, want 0", modelRepo.writeCalls)
	}
}
