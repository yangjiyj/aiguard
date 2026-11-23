package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

func selectionTestProvider(providerType string) *repository.Provider {
	return &repository.Provider{
		ID:           "prov_select",
		TenantID:     "tenant_456",
		Name:         "上游渠道",
		ProviderType: providerType,
		BaseURL:      "https://upstream.example.com/v1",
		AuthMode:     "api_key",
		Status:       "active",
	}
}

func selectionTestProviderRepo(provider *repository.Provider) *MockProviderRepository {
	return &MockProviderRepository{
		Providers: map[string]*repository.Provider{provider.ID: provider},
		Credentials: map[string]*repository.ProviderCredential{
			provider.ID: {
				ID:               "cred_1",
				ProviderID:       provider.ID,
				SecretCiphertext: "test-api-key",
				Status:           "active",
			},
		},
	}
}

func postSyncModels(t *testing.T, handler http.HandlerFunc, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/models/sync", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	}))
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

func decodeSyncModelsResponse(t *testing.T, w *httptest.ResponseRecorder) types.SyncModelsResponse {
	t.Helper()
	var resp types.SyncModelsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode sync response: %v (%s)", err, w.Body.String())
	}
	return resp
}

// 勾选同步必须只写入被勾选的模型；未勾选的目录模型不能进库，
// 已存在的模型也不能因为"没勾选"而被停用。
func TestSyncModelsSelectionOnlyWritesSelectedModels(t *testing.T) {
	provider := selectionTestProvider("newapi")
	modelRepo := &MockModelRepository{
		UpsertResults: map[string]UpsertResult{"gpt-4o": {Created: false}},
		Models: map[string]*repository.Model{
			"model_existing": {ID: "model_existing", ProviderID: provider.ID, ModelName: "gpt-4o", UpstreamModelID: "gpt-4o", Status: "active"},
			"model_kept":     {ID: "model_kept", ProviderID: provider.ID, ModelName: "claude-3", UpstreamModelID: "claude-3", Status: "active"},
		},
	}
	catalogClient := &MockCatalogClient{Models: []types.ProviderCatalogModel{
		{ID: "gpt-4o", Object: "model"},
		{ID: "gpt-3.5-turbo", Object: "model"},
		{ID: "claude-3", Object: "model"},
	}}
	handler := SyncModels(&Dependencies{
		ProviderRepo:   selectionTestProviderRepo(provider),
		ModelRepo:      modelRepo,
		CatalogFactory: &MockCatalogFactory{Client: catalogClient},
	})

	w := postSyncModels(t, handler, types.SyncModelsRequest{
		ProviderID:      provider.ID,
		CatalogModelIDs: []string{"gpt-4o"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	resp := decodeSyncModelsResponse(t, w)
	if !resp.SelectionApplied {
		t.Fatalf("selection_applied = false, want true")
	}
	if resp.SelectedMatched != 1 {
		t.Fatalf("selected_matched = %d, want 1", resp.SelectedMatched)
	}
	if resp.Created != 0 || resp.Updated != 1 {
		t.Fatalf("created=%d updated=%d, want 0/1", resp.Created, resp.Updated)
	}
	if len(modelRepo.UpsertCalls) != 1 || modelRepo.UpsertCalls[0].ModelName != "gpt-4o" {
		t.Fatalf("upsert calls = %+v, want only gpt-4o", modelRepo.UpsertCalls)
	}
	if resp.Deactivated != 0 {
		t.Fatalf("deactivated = %d, want 0: 勾选同步不能停用未被勾选的模型", resp.Deactivated)
	}
	if modelRepo.Models["model_kept"].Status != "active" {
		t.Fatalf("未勾选的已存在模型被改成 %q，必须保持 active", modelRepo.Models["model_kept"].Status)
	}
	if len(resp.NotFoundModelIDs) != 0 {
		t.Fatalf("not_found_model_ids = %v, want empty", resp.NotFoundModelIDs)
	}
}

// 勾选里出现上游已不存在的标识时，必须回报而不是静默忽略。
func TestSyncModelsSelectionReportsCatalogIDsMissingUpstream(t *testing.T) {
	provider := selectionTestProvider("openai")
	modelRepo := &MockModelRepository{}
	handler := SyncModels(&Dependencies{
		ProviderRepo: selectionTestProviderRepo(provider),
		ModelRepo:    modelRepo,
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{Models: []types.ProviderCatalogModel{
			{ID: "gpt-4o", Object: "model"},
		}}},
	})

	w := postSyncModels(t, handler, types.SyncModelsRequest{
		ProviderID:      provider.ID,
		CatalogModelIDs: []string{"gpt-4o", "ghost-model"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	resp := decodeSyncModelsResponse(t, w)
	if resp.SelectedMatched != 1 {
		t.Fatalf("selected_matched = %d, want 1", resp.SelectedMatched)
	}
	if len(resp.NotFoundModelIDs) != 1 || resp.NotFoundModelIDs[0] != "ghost-model" {
		t.Fatalf("not_found_model_ids = %v, want [ghost-model]", resp.NotFoundModelIDs)
	}
}

// 重复标识先去重，不能变成两次上游探测。
func TestSyncModelsSelectionDeduplicatesCatalogIDs(t *testing.T) {
	provider := selectionTestProvider("openai")
	modelRepo := &MockModelRepository{}
	handler := SyncModels(&Dependencies{
		ProviderRepo: selectionTestProviderRepo(provider),
		ModelRepo:    modelRepo,
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{Models: []types.ProviderCatalogModel{
			{ID: "gpt-4o", Object: "model"},
		}}},
	})

	w := postSyncModels(t, handler, types.SyncModelsRequest{
		ProviderID:      provider.ID,
		CatalogModelIDs: []string{"gpt-4o", " gpt-4o ", "gpt-4o"},
	})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if len(modelRepo.UpsertCalls) != 1 {
		t.Fatalf("upsert calls = %d, want 1", len(modelRepo.UpsertCalls))
	}
	resp := decodeSyncModelsResponse(t, w)
	if resp.SelectedMatched != 1 || len(resp.NotFoundModelIDs) != 0 {
		t.Fatalf("selected_matched=%d not_found=%v, want 1/empty", resp.SelectedMatched, resp.NotFoundModelIDs)
	}
}

// 越界或畸形的勾选必须在碰上游之前就被拒绝，避免把无效请求变成一次目录拉取。
func TestSyncModelsSelectionRejectsInvalidSelection(t *testing.T) {
	oversized := make([]string, 0, modelSyncMaxCatalogSelection+1)
	for i := 0; i <= modelSyncMaxCatalogSelection; i++ {
		oversized = append(oversized, fmt.Sprintf("model-%d", i))
	}
	longID := ""
	for len(longID) <= modelSyncFieldMaxRunes {
		longID += "aaaaaaaaaa"
	}

	tests := map[string][]string{
		"oversized":     oversized,
		"control_char":  {"gpt-4o\u0000evil"},
		"over_long":     {longID},
		"blank_entry":   {"gpt-4o", "   "},
		"with_space_id": {"gpt 4o"},
	}
	for name, selection := range tests {
		t.Run(name, func(t *testing.T) {
			provider := selectionTestProvider("openai")
			catalogClient := &MockCatalogClient{}
			handler := SyncModels(&Dependencies{
				ProviderRepo:   selectionTestProviderRepo(provider),
				ModelRepo:      &MockModelRepository{},
				CatalogFactory: &MockCatalogFactory{Client: catalogClient},
			})

			w := postSyncModels(t, handler, types.SyncModelsRequest{
				ProviderID:      provider.ID,
				CatalogModelIDs: selection,
			})

			if w.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
			}
			if len(catalogClient.FetchCalls) != 0 {
				t.Fatalf("catalog fetch calls = %d, want 0", len(catalogClient.FetchCalls))
			}
		})
	}
}

// 不传勾选时保持原有全量同步语义：仍然会停用上游已消失的模型。
func TestSyncModelsWithoutSelectionKeepsFullCatalogBehavior(t *testing.T) {
	provider := selectionTestProvider("openai")
	modelRepo := &MockModelRepository{
		Models: map[string]*repository.Model{
			"model_stale": {ID: "model_stale", ProviderID: provider.ID, ModelName: "gpt-legacy", UpstreamModelID: "gpt-legacy", Status: "active"},
		},
	}
	handler := SyncModels(&Dependencies{
		ProviderRepo: selectionTestProviderRepo(provider),
		ModelRepo:    modelRepo,
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{Models: []types.ProviderCatalogModel{
			{ID: "gpt-4o", Object: "model"},
		}}},
	})

	w := postSyncModels(t, handler, types.SyncModelsRequest{ProviderID: provider.ID})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	resp := decodeSyncModelsResponse(t, w)
	if resp.SelectionApplied {
		t.Fatalf("selection_applied = true, want false")
	}
	if resp.Deactivated != 1 || modelRepo.Models["model_stale"].Status != "disabled" {
		t.Fatalf("deactivated=%d status=%q, want 1/disabled", resp.Deactivated, modelRepo.Models["model_stale"].Status)
	}
}

func callCandidateList(t *testing.T, deps *Dependencies, providerID string) (*httptest.ResponseRecorder, ModelSyncCandidateListResponse) {
	t.Helper()
	payload, err := json.Marshal(ModelSyncCandidateRequest{ProviderID: providerID})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/models/sync/candidates", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{
		ID:       "user_1",
		TenantID: "tenant_456",
	}))
	w := httptest.NewRecorder()
	ListModelSyncCandidates(deps)(w, req)

	var resp ModelSyncCandidateListResponse
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode candidate response: %v (%s)", err, w.Body.String())
		}
	}
	return w, resp
}

// 通用渠道也能拿到候选目录，并带上当前纳入状态，供管理员勾选。
func TestListModelSyncCandidatesReturnsCatalogForGenericProvider(t *testing.T) {
	provider := selectionTestProvider("newapi")
	deps := &Dependencies{
		ProviderRepo: selectionTestProviderRepo(provider),
		ModelRepo: &MockModelRepository{
			Models: map[string]*repository.Model{
				"model_active":   {ID: "model_active", ProviderID: provider.ID, ModelName: "gpt-4o", UpstreamModelID: "gpt-4o", Status: "active"},
				"model_disabled": {ID: "model_disabled", ProviderID: provider.ID, ModelName: "claude-3", UpstreamModelID: "claude-3", Status: "disabled"},
			},
		},
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{Models: []types.ProviderCatalogModel{
			{ID: "gpt-4o", Name: "GPT-4o", Object: "model"},
			{ID: "claude-3", Object: "model"},
			{ID: "gemini-1.5-pro", Object: "model"},
			{ID: "other-object", Object: "not-a-model"},
		}}},
	}

	w, resp := callCandidateList(t, deps, provider.ID)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if resp.CatalogUnavailable {
		t.Fatalf("catalog_unavailable = true, want false")
	}
	if resp.CurrentActive != 1 {
		t.Fatalf("current_active = %d, want 1", resp.CurrentActive)
	}
	if len(resp.Candidates) != 3 {
		t.Fatalf("candidates = %+v, want 3 entries (非 model 对象必须被过滤)", resp.Candidates)
	}
	if resp.Candidates[0].CatalogModelID != "claude-3" || resp.Candidates[1].CatalogModelID != "gemini-1.5-pro" || resp.Candidates[2].CatalogModelID != "gpt-4o" {
		t.Fatalf("candidates must be sorted by catalog id: %+v", resp.Candidates)
	}
	if resp.Candidates[1].CurrentStatus != "" {
		t.Fatalf("未纳管的候选 current_status = %q, want empty", resp.Candidates[1].CurrentStatus)
	}
	if resp.Candidates[2].CurrentStatus != "active" {
		t.Fatalf("已纳管候选 current_status = %q, want active", resp.Candidates[2].CurrentStatus)
	}
	if resp.Candidates[0].CurrentStatus != "disabled" {
		t.Fatalf("已下架候选 current_status = %q, want disabled", resp.Candidates[0].CurrentStatus)
	}
	if resp.Candidates[2].DisplayName != "GPT-4o" {
		t.Fatalf("display_name = %q, want GPT-4o", resp.Candidates[2].DisplayName)
	}
	if resp.MaxSelection != modelSyncMaxCatalogSelection {
		t.Fatalf("max_selection = %d, want %d", resp.MaxSelection, modelSyncMaxCatalogSelection)
	}
}

// 无法拉取目录时返回可读状态，而不是 5xx，让前端能给出准确提示。
func TestListModelSyncCandidatesReportsCatalogUnavailable(t *testing.T) {
	provider := selectionTestProvider("openai")
	client := &MockCatalogClient{Err: fmt.Errorf("upstream unreachable")}
	w, resp := callCandidateList(t, &Dependencies{
		ProviderRepo:   selectionTestProviderRepo(provider),
		ModelRepo:      &MockModelRepository{},
		CatalogFactory: &MockCatalogFactory{Client: client},
	}, provider.ID)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	if !resp.CatalogUnavailable {
		t.Fatalf("catalog_unavailable = false, want true")
	}
	if len(resp.Candidates) != 0 {
		t.Fatalf("candidates = %+v, want empty", resp.Candidates)
	}
}

// 不支持目录同步的渠道不能在候选阶段就被放行。
func TestListModelSyncCandidatesRejectsIneligibleProviders(t *testing.T) {
	tests := map[string]*repository.Provider{
		"gemini": {
			ID: "prov_select", TenantID: "tenant_456", ProviderType: "gemini",
			BaseURL: "https://us-central1-aiplatform.googleapis.com", Status: "active",
		},
		"bedrock": {
			ID: "prov_select", TenantID: "tenant_456", ProviderType: "bedrock",
			BaseURL: "https://bedrock-runtime.us-east-1.amazonaws.com", Status: "active",
		},
		"complete_chat": {
			ID: "prov_select", TenantID: "tenant_456", ProviderType: "openai",
			BaseURL: "https://relay.example.com/v1", AuthMode: "authorization_raw", Status: "active",
		},
		"disabled": {
			ID: "prov_select", TenantID: "tenant_456", ProviderType: "openai",
			BaseURL: "https://api.openai.com", Status: "disabled",
		},
	}
	for name, provider := range tests {
		t.Run(name, func(t *testing.T) {
			client := &MockCatalogClient{}
			w, _ := callCandidateList(t, &Dependencies{
				ProviderRepo:   selectionTestProviderRepo(provider),
				ModelRepo:      &MockModelRepository{},
				CatalogFactory: &MockCatalogFactory{Client: client},
			}, provider.ID)

			if w.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
			}
			if len(client.FetchCalls) != 0 {
				t.Fatalf("catalog fetch calls = %d, want 0", len(client.FetchCalls))
			}
		})
	}
}

// 未认证请求不能借候选接口探测渠道或上游。
func TestListModelSyncCandidatesRequiresAuthentication(t *testing.T) {
	provider := selectionTestProvider("openai")
	client := &MockCatalogClient{}
	deps := &Dependencies{
		ProviderRepo:   selectionTestProviderRepo(provider),
		ModelRepo:      &MockModelRepository{},
		CatalogFactory: &MockCatalogFactory{Client: client},
	}
	payload, err := json.Marshal(ModelSyncCandidateRequest{ProviderID: provider.ID})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/models/sync/candidates", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	ListModelSyncCandidates(deps)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401: %s", w.Code, w.Body.String())
	}
	if len(client.FetchCalls) != 0 {
		t.Fatalf("catalog fetch calls = %d, want 0", len(client.FetchCalls))
	}
}
