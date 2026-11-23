package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

func TestProviderSyncGateScopesAndReleasesKeys(t *testing.T) {
	var gate providerSyncGate
	if !gate.tryStart("tenant-a", "provider-a") {
		t.Fatal("first start was rejected")
	}
	if gate.tryStart("tenant-a", "provider-a") {
		t.Fatal("duplicate start was accepted")
	}
	if !gate.tryStart("tenant-a", "provider-b") {
		t.Fatal("a different provider was blocked")
	}
	if !gate.tryStart("tenant-b", "provider-a") {
		t.Fatal("a different tenant was blocked")
	}

	gate.finish("tenant-a", "provider-a")
	if !gate.tryStart("tenant-a", "provider-a") {
		t.Fatal("released key stayed blocked")
	}
}

type blockingFirstCatalogClient struct {
	mu           sync.Mutex
	calls        int
	firstEntered chan struct{}
	releaseFirst chan struct{}
	releaseOnce  sync.Once
}

func newBlockingFirstCatalogClient() *blockingFirstCatalogClient {
	return &blockingFirstCatalogClient{
		firstEntered: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
}

func (c *blockingFirstCatalogClient) FetchModels(ctx context.Context, _, _ string) ([]types.ProviderCatalogModel, error) {
	c.mu.Lock()
	c.calls++
	call := c.calls
	c.mu.Unlock()
	if call == 1 {
		close(c.firstEntered)
		select {
		case <-c.releaseFirst:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return []types.ProviderCatalogModel{}, nil
}

func (c *blockingFirstCatalogClient) release() {
	c.releaseOnce.Do(func() { close(c.releaseFirst) })
}

func (c *blockingFirstCatalogClient) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func TestSyncModelsRejectsConcurrentRequestForSameTenantProvider(t *testing.T) {
	const tenantID = "tenant-sync"
	const providerID = "provider-sync"
	catalogClient := newBlockingFirstCatalogClient()
	t.Cleanup(catalogClient.release)
	deps := &Dependencies{
		ProviderRepo: &MockProviderRepository{
			Providers: map[string]*repository.Provider{
				providerID: {
					ID: providerID, TenantID: tenantID, ProviderType: "openai",
					BaseURL: "https://api.example.test", Status: "active",
				},
			},
			Credentials: map[string]*repository.ProviderCredential{
				providerID: {ID: "credential-sync", ProviderID: providerID, SecretCiphertext: "test-api-key", Status: "active"},
			},
		},
		ModelRepo:      &MockModelRepository{},
		CatalogFactory: &MockCatalogFactory{Client: catalogClient},
	}
	handler := SyncModels(deps)

	firstRequest := newSyncModelsRequest(t, tenantID, providerID)
	firstResult := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		response := httptest.NewRecorder()
		handler(response, firstRequest)
		firstResult <- response
	}()

	select {
	case <-catalogClient.firstEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first sync did not reach the catalog client")
	}

	duplicate := httptest.NewRecorder()
	handler(duplicate, newSyncModelsRequest(t, tenantID, providerID))
	if duplicate.Code != http.StatusConflict {
		t.Fatalf("duplicate status=%d, want %d: %s", duplicate.Code, http.StatusConflict, duplicate.Body.String())
	}
	if code := responseErrorCode(t, duplicate); code != "sync_in_progress" {
		t.Fatalf("duplicate error code=%q, want sync_in_progress", code)
	}
	if calls := catalogClient.callCount(); calls != 1 {
		t.Fatalf("catalog calls while first sync is blocked=%d, want 1", calls)
	}

	catalogClient.release()
	select {
	case first := <-firstResult:
		if first.Code != http.StatusOK {
			t.Fatalf("first sync status=%d, want 200: %s", first.Code, first.Body.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first sync did not finish after release")
	}

	retry := httptest.NewRecorder()
	handler(retry, newSyncModelsRequest(t, tenantID, providerID))
	if retry.Code != http.StatusOK {
		t.Fatalf("retry status=%d, want 200: %s", retry.Code, retry.Body.String())
	}
	if calls := catalogClient.callCount(); calls != 2 {
		t.Fatalf("catalog calls after retry=%d, want 2", calls)
	}
}

func TestSyncModelsChecksTenantBeforeInProgressState(t *testing.T) {
	const providerID = "provider-other-tenant"
	deps := &Dependencies{
		ProviderRepo: &MockProviderRepository{
			Providers: map[string]*repository.Provider{
				providerID: {
					ID: providerID, TenantID: "tenant-owner", ProviderType: "openai",
					BaseURL: "https://api.example.test", Status: "active",
				},
			},
		},
		ModelRepo:      &MockModelRepository{},
		CatalogFactory: &MockCatalogFactory{Client: &MockCatalogClient{}},
	}
	if !deps.modelSyncGate.tryStart("tenant-requester", providerID) {
		t.Fatal("failed to arrange an in-progress key")
	}
	t.Cleanup(func() { deps.modelSyncGate.finish("tenant-requester", providerID) })

	response := httptest.NewRecorder()
	SyncModels(deps)(response, newSyncModelsRequest(t, "tenant-requester", providerID))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d, want %d: %s", response.Code, http.StatusForbidden, response.Body.String())
	}
	if code := responseErrorCode(t, response); code != "provider_not_found" {
		t.Fatalf("error code=%q, want provider_not_found", code)
	}
}

func newSyncModelsRequest(t *testing.T, tenantID, providerID string) *http.Request {
	t.Helper()
	body, err := json.Marshal(types.SyncModelsRequest{ProviderID: providerID})
	if err != nil {
		t.Fatalf("marshal sync request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/admin/v1/models/sync", bytes.NewReader(body))
	return request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{
		ID: "user-sync", TenantID: tenantID,
	}))
}

func responseErrorCode(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error response: %v", err)
	}
	return payload.Error.Code
}
