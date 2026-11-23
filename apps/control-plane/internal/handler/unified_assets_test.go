package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type fakeUnifiedAssetRepo struct {
	tenant, assetID, actor                       string
	ownership                                    repository.AgentAssetOwnershipUpdate
	catalog                                      repository.AgentAssetCatalogUpdate
	source                                       repository.AgentAssetSourceRef
	mergeSource, mergeTarget                     string
	lookupSourceID, lookupRefHash, lookupAssetID string
	lookupFound                                  bool
	assetFilter                                  repository.AgentUnifiedAssetFilter
	calls                                        int
	updated, merged                              bool
	err                                          error
}

func (f *fakeUnifiedAssetRepo) List(_ context.Context, tenant string, filter repository.AgentUnifiedAssetFilter) (*repository.AgentUnifiedAssetPage, error) {
	f.tenant, f.assetFilter = tenant, filter
	return &repository.AgentUnifiedAssetPage{}, nil
}

func (f *fakeUnifiedAssetRepo) ListHistory(_ context.Context, tenant, assetID string, _, _ int) (*repository.AgentUnifiedAssetHistoryPage, bool, error) {
	f.tenant, f.assetID = tenant, assetID
	return &repository.AgentUnifiedAssetHistoryPage{}, true, nil
}

func (f *fakeUnifiedAssetRepo) FindNativeReferenceAsset(_ context.Context, tenant, sourceID, refHash string) (string, bool, error) {
	f.tenant, f.lookupSourceID, f.lookupRefHash = tenant, sourceID, refHash
	f.calls++
	return f.lookupAssetID, f.lookupFound, f.err
}

func (f *fakeUnifiedAssetRepo) UpdateOwnership(_ context.Context, tenant, assetID string, input repository.AgentAssetOwnershipUpdate) (bool, error) {
	f.tenant, f.assetID, f.ownership = tenant, assetID, input
	f.calls++
	return f.updated, f.err
}

func (f *fakeUnifiedAssetRepo) UpdateCatalog(_ context.Context, tenant, assetID, actor string, input repository.AgentAssetCatalogUpdate) (bool, error) {
	f.tenant, f.assetID, f.actor, f.catalog = tenant, assetID, actor, input
	f.calls++
	return f.updated, f.err
}

func (f *fakeUnifiedAssetRepo) LinkSource(_ context.Context, tenant, assetID, actor string, input repository.AgentAssetSourceRef) error {
	f.tenant, f.assetID, f.actor, f.source = tenant, assetID, actor, input
	f.calls++
	return f.err
}

func (f *fakeUnifiedAssetRepo) Merge(_ context.Context, tenant, source, target string) (bool, error) {
	f.tenant, f.mergeSource, f.mergeTarget = tenant, source, target
	f.calls++
	return f.merged, f.err
}

func TestUnifiedAssetWritesUseAuthenticatedTenantAndStrictBodies(t *testing.T) {
	repo := &fakeUnifiedAssetRepo{updated: true}
	api := NewAgentUnifiedAssetAPI(repo, &Dependencies{})
	router := chi.NewRouter()
	router.Put("/admin/v1/agent/unified-assets/{id}/ownership", api.UpdateOwnership)
	router.Put("/admin/v1/agent/unified-assets/{id}/catalog", api.UpdateCatalog)
	router.Put("/admin/v1/agent/unified-assets/{id}/sources", api.LinkSource)
	router.Get("/admin/v1/agent/unified-assets/native-reference-link", api.FindNativeReferenceAsset)
	router.Post("/admin/v1/agent/unified-assets/{id}/merge", api.Merge)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/ownership", "tenant_admin",
		[]byte(`{"owner_user_id":"user-a","business_unit":"security","business_service":"agent-platform","tenant_id":"tenant-b"}`)))
	if rec.Code != http.StatusBadRequest || repo.calls != 0 {
		t.Fatalf("tenant override status=%d calls=%d body=%s", rec.Code, repo.calls, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/ownership", "tenant_admin",
		[]byte(`{"owner_user_id":"user-a","business_unit":"security","business_service":"agent-platform"}`)))
	if rec.Code != http.StatusOK || repo.tenant != "tenant-a" || repo.assetID != "ua_1" ||
		repo.ownership.OwnerUserID != "user-a" || repo.ownership.BusinessUnit != "security" {
		t.Fatalf("ownership status=%d repo=%+v body=%s", rec.Code, repo, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	tooLongOwner := strings.Repeat("u", 65)
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/ownership", "tenant_admin",
		[]byte(`{"owner_user_id":"`+tooLongOwner+`","business_unit":"","business_service":""}`)))
	if rec.Code != http.StatusBadRequest || repo.calls != 1 {
		t.Fatalf("oversized owner id status=%d calls=%d body=%s", rec.Code, repo.calls, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/sources", "tenant_admin",
		[]byte(`{"source_type":"identity_event","source_namespace":"verified-producer","native_id":"asset:1","tenant_id":"tenant-b"}`)))
	if rec.Code != http.StatusBadRequest || repo.calls != 1 {
		t.Fatalf("source tenant override status=%d calls=%d body=%s", rec.Code, repo.calls, rec.Body.String())
	}
}

func TestUnifiedAssetNativeReferenceLinkUsesExactTenantScopedIdentity(t *testing.T) {
	refHash := strings.Repeat("b", 64)
	repo := &fakeUnifiedAssetRepo{lookupFound: true, lookupAssetID: "ua_exact"}
	api := NewAgentUnifiedAssetAPI(repo, &Dependencies{})
	router := chi.NewRouter()
	router.Get("/admin/v1/agent/unified-assets/native-reference-link", api.FindNativeReferenceAsset)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/unified-assets/native-reference-link?source_id=source-a&ref_hash="+refHash+"&tenant_id=tenant-b", "tenant_admin", nil))
	if rec.Code != http.StatusOK || repo.tenant != "tenant-a" || repo.lookupSourceID != "source-a" || repo.lookupRefHash != refHash || !strings.Contains(rec.Body.String(), "\"asset_id\":\"ua_exact\"") {
		t.Fatalf("native link status=%d repo=%+v body=%s", rec.Code, repo, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/unified-assets/native-reference-link?source_id=source-a&ref_hash=short", "tenant_admin", nil))
	if rec.Code != http.StatusBadRequest || repo.calls != 1 {
		t.Fatalf("short reference hash status=%d calls=%d body=%s", rec.Code, repo.calls, rec.Body.String())
	}
}

func TestUnifiedAssetCatalogExceptionRequiresReasonAndFutureExpiry(t *testing.T) {
	repo := &fakeUnifiedAssetRepo{updated: true}
	api := NewAgentUnifiedAssetAPI(repo, &Dependencies{})
	router := chi.NewRouter()
	router.Put("/admin/v1/agent/unified-assets/{id}/catalog", api.UpdateCatalog)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/catalog", "tenant_admin",
		[]byte(`{"status":"exception","reason":"","expires_at":""}`)))
	if rec.Code != http.StatusBadRequest || repo.calls != 0 {
		t.Fatalf("empty exception status=%d calls=%d body=%s", rec.Code, repo.calls, rec.Body.String())
	}

	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339)
	body := []byte(`{"status":"exception","reason":"approved for a bounded pilot","expires_at":"` + expires + `"}`)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/catalog", "tenant_admin", body))
	if rec.Code != http.StatusOK || repo.calls != 1 || repo.tenant != "tenant-a" ||
		repo.actor != "user-a" || repo.catalog.Status != "exception" || repo.catalog.ExpiresAt == nil {
		t.Fatalf("catalog status=%d repo=%+v body=%s", rec.Code, repo, rec.Body.String())
	}
}

func TestUnifiedAssetSourceLinkAndMergeConflictAreTenantScoped(t *testing.T) {
	repo := &fakeUnifiedAssetRepo{err: nil}
	api := NewAgentUnifiedAssetAPI(repo, &Dependencies{})
	router := chi.NewRouter()
	router.Put("/admin/v1/agent/unified-assets/{id}/sources", api.LinkSource)
	router.Post("/admin/v1/agent/unified-assets/{id}/merge", api.Merge)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/sources", "tenant_admin",
		[]byte(`{"source_type":"identity_event","source_namespace":"verified-producer","native_id":"asset:1"}`)))
	if rec.Code != http.StatusOK || repo.tenant != "tenant-a" || repo.assetID != "ua_1" ||
		repo.source.SourceType != "identity_event" || repo.actor != "user-a" {
		t.Fatalf("source link status=%d repo=%+v body=%s", rec.Code, repo, rec.Body.String())
	}

	repo.err = repository.ErrAgentAssetMergeConflict
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPost, "/admin/v1/agent/unified-assets/ua_1/merge", "tenant_admin",
		[]byte(`{"target_asset_id":"ua_2"}`)))
	if rec.Code != http.StatusConflict || repo.tenant != "tenant-a" || repo.mergeSource != "ua_1" || repo.mergeTarget != "ua_2" {
		t.Fatalf("merge conflict status=%d repo=%+v body=%s", rec.Code, repo, rec.Body.String())
	}
}

func TestUnifiedAssetListDoesNotAcceptTenantOverride(t *testing.T) {
	repo := &fakeUnifiedAssetRepo{}
	api := NewAgentUnifiedAssetAPI(repo, &Dependencies{})
	rec := httptest.NewRecorder()
	api.List(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/unified-assets?tenant_id=tenant-b", "tenant_admin", nil))
	if rec.Code != http.StatusOK || repo.tenant != "tenant-a" || strings.Contains(rec.Body.String(), "tenant-b") {
		t.Fatalf("tenant query affected scope: status=%d tenant=%q body=%s", rec.Code, repo.tenant, rec.Body.String())
	}
}

func TestUnifiedAssetListSupportsExactAssetDeepLinkInAuthenticatedTenant(t *testing.T) {
	repo := &fakeUnifiedAssetRepo{}
	api := NewAgentUnifiedAssetAPI(repo, &Dependencies{})
	rec := httptest.NewRecorder()
	api.List(rec, agentAdminRequest(http.MethodGet, "/admin/v1/agent/unified-assets?asset_id=ua_exact&tenant_id=tenant-b", "tenant_admin", nil))
	if rec.Code != http.StatusOK || repo.tenant != "tenant-a" || repo.assetFilter.AssetID != "ua_exact" || strings.Contains(rec.Body.String(), "tenant-b") {
		t.Fatalf("exact asset list status=%d tenant=%q filter=%+v body=%s", rec.Code, repo.tenant, repo.assetFilter, rec.Body.String())
	}
}

func TestUnifiedAssetLinkSourceAcceptsOnlyIdentityEvent(t *testing.T) {
	repo := &fakeUnifiedAssetRepo{}
	api := NewAgentUnifiedAssetAPI(repo, &Dependencies{})
	router := chi.NewRouter()
	router.Put("/admin/v1/agent/unified-assets/{id}/sources", api.LinkSource)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/sources", "tenant_admin",
		[]byte("{\"source_type\":\"identity_event\",\"source_namespace\":\"verified-producer\",\"native_id\":\"asset:42\"}")))
	if rec.Code != http.StatusOK || repo.calls != 1 || repo.source.SourceType != "identity_event" {
		t.Fatalf("identity event link status=%d calls=%d source=%+v body=%s", rec.Code, repo.calls, repo.source, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/sources", "tenant_admin",
		[]byte("{\"source_type\":\"agent_endpoint\",\"source_namespace\":\"endpoint-a\",\"native_id\":\"skill-deploy\"}")))
	if rec.Code != http.StatusBadRequest || repo.calls != 1 {
		t.Fatalf("manual endpoint link status=%d calls=%d body=%s", rec.Code, repo.calls, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, agentAdminRequest(http.MethodPut, "/admin/v1/agent/unified-assets/ua_1/sources", "tenant_admin",
		[]byte("{\"source_type\":\"agent_endpoint\",\"source_namespace\":\"endpoint-a\",\"native_id\":\"skill\\u001edeploy\"}")))
	if rec.Code != http.StatusBadRequest || repo.calls != 1 {
		t.Fatalf("encoded endpoint native-id link status=%d calls=%d body=%s", rec.Code, repo.calls, rec.Body.String())
	}
}
