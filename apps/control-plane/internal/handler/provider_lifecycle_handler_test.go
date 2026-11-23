package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type providerLifecycleHandlerRepo struct {
	ProviderRepo
	deleteErr error
	deleted   []*repository.Provider
	restored  *repository.Provider
}

func (r *providerLifecycleHandlerRepo) Delete(context.Context, string, string) error {
	return r.deleteErr
}
func (r *providerLifecycleHandlerRepo) ListDeleted(context.Context, string) ([]*repository.Provider, error) {
	return r.deleted, nil
}
func (r *providerLifecycleHandlerRepo) Restore(context.Context, string, string) (*repository.Provider, error) {
	return r.restored, nil
}

func providerLifecycleRequest(method, path string) *http.Request {
	req := httptest.NewRequest(method, path, nil)
	user := &repository.User{ID: "admin", TenantID: "tenant-a", Role: "tenant_owner"}
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
}

func TestDeleteProviderReturnsConflictAndAuditsRejection(t *testing.T) {
	audit := &modelRoutingAuditRepo{}
	repo := &providerLifecycleHandlerRepo{deleteErr: repository.ErrProviderReferencedByRoutingPolicy}
	deps := &Dependencies{ProviderRepo: repo, SystemRepo: audit}
	router := chi.NewRouter()
	router.Delete("/providers/{id}", DeleteProvider(deps))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, providerLifecycleRequest(http.MethodDelete, "/providers/provider-sensitive-id"))

	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "provider_in_use") || strings.Contains(recorder.Body.String(), "provider-sensitive-id") {
		t.Fatalf("delete conflict status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(audit.operations) != 1 || audit.operations[0].ActionType != "delete_provider_rejected" {
		t.Fatalf("rejection audit=%#v", audit.operations)
	}
}

func TestProviderRecoveryEndpointsAreSanitizedAndAudited(t *testing.T) {
	audit := &modelRoutingAuditRepo{}
	provider := &repository.Provider{ID: "provider-recover", TenantID: "tenant-a", Name: "验收上游", ProviderType: "openai", BaseURL: "https://sensitive.invalid", HasCredential: true, Status: "deleted"}
	repo := &providerLifecycleHandlerRepo{deleted: []*repository.Provider{provider}, restored: &repository.Provider{ID: provider.ID, TenantID: provider.TenantID, Name: provider.Name, ProviderType: provider.ProviderType, BaseURL: provider.BaseURL, HasCredential: true, Status: "active"}}
	deps := &Dependencies{ProviderRepo: repo, SystemRepo: audit}

	listRecorder := httptest.NewRecorder()
	ListDeletedProviders(deps)(listRecorder, providerLifecycleRequest(http.MethodGet, "/providers/deleted"))
	if listRecorder.Code != http.StatusOK || !strings.Contains(listRecorder.Body.String(), "验收上游") || strings.Contains(listRecorder.Body.String(), "sensitive.invalid") || strings.Contains(listRecorder.Body.String(), "credential_id") {
		t.Fatalf("deleted list status=%d body=%s", listRecorder.Code, listRecorder.Body.String())
	}

	router := chi.NewRouter()
	router.Post("/providers/{id}/restore", RestoreProvider(deps))
	restoreRecorder := httptest.NewRecorder()
	router.ServeHTTP(restoreRecorder, providerLifecycleRequest(http.MethodPost, "/providers/provider-recover/restore"))
	if restoreRecorder.Code != http.StatusOK || !strings.Contains(restoreRecorder.Body.String(), `"status":"active"`) || strings.Contains(restoreRecorder.Body.String(), "sensitive.invalid") {
		t.Fatalf("restore status=%d body=%s", restoreRecorder.Code, restoreRecorder.Body.String())
	}
	if len(audit.operations) != 1 || audit.operations[0].ActionType != "restore_provider" {
		t.Fatalf("restore audit=%#v", audit.operations)
	}
}
