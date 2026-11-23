package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/go-chi/chi/v5"
)

func TestRawChatSameURLUpdateRefreshesFactWithExactSnapshot(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "raw-chat-update-test-only")
	ciphertext, _, err := secrets.EncryptProviderSecret("Bearer synthetic-current-key")
	if err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Truncate(time.Second)
	p := &repository.Provider{ID: "provider-a", TenantID: "tenant-a", ProviderType: "openai", BaseURL: "http://10.20.30.1:28991/v1/chat/completions", AuthMode: "authorization_raw", Status: "active", UpdatedAt: before}
	c := &repository.ProviderCredential{ID: "credential-a", ProviderID: p.ID, SecretCiphertext: ciphertext, Status: "active"}
	m := &repository.Model{ID: "model-a", ProviderID: p.ID, ModelName: "actual-model", UpstreamModelID: "actual-upstream", Status: "active"}
	for _, conflict := range []bool{false, true} {
		t.Run(map[bool]string{false: "verified", true: "stale_snapshot"}[conflict], func(t *testing.T) {
			repo := &completeChatProviderRepo{MockProviderRepository: &MockProviderRepository{Providers: map[string]*repository.Provider{p.ID: p}, Credentials: map[string]*repository.ProviderCredential{p.ID: c}}}
			if conflict {
				repo.verifiedError = repository.ErrProviderProtocolProbeConflict
			}
			models := &MockModelRepository{Models: map[string]*repository.Model{m.ID: m}}
			prober := &completeChatProber{result: catalog.ModelProbeResult{OK: true, PayloadValidated: true, HTTPStatus: 200}}
			request := httptest.NewRequest(http.MethodPatch, "/admin/v1/providers/provider-a", strings.NewReader(`{"base_url":"`+p.BaseURL+`"}`))
			route := chi.NewRouteContext()
			route.URLParams.Add("id", p.ID)
			ctx := context.WithValue(request.Context(), chi.RouteCtxKey, route)
			ctx = context.WithValue(ctx, auth.UserKey, &repository.User{ID: "user-a", TenantID: p.TenantID})
			response := httptest.NewRecorder()
			UpdateProvider(&Dependencies{ProviderRepo: repo, ModelRepo: models, ModelProber: prober}).ServeHTTP(response, request.WithContext(ctx))
			want := http.StatusOK
			if conflict {
				want = http.StatusConflict
			}
			if response.Code != want || prober.calls != 1 || repo.verifiedCalls != 1 {
				t.Fatalf("status=%d probe=%d verified=%d body=%s", response.Code, prober.calls, repo.verifiedCalls, response.Body.String())
			}
			if prober.request.APIKey != "Bearer synthetic-current-key" || prober.request.DeploymentName != m.UpstreamModelID {
				t.Fatal("native snapshot probe differs")
			}
			snapshot := repo.verifiedSnapshot
			if snapshot.ModelID != m.ID || snapshot.ModelName != m.ModelName || snapshot.UpstreamModelID != m.UpstreamModelID || snapshot.CredentialID != c.ID || snapshot.SecretCiphertext != c.SecretCiphertext || !snapshot.ProviderUpdatedAt.Equal(p.UpdatedAt) {
				t.Fatalf("snapshot=%+v", snapshot)
			}
			if repo.verifiedRecord.ProviderConfigDigest != repository.VerifiedModelSyncProviderConfigDigest(p.ProviderType, p.BaseURL, p.AuthMode) || len(repo.verifiedRecord.Endpoints) != 1 || repo.verifiedRecord.Endpoints[0].EndpointType != "chat" {
				t.Fatal("raw update fact differs")
			}
			if conflict && repo.updateCalls != 0 {
				t.Fatal("stale proof mutated provider")
			}
			if repo.rotated != nil {
				t.Fatal("same URL repair rotated credential")
			}
		})
	}
}
