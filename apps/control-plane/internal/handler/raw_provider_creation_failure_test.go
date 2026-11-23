package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestRawChatCreationCancellationAndActivationFailureLeaveModelDisabled(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "complete-chat-disabled-test-only")
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "activation_failure", true: "cancelled_after_bundle"}[cancelled], func(t *testing.T) {
			repo := &completeChatProviderRepo{MockProviderRepository: &MockProviderRepository{}}
			models := &rawChatFactModels{MockModelRepository: &MockModelRepository{}, failActivation: !cancelled}
			prober := &completeChatProber{result: catalog.ModelProbeResult{OK: true, PayloadValidated: true, HTTPStatus: 200}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if cancelled {
				repo.afterCreate = cancel
			}
			ctx = context.WithValue(ctx, auth.UserKey, &repository.User{ID: "user-a", TenantID: "tenant-a"})
			body := `{"name":"native-raw","provider_type":"openai","base_url":"http://10.20.30.1:28991/v1/chat/completions","api_key":"Bearer synthetic-key","auth_mode":"authorization_raw","model_id":"actual-upstream"}`
			request := httptest.NewRequest(http.MethodPost, "/admin/v1/providers", strings.NewReader(body)).WithContext(ctx)
			response := httptest.NewRecorder()
			CreateProvider(&Dependencies{ProviderRepo: repo, ModelRepo: models, ModelProber: prober}).ServeHTTP(response, request)
			if response.Code == http.StatusOK || repo.model == nil || repo.model.Status != "disabled" {
				t.Fatalf("status=%d model=%+v", response.Code, repo.model)
			}
			if cancelled && len(models.activations) != 0 {
				t.Fatal("cancelled proof activated model")
			}
		})
	}
}
