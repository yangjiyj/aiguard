package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

func TestCreateNativeModelRequiresGenerationProofAndDoesNotInventNativeEndpoints(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "native-model-create-test-encryption")
	for _, typ := range []string{"gemini", "vertex", "bedrock"} {
		for _, validated := range []bool{false, true} {
			t.Run(typ+map[bool]string{false: "/invalid-body", true: "/verified"}[validated], func(t *testing.T) {
				cipher, _, err := secrets.EncryptProviderSecret("fixture-credential")
				if err != nil {
					t.Fatal(err)
				}
				provider := &repository.Provider{ID: "native", TenantID: "tenant-1", ProviderType: typ, BaseURL: "https://native.fixture", AuthMode: "api_key", Status: "active"}
				credential := &repository.ProviderCredential{ID: "cred-native", ProviderID: "native", SecretCiphertext: cipher, Status: "active"}
				providers := &MockProviderRepository{Providers: map[string]*repository.Provider{"native": provider}, Credentials: map[string]*repository.ProviderCredential{"native": credential}}
				models := &MockModelRepository{}
				prober := &createModelProbeStub{results: map[string]catalog.ModelProbeResult{"chat_completions": {OK: true, PayloadValidated: validated, HTTPStatus: 200}}}
				// Explicit Chat must still perform a real native probe; a checkbox is not proof.
				request := httptest.NewRequest(http.MethodPost, "/admin/v1/models", bytes.NewBufferString(`{"provider_id":"native","model_name":"native-fixture","protocols":["chat_completions"]}`))
				request = request.WithContext(context.WithValue(request.Context(), auth.UserKey, &repository.User{ID: "actor", TenantID: "tenant-1"}))
				recorder := httptest.NewRecorder()
				CreateModel(&Dependencies{ProviderRepo: providers, ModelRepo: models, ModelProber: prober})(recorder, request)
				if len(prober.calls) != 1 || prober.calls[0].ProviderType != typ || prober.calls[0].APIKey != "fixture-credential" || prober.calls[0].DeploymentName != "native-fixture" {
					t.Fatal("native dispatch lost saved identity")
				}
				if !validated {
					if recorder.Code != 502 || len(models.UpsertCalls) != 0 || len(models.RecordProtocolProbeCalls) != 0 {
						t.Fatalf("invalid response admitted model: status=%d writes=%d", recorder.Code, len(models.UpsertCalls))
					}
					return
				}
				if recorder.Code != 200 || len(models.RecordProtocolProbeCalls) != 1 || len(models.CapabilityOverrideCalls) != 0 {
					t.Fatalf("valid native model not admitted: status=%d body=%s", recorder.Code, recorder.Body.String())
				}
				record := models.RecordProtocolProbeCalls[0].Record
				if len(record.Endpoints) != 1 || record.Endpoints[0].EndpointType != "chat" || record.Endpoints[0].State != "supported" || record.CredentialID != credential.ID || record.SecretCiphertext != cipher {
					t.Fatal("native evidence lacks canonical Chat or credential binding")
				}
				protocols := models.RecordProtocolProbeCalls[0].Capabilities["protocols"].(map[string]interface{})
				if protocols["chat_completions"] != true || protocols["responses_native"] == true || protocols["anthropic_messages"] == true {
					t.Fatal("unverified native endpoint invented")
				}
			})
		}
	}
}

func TestNativeProtocolProofRejectsHTTP200WithoutValidatedBody(t *testing.T) {
	provider := &repository.Provider{ProviderType: "gemini", BaseURL: "https://fixture.test", AuthMode: "api_key"}
	for _, result := range []catalog.ModelProbeResult{{OK: true, HTTPStatus: 200}, {HTTPStatus: 401, ErrorKind: "unauthorized"}, {OK: true, PayloadValidated: true, HTTPStatus: 204}} {
		prober := &createModelProbeStub{results: map[string]catalog.ModelProbeResult{"chat_completions": result}}
		if protocols, record, err := probeNativeModelProtocols(context.Background(), prober, provider, "secret", "deployment"); err == nil || protocols != nil || len(record.Endpoints) != 0 {
			t.Fatal("unverified native model produced admission proof")
		}
	}
}

// The production implementation has a PostgreSQL transaction; this double only
// records the handler contract, while repository tests exercise atomic storage.
func (m *MockModelRepository) UpsertNativeVerifiedModel(ctx context.Context, tenant string, model *repository.Model, record repository.ModelProtocolProbeRecord, _ repository.NativeModelAdmissionSnapshot) (bool, error) {
	created, err := m.UpsertByProviderAndName(ctx, model)
	if err != nil {
		return false, err
	}
	return created, m.RecordProtocolProbe(ctx, tenant, model.ProviderID, model.ID, model.Capabilities, record)
}
