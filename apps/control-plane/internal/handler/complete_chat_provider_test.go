package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type completeChatProviderRepo struct {
	*MockProviderRepository
	createCalls      int
	provider         *repository.Provider
	credential       *repository.ProviderCredential
	model            *repository.Model
	updateCalls      int
	updated          *repository.Provider
	rotated          *repository.ProviderCredential
	verifiedCalls    int
	verifiedSnapshot repository.ProviderProtocolProbeSnapshot
	verifiedRecord   repository.ModelProtocolProbeRecord
	verifiedError    error
	afterCreate      func()
}

func (r *completeChatProviderRepo) UpdateWithCredentialAndProtocolProbe(ctx context.Context, provider *repository.Provider, credential *repository.ProviderCredential, snapshot repository.ProviderProtocolProbeSnapshot, capabilities map[string]interface{}, record repository.ModelProtocolProbeRecord) error {
	r.verifiedCalls++
	r.verifiedSnapshot, r.verifiedRecord = snapshot, record
	if r.verifiedError != nil {
		return r.verifiedError
	}
	return r.UpdateWithCredential(ctx, provider, credential)
}

func (r *completeChatProviderRepo) UpdateWithCredential(_ context.Context, provider *repository.Provider, credential *repository.ProviderCredential) error {
	r.updateCalls++
	r.updated, r.rotated = provider, credential
	return nil
}

func (r *completeChatProviderRepo) CreateWithCredentialAndModel(_ context.Context, provider *repository.Provider, credential *repository.ProviderCredential, model *repository.Model) error {
	r.createCalls++
	provider.ID, model.ID = "provider-native", "model-native"
	r.provider, r.credential, r.model = provider, credential, model
	if r.afterCreate != nil {
		r.afterCreate()
	}
	return nil
}

type completeChatProber struct {
	result  catalog.ModelProbeResult
	calls   int
	request catalog.ModelProbeRequest
}

func (p *completeChatProber) Probe(_ context.Context, request catalog.ModelProbeRequest) catalog.ModelProbeResult {
	p.calls++
	p.request = request
	return p.result
}

func performCompleteChatCreate(t *testing.T, body string, repo ProviderRepo, prober catalog.ModelProber, modelRepos ...ModelRepo) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/providers", bytes.NewBufferString(body))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user-a", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	var models ModelRepo = &MockModelRepository{}
	if len(modelRepos) > 0 {
		models = modelRepos[0]
	}
	CreateProvider(&Dependencies{ProviderRepo: repo, ModelRepo: models, ModelProber: prober}).ServeHTTP(rec, req)
	return rec
}

func TestCreateAuthorizationRawProviderProbesThenCreatesAtomicBundle(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "complete-chat-provider-test-key")
	repo := &completeChatProviderRepo{MockProviderRepository: &MockProviderRepository{Providers: map[string]*repository.Provider{}, Credentials: map[string]*repository.ProviderCredential{}}}
	prober := &completeChatProber{result: catalog.ModelProbeResult{OK: true, PayloadValidated: true, HTTPStatus: 200, Message: "部署探测成功"}}
	body := `{"name":"内部大模型","provider_type":"custom","base_url":"http://10.10.20.30:19000/private/chat/V2","api_key":"raw-secret","auth_mode":"authorization_raw","model_id":"vendor-model-72b"}`

	rec := performCompleteChatCreate(t, body, repo, prober)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if prober.calls != 1 || prober.request.AuthMode != "authorization_raw" || prober.request.BaseURL != "http://10.10.20.30:19000/private/chat/V2" || prober.request.APIKey != "raw-secret" || prober.request.DeploymentName != "vendor-model-72b" {
		t.Fatalf("probe calls=%d request=%+v", prober.calls, prober.request)
	}
	if repo.createCalls != 1 || repo.provider == nil || repo.credential == nil || repo.model == nil {
		t.Fatalf("atomic bundle calls=%d provider=%+v credential=%+v model=%+v", repo.createCalls, repo.provider, repo.credential, repo.model)
	}
	if repo.provider.AuthMode != "authorization_raw" || repo.model.ModelName != "vendor-model-72b" || repo.model.UpstreamModelID != "vendor-model-72b" {
		t.Fatalf("provider=%+v model=%+v", repo.provider, repo.model)
	}
	protocols, _ := repo.model.Capabilities["protocols"].(map[string]interface{})
	if len(protocols) != 1 || protocols["chat_completions"] != true {
		t.Fatalf("capabilities=%+v", repo.model.Capabilities)
	}
	if repo.credential.SecretCiphertext == "raw-secret" {
		t.Fatal("credential was stored in plaintext")
	}
}

func TestCreateAuthorizationRawProviderProbeFailureDoesNotWriteOrLeakSecret(t *testing.T) {
	repo := &completeChatProviderRepo{MockProviderRepository: &MockProviderRepository{Providers: map[string]*repository.Provider{}, Credentials: map[string]*repository.ProviderCredential{}}}
	prober := &completeChatProber{result: catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorUnauthorized, Message: "上游认证失败"}}
	const secret = "must-not-leak"
	body := `{"name":"内部大模型","provider_type":"custom","base_url":"http://10.10.20.30/chat","api_key":"` + secret + `","auth_mode":"authorization_raw","model_id":"vendor-model"}`

	rec := performCompleteChatCreate(t, body, repo, prober)
	if rec.Code != http.StatusBadRequest || repo.createCalls != 0 {
		t.Fatalf("status=%d createCalls=%d body=%s", rec.Code, repo.createCalls, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("response leaked credential: %s", rec.Body.String())
	}
}

func TestCreateAuthorizationRawProviderRequiresCredentialModelAndCompatibleType(t *testing.T) {
	for _, body := range []string{
		`{"name":"x","provider_type":"custom","base_url":"http://10.0.0.1/chat","auth_mode":"authorization_raw","model_id":"m"}`,
		`{"name":"x","provider_type":"custom","base_url":"http://10.0.0.1/chat","api_key":"k","auth_mode":"authorization_raw"}`,
		`{"name":"x","provider_type":"anthropic","base_url":"http://10.0.0.1/chat","api_key":"k","auth_mode":"authorization_raw","model_id":"m"}`,
	} {
		repo := &completeChatProviderRepo{MockProviderRepository: &MockProviderRepository{Providers: map[string]*repository.Provider{}, Credentials: map[string]*repository.ProviderCredential{}}}
		prober := &completeChatProber{result: catalog.ModelProbeResult{OK: true}}
		rec := performCompleteChatCreate(t, body, repo, prober)
		if rec.Code != http.StatusBadRequest || prober.calls != 0 || repo.createCalls != 0 {
			t.Fatalf("body=%s status=%d probeCalls=%d createCalls=%d response=%s", body, rec.Code, prober.calls, repo.createCalls, rec.Body.String())
		}
	}
}

func TestSyncModelsRejectsAuthorizationRawWithoutReadingCredential(t *testing.T) {
	repo := &MockProviderRepository{Providers: map[string]*repository.Provider{
		"provider-a": {ID: "provider-a", TenantID: "tenant-a", ProviderType: "custom", AuthMode: "authorization_raw", Status: "active"},
	}, Credentials: map[string]*repository.ProviderCredential{}}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/models/sync", bytes.NewBufferString(`{"provider_id":"provider-a"}`))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user-a", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	SyncModels(&Dependencies{ProviderRepo: repo, ModelRepo: &MockModelRepository{}}).ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rec.Body.String(), "无需同步") {
		t.Fatalf("body=%s", rec.Body.String())
	}
}

func TestUpdateAuthorizationRawProviderReprobesBeforePersistingConnectionChanges(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "complete-chat-provider-update-test-key")
	repo := &completeChatProviderRepo{MockProviderRepository: &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"provider-a": {ID: "provider-a", TenantID: "tenant-a", ProviderType: "custom", BaseURL: "http://old.internal/chat", AuthMode: "authorization_raw", Status: "active"},
		},
		Credentials: map[string]*repository.ProviderCredential{"provider-a": {ID: "credential-a", ProviderID: "provider-a", SecretCiphertext: "synthetic-old-cipher", Status: "active"}},
	}}
	models := &MockModelRepository{Models: map[string]*repository.Model{
		"model-a": {ID: "model-a", ProviderID: "provider-a", ModelName: "public-model", UpstreamModelID: "vendor-model", Status: "active"},
	}}
	prober := &completeChatProber{result: catalog.ModelProbeResult{OK: true, PayloadValidated: true, HTTPStatus: 200, Message: "部署探测成功"}}

	req := httptest.NewRequest(http.MethodPatch, "/admin/v1/providers/provider-a", bytes.NewBufferString(`{"base_url":"http://new.internal/api/llm/chat/completions/V2","api_key":"new-raw-key"}`))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "provider-a")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx)
	ctx = context.WithValue(ctx, auth.UserKey, &repository.User{ID: "user-a", TenantID: "tenant-a"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	UpdateProvider(&Dependencies{ProviderRepo: repo, ModelRepo: models, ModelProber: prober}).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if prober.calls != 1 || prober.request.BaseURL != "http://new.internal/api/llm/chat/completions/V2" || prober.request.APIKey != "new-raw-key" || prober.request.DeploymentName != "vendor-model" {
		t.Fatalf("probe calls=%d request=%+v", prober.calls, prober.request)
	}
	if repo.updateCalls != 1 || repo.updated == nil || repo.updated.ProviderType != "custom" || repo.updated.BaseURL != "http://new.internal/api/llm/chat/completions/V2" || repo.rotated == nil {
		t.Fatalf("update calls=%d provider=%+v credential=%+v", repo.updateCalls, repo.updated, repo.rotated)
	}
}

func TestUpdateAuthorizationRawProviderProbeFailureKeepsPersistedConnection(t *testing.T) {
	repo := &completeChatProviderRepo{MockProviderRepository: &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"provider-a": {ID: "provider-a", TenantID: "tenant-a", ProviderType: "custom", BaseURL: "http://old.internal/chat", AuthMode: "authorization_raw", Status: "active"},
		},
		Credentials: map[string]*repository.ProviderCredential{"provider-a": {ID: "credential-a", ProviderID: "provider-a", SecretCiphertext: "synthetic-old-cipher", Status: "active"}},
	}}
	models := &MockModelRepository{Models: map[string]*repository.Model{
		"model-a": {ID: "model-a", ProviderID: "provider-a", ModelName: "vendor-model", Status: "active"},
	}}
	prober := &completeChatProber{result: catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorUnauthorized, Message: "上游认证失败"}}
	const secret = "new-key-must-not-leak"
	req := httptest.NewRequest(http.MethodPatch, "/admin/v1/providers/provider-a", bytes.NewBufferString(`{"base_url":"http://bad.internal/chat","api_key":"`+secret+`"}`))
	routeCtx := chi.NewRouteContext()
	routeCtx.URLParams.Add("id", "provider-a")
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, routeCtx)
	ctx = context.WithValue(ctx, auth.UserKey, &repository.User{ID: "user-a", TenantID: "tenant-a"})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	UpdateProvider(&Dependencies{ProviderRepo: repo, ModelRepo: models, ModelProber: prober}).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest || repo.updateCalls != 0 || strings.Contains(rec.Body.String(), secret) {
		t.Fatalf("status=%d updates=%d body=%s", rec.Code, repo.updateCalls, rec.Body.String())
	}
}

type rawChatFactModels struct {
	*MockModelRepository
	failRecord     bool
	disabled       []string
	failActivation bool
	activations    []string
}

func (m *rawChatFactModels) RecordProtocolProbe(ctx context.Context, tenant, provider, model string, caps map[string]interface{}, record repository.ModelProtocolProbeRecord) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if m.failRecord {
		return errors.New("synthetic persistence failure")
	}
	return m.MockModelRepository.RecordProtocolProbe(ctx, tenant, provider, model, caps, record)
}

func (m *rawChatFactModels) UpdateStatus(ctx context.Context, id, status string) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if status == "active" {
		m.activations = append(m.activations, id)
		if m.failActivation {
			return errors.New("synthetic activation failure")
		}
	}
	if status == "disabled" {
		m.disabled = append(m.disabled, id)
	}
	return nil
}

func TestRawChatCreationRecordsActualChatFact(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "complete-chat-fact-test-only")
	repo := &completeChatProviderRepo{MockProviderRepository: &MockProviderRepository{}}
	models := &rawChatFactModels{MockModelRepository: &MockModelRepository{}}
	prober := &completeChatProber{result: catalog.ModelProbeResult{OK: true, PayloadValidated: true, HTTPStatus: 200}}
	body := `{"name":"native-raw","provider_type":"openai","base_url":"http://10.20.30.1:28991/v1/chat/completions","api_key":"Bearer synthetic-key","auth_mode":"authorization_raw","model_id":"actual-upstream"}`
	before := time.Now().UTC()
	rec := performCompleteChatCreate(t, body, repo, prober, models)
	if rec.Code != http.StatusOK || len(models.RecordProtocolProbeCalls) != 1 {
		t.Fatalf("status=%d fact calls=%d body=%s", rec.Code, len(models.RecordProtocolProbeCalls), rec.Body.String())
	}
	call := models.RecordProtocolProbeCalls[0]
	if repo.model.Status != "disabled" || len(models.activations) != 1 || models.activations[0] != repo.model.ID {
		t.Fatal("new model was not disabled before persisted proof and confirmed activation")
	}
	if call.TenantID != "tenant-a" || call.ProviderID != repo.provider.ID || call.ModelID != repo.model.ID {
		t.Fatalf("fact identity = %+v", call)
	}
	record := call.Record
	wantDigest := repository.VerifiedModelSyncProviderConfigDigest("openai", repo.provider.BaseURL, "authorization_raw")
	if record.ProviderConfigDigest != wantDigest || record.SourceVersion == "" || record.VerifiedAt.Before(before) || record.ExpiresAt.Sub(record.VerifiedAt) != 30*24*time.Hour || len(record.Endpoints) != 1 || record.Endpoints[0].EndpointType != "chat" || record.Endpoints[0].State != "supported" {
		t.Fatalf("actual raw chat fact = %+v", record)
	}
}

func TestRawChatCreationUnvalidatedProbeOrWriterFailureDoesNotPublishSuccess(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "complete-chat-fact-test-only")
	body := `{"name":"native-raw","provider_type":"openai","base_url":"http://10.20.30.1:28991/v1/chat/completions","api_key":"Bearer synthetic-key","auth_mode":"authorization_raw","model_id":"actual-upstream"}`
	for _, writerFailure := range []bool{false, true} {
		t.Run(map[bool]string{false: "unvalidated", true: "writer_failure"}[writerFailure], func(t *testing.T) {
			repo := &completeChatProviderRepo{MockProviderRepository: &MockProviderRepository{}}
			models := &rawChatFactModels{MockModelRepository: &MockModelRepository{}, failRecord: writerFailure}
			prober := &completeChatProber{result: catalog.ModelProbeResult{OK: true, PayloadValidated: writerFailure, HTTPStatus: 200}}
			rec := performCompleteChatCreate(t, body, repo, prober, models)
			if rec.Code == http.StatusOK {
				t.Fatalf("unproven or unpersisted fact advertised success: %s", rec.Body.String())
			}
			if !writerFailure && repo.createCalls != 0 {
				t.Fatal("unvalidated probe created bundle")
			}
			if writerFailure && (repo.model.Status != "disabled" || len(models.activations) != 0) {
				t.Fatal("unpersisted model was created active or activated")
			}
		})
	}
}
