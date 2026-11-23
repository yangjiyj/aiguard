package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

type verifiedProviderRepo struct {
	*MockProviderRepository
	getByIDCalls         atomic.Int32
	getCredentialCalls   atomic.Int32
	panicOnGetCredential bool
}

func (r *verifiedProviderRepo) GetByID(ctx context.Context, tenantID, id string) (*repository.Provider, error) {
	r.getByIDCalls.Add(1)
	return r.MockProviderRepository.GetByID(ctx, tenantID, id)
}

func (r *verifiedProviderRepo) GetCredential(ctx context.Context, providerID string) (*repository.ProviderCredential, error) {
	if r.panicOnGetCredential {
		panic("GetCredential must not be called")
	}
	r.getCredentialCalls.Add(1)
	return r.MockProviderRepository.GetCredential(ctx, providerID)
}

type verifiedModelRepo struct {
	*MockModelRepository
	listErr      error
	listCalls    atomic.Int32
	replaceCalls atomic.Int32
}

func (r *verifiedModelRepo) List(ctx context.Context, tenantID string) ([]*repository.Model, error) {
	r.listCalls.Add(1)
	if r.listErr != nil {
		return nil, r.listErr
	}
	return r.MockModelRepository.List(ctx, tenantID)
}

func (r *verifiedModelRepo) MergeVerifiedProviderModels(ctx context.Context, tenantID, providerID, credentialID, providerConfigDigest string, desired []repository.VerifiedProviderModel) (repository.VerifiedModelSyncResult, error) {
	r.replaceCalls.Add(1)
	return r.MockModelRepository.MergeVerifiedProviderModels(ctx, tenantID, providerID, credentialID, providerConfigDigest, desired)
}

type verifiedPermissionAuthorizer struct {
	allowed bool
	err     error
	calls   []modelBatchDeletePermissionCall
}

func (a *verifiedPermissionAuthorizer) HasPermission(
	_ context.Context,
	userID, tenantID, scopeType, scopeID, resource, action string,
) (bool, error) {
	a.calls = append(a.calls, modelBatchDeletePermissionCall{
		userID: userID, tenantID: tenantID, scopeType: scopeType,
		scopeID: scopeID, resource: resource, action: action,
	})
	return a.allowed, a.err
}

func (*verifiedPermissionAuthorizer) InvalidateUserCache(string) {}

type verifiedCatalogFactory struct {
	client catalog.Client
	err    error
	calls  atomic.Int32
}

func (f *verifiedCatalogFactory) GetClient(string) (catalog.Client, error) {
	f.calls.Add(1)
	return f.client, f.err
}

type verifiedProber struct {
	mu       sync.Mutex
	results  map[string]catalog.ModelProbeResult
	calls    []catalog.ModelProbeRequest
	inFlight atomic.Int32
	peak     atomic.Int32
	block    chan struct{}
	entered  chan struct{}
}

func (p *verifiedProber) Probe(ctx context.Context, req catalog.ModelProbeRequest) catalog.ModelProbeResult {
	current := p.inFlight.Add(1)
	for {
		peak := p.peak.Load()
		if current <= peak || p.peak.CompareAndSwap(peak, current) {
			break
		}
	}
	p.mu.Lock()
	p.calls = append(p.calls, req)
	p.mu.Unlock()
	if p.entered != nil {
		select {
		case p.entered <- struct{}{}:
		default:
		}
	}
	if p.block != nil {
		select {
		case <-p.block:
		case <-ctx.Done():
		}
	}
	p.inFlight.Add(-1)
	if result, ok := p.results[req.DeploymentName]; ok {
		return result
	}
	return catalog.ModelProbeResult{OK: true, Message: "ok"}
}

func (p *verifiedProber) snapshot() []catalog.ModelProbeRequest {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]catalog.ModelProbeRequest(nil), p.calls...)
}

type verifiedAuditRepo struct{ ops []*repository.AuditOperation }

func (*verifiedAuditRepo) Get(context.Context, string) (*repository.SystemSetting, error) {
	return nil, nil
}
func (*verifiedAuditRepo) GetAll(context.Context) ([]*repository.SystemSetting, error) {
	return nil, nil
}
func (*verifiedAuditRepo) Set(context.Context, string, string) error            { return nil }
func (*verifiedAuditRepo) SetMultiple(context.Context, map[string]string) error { return nil }
func (*verifiedAuditRepo) GetBool(context.Context, string) (bool, error)        { return false, nil }
func (*verifiedAuditRepo) ListAuditOperations(context.Context, int, int, string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (r *verifiedAuditRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.ops = append(r.ops, op)
	return nil
}

func verifiedDeps() (*Dependencies, *verifiedProviderRepo, *verifiedModelRepo, *verifiedCatalogFactory) {
	providers := &verifiedProviderRepo{MockProviderRepository: &MockProviderRepository{
		Providers: map[string]*repository.Provider{
			"provider-a": {ID: "provider-a", TenantID: "tenant-a", ProviderType: "azure", BaseURL: "https://azure.example.test", AuthMode: "api-key", Status: "active"},
			"provider-b": {ID: "provider-b", TenantID: "tenant-b", ProviderType: "azure", BaseURL: "https://other.example.test", AuthMode: "bearer", Status: "active"},
		},
		Credentials: map[string]*repository.ProviderCredential{
			"provider-a": {ID: "credential-a", ProviderID: "provider-a", SecretCiphertext: "api-key-secret", Status: "active"},
			"provider-b": {ID: "credential-b", ProviderID: "provider-b", SecretCiphertext: "other-secret", Status: "active"},
		},
	}}
	models := &verifiedModelRepo{MockModelRepository: &MockModelRepository{Models: map[string]*repository.Model{
		"m1":    {ID: "m1", ProviderID: "provider-a", ModelName: "gpt-5.5", UpstreamModelID: "edited-existing", Status: "active"},
		"m2":    {ID: "m2", ProviderID: "provider-a", ModelName: "old", UpstreamModelID: "old-deploy", Status: "disabled"},
		"other": {ID: "other", ProviderID: "provider-b", ModelName: "other", Status: "active"},
	}}}
	factory := &verifiedCatalogFactory{client: &MockCatalogClient{Models: []types.ProviderCatalogModel{
		{ID: "gpt-5.6", Name: "GPT 5.6"}, {ID: "gpt-5.5", Name: "GPT 5.5"}, {ID: "gpt-5.5", Name: "duplicate"},
	}}}
	deps := &Dependencies{
		ProviderRepo: providers, ModelRepo: models, CatalogFactory: factory,
		ModelProber: &verifiedProber{}, ModelSyncProofSecret: modelSyncTokenTestSecret,
		ModelSyncVerifyGate: NewModelSyncVerifyGate(),
		PermissionChecker:   &verifiedPermissionAuthorizer{allowed: true},
	}
	return deps, providers, models, factory
}

func verifiedModelSyncTestClaim(catalogID, deploymentName, credentialID string, expiresAt int64) modelSyncClaim {
	activeModels := []*repository.Model{{
		ID:              "m1",
		ProviderID:      "provider-a",
		ModelName:       "gpt-5.5",
		UpstreamModelID: "edited-existing",
		Status:          "active",
	}}
	return modelSyncClaim{
		Version:              2,
		TenantID:             "tenant-a",
		ProviderID:           "provider-a",
		CredentialID:         credentialID,
		ProviderConfigDigest: repository.VerifiedModelSyncProviderConfigDigest("azure", "https://azure.example.test", "api-key"),
		ActiveSetDigest:      repository.VerifiedModelSyncActiveSetDigest(activeModels, "provider-a"),
		VerificationBatchID:  "batch-a",
		CatalogID:            catalogID,
		DeploymentName:       deploymentName,
		EndpointType:         "chat",
		ExpiresAt:            expiresAt,
	}
}

func verifiedRequest(t *testing.T, h http.HandlerFunc, body any, raw string) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if raw != "" {
		data = []byte(raw)
	} else {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user-a", TenantID: "tenant-a"}))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func verifiedDecode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var got T
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %d %q: %v", rec.Code, rec.Body.String(), err)
	}
	return got
}

func TestVerifiedModelSyncAuthorizationFailsClosedBeforeParsingOrDependencies(t *testing.T) {
	endpoints := []struct {
		name string
		get  func(*Dependencies) http.HandlerFunc
	}{
		{name: "preview", get: PreviewVerifiedModelSync},
		{name: "verify", get: VerifyModelSyncCandidates},
		{name: "commit", get: CommitVerifiedModelSync},
	}
	checks := []struct {
		name     string
		checker  *verifiedPermissionAuthorizer
		wantCode string
	}{
		{name: "missing", checker: nil, wantCode: "permission_check_failed"},
		{name: "error", checker: &verifiedPermissionAuthorizer{allowed: true, err: errors.New("permission backend sensitive")}, wantCode: "permission_check_failed"},
		{name: "denied", checker: &verifiedPermissionAuthorizer{allowed: false}, wantCode: "permission_denied"},
	}

	for _, endpoint := range endpoints {
		for _, check := range checks {
			t.Run(endpoint.name+"/"+check.name, func(t *testing.T) {
				deps, providers, models, factory := verifiedDeps()
				if check.checker == nil {
					deps.PermissionChecker = nil
				} else {
					check.checker.calls = nil
					deps.PermissionChecker = check.checker
				}
				prober := &verifiedProber{}
				deps.ModelProber = prober

				rec := verifiedRequest(t, endpoint.get(deps), nil, "not-json")
				if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), check.wantCode) || strings.Contains(rec.Body.String(), "sensitive") {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
				}
				if providers.getByIDCalls.Load() != 0 || providers.getCredentialCalls.Load() != 0 ||
					factory.calls.Load() != 0 || models.listCalls.Load() != 0 || models.replaceCalls.Load() != 0 || len(prober.snapshot()) != 0 {
					t.Fatalf("dependencies reached: provider=%d credential=%d catalog=%d list=%d replace=%d probes=%d",
						providers.getByIDCalls.Load(), providers.getCredentialCalls.Load(), factory.calls.Load(),
						models.listCalls.Load(), models.replaceCalls.Load(), len(prober.snapshot()))
				}
				if check.checker != nil {
					if len(check.checker.calls) != 1 {
						t.Fatalf("permission calls=%d want=1", len(check.checker.calls))
					}
					call := check.checker.calls[0]
					if call.userID != "user-a" || call.tenantID != "tenant-a" || call.scopeType != "tenant" || call.scopeID != "tenant-a" || call.resource != "models" || call.action != "write" {
						t.Fatalf("permission call=%#v", call)
					}
				}
			})
		}
	}
}

func TestPreviewVerifiedModelSyncIsReadOnly(t *testing.T) {
	deps, _, models, _ := verifiedDeps()
	rec := verifiedRequest(t, PreviewVerifiedModelSync(deps), ModelSyncPreviewRequest{ProviderID: "provider-a"}, "")
	got := verifiedDecode[ModelSyncPreviewResponse](t, rec)
	if rec.Code != http.StatusOK || got.ProviderID != "provider-a" || got.CatalogUnavailable || got.CurrentActive != 1 || len(got.Candidates) != 2 {
		t.Fatalf("status=%d preview=%#v", rec.Code, got)
	}
	if got.Candidates[0].CatalogModelID != "gpt-5.5" || got.Candidates[0].DeploymentName != "edited-existing" || got.Candidates[0].CurrentStatus != "active" {
		t.Fatalf("existing=%#v", got.Candidates[0])
	}
	if models.replaceCalls.Load() != 0 || len(models.UpsertCalls) != 0 || len(models.UpdateCapabilitiesCalls) != 0 {
		t.Fatal("preview wrote model repo")
	}
}

func TestPreviewVerifiedModelSyncFiltersUnverifiableCatalogEntries(t *testing.T) {
	deps, _, _, factory := verifiedDeps()
	invalidUTF8 := string([]byte{0xff, 0xfe})
	factory.client = &MockCatalogClient{Models: []types.ProviderCatalogModel{
		{ID: "valid", Name: "unsafe\nname"},
		{ID: "valid", Name: "duplicate must be ignored"},
		{ID: "valid-two", Name: strings.Repeat("n", modelSyncFieldMaxRunes+1)},
		{ID: "valid-three", Name: invalidUTF8},
		{ID: "bad internal space"},
		{ID: "bad\ncontrol"},
		{ID: strings.Repeat("x", modelSyncFieldMaxRunes+1)},
		{ID: invalidUTF8},
	}}
	rec := verifiedRequest(t, PreviewVerifiedModelSync(deps), ModelSyncPreviewRequest{ProviderID: "provider-a"}, "")
	got := verifiedDecode[ModelSyncPreviewResponse](t, rec)
	if rec.Code != http.StatusOK || len(got.Candidates) != 3 {
		t.Fatalf("status=%d candidates=%#v", rec.Code, got.Candidates)
	}
	for _, candidate := range got.Candidates {
		if candidate.DisplayName != candidate.CatalogModelID || containsUnicodeControl(candidate.DisplayName) || !utf8.ValidString(candidate.DisplayName) || utf8.RuneCountInString(candidate.DisplayName) > modelSyncFieldMaxRunes {
			t.Fatalf("unsafe display candidate=%#v", candidate)
		}
	}
}

func TestPreviewVerifiedModelSyncRejectsCrossTenantProvider(t *testing.T) {
	deps, providers, models, factory := verifiedDeps()
	rec := verifiedRequest(t, PreviewVerifiedModelSync(deps), ModelSyncPreviewRequest{ProviderID: "provider-b"}, "")
	if rec.Code != http.StatusNotFound || providers.getCredentialCalls.Load() != 0 || factory.calls.Load() != 0 || models.listCalls.Load() != 0 {
		t.Fatalf("status=%d cred=%d catalog=%d list=%d body=%s", rec.Code, providers.getCredentialCalls.Load(), factory.calls.Load(), models.listCalls.Load(), rec.Body.String())
	}
}

func TestPreviewVerifiedModelSyncCatalogUnavailable(t *testing.T) {
	deps, _, _, factory := verifiedDeps()
	factory.client = &MockCatalogClient{Err: errors.New("sensitive upstream failure")}
	rec := verifiedRequest(t, PreviewVerifiedModelSync(deps), ModelSyncPreviewRequest{ProviderID: "provider-a"}, "")
	got := verifiedDecode[ModelSyncPreviewResponse](t, rec)
	if rec.Code != http.StatusOK || !got.CatalogUnavailable || got.CurrentActive != 1 || got.Candidates == nil || len(got.Candidates) != 0 || strings.Contains(rec.Body.String(), "sensitive") {
		t.Fatalf("status=%d preview=%#v body=%s", rec.Code, got, rec.Body.String())
	}
}

func TestVerifyModelSyncCandidatesFailureKinds(t *testing.T) {
	tests := []struct {
		name  string
		probe catalog.ModelProbeResult
		want  string
	}{
		{"401", catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorUnauthorized, Message: "raw 401 secret"}, catalog.ModelProbeErrorUnauthorized},
		{"403", catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorUnauthorized, Message: "raw 403 secret"}, catalog.ModelProbeErrorUnauthorized},
		{"404", catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorNotDeployed, Message: "raw 404 detail"}, catalog.ModelProbeErrorNotDeployed},
		{"429", catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorRateLimited, Message: "raw 429 detail"}, catalog.ModelProbeErrorRateLimited},
		{"timeout", catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorTimeout, Message: "raw timeout detail"}, catalog.ModelProbeErrorTimeout},
		{"500", catalog.ModelProbeResult{ErrorKind: catalog.ModelProbeErrorUpstream, Message: "raw 500 detail"}, catalog.ModelProbeErrorUpstream},
		{"unknown", catalog.ModelProbeResult{ErrorKind: "untrusted_kind", Message: "raw unknown detail"}, catalog.ModelProbeErrorUpstream},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _, _, _ := verifiedDeps()
			deps.ModelProber = &verifiedProber{results: map[string]catalog.ModelProbeResult{"deployment": tt.probe}}
			rec := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: []ModelSyncVerifyItem{{"catalog", "deployment", nil}}}, "")
			got := verifiedDecode[ModelSyncVerifyResponse](t, rec)
			if rec.Code != http.StatusOK || len(got.Results) != 1 {
				t.Fatalf("status=%d response=%#v", rec.Code, got)
			}
			result := got.Results[0]
			if result.Status != "failed" || result.ErrorKind != tt.want || result.ProofToken != "" || result.ExpiresAt != nil || strings.Contains(rec.Body.String(), "raw ") {
				t.Fatalf("result=%#v body=%s", result, rec.Body.String())
			}
		})
	}
}

func TestVerifyModelSyncCandidatesOnlyMintsTokenFor2xx(t *testing.T) {
	deps, _, _, _ := verifiedDeps()
	prober := &verifiedProber{results: map[string]catalog.ModelProbeResult{"unauth": {ErrorKind: catalog.ModelProbeErrorUnauthorized, Message: "sensitive raw detail"}}}
	deps.ModelProber = prober
	items := []ModelSyncVerifyItem{{"a", "ok", nil}, {"b", "ok-two", nil}, {"c", "ok-three", nil}, {"d", "unauth", nil}, {"e", "never", nil}}
	rec := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: items}, "")
	got := verifiedDecode[ModelSyncVerifyResponse](t, rec)
	if rec.Code != http.StatusOK || len(got.Results) != 5 {
		t.Fatalf("status=%d response=%#v", rec.Code, got)
	}
	for i := 0; i < 3; i++ {
		if got.Results[i].Status != "success" || got.Results[i].ErrorKind != "" || got.Results[i].ProofToken == "" || got.Results[i].ExpiresAt == nil {
			t.Fatalf("success[%d]=%#v", i, got.Results[i])
		}
	}
	if got.Results[3].Status != "failed" || got.Results[3].ErrorKind != catalog.ModelProbeErrorUnauthorized || got.Results[3].ProofToken != "" {
		t.Fatalf("unauthorized=%#v", got.Results[3])
	}
	if got.Results[4].Status != "skipped" || got.Results[4].ErrorKind != "skipped_after_unauthorized" || got.Results[4].ProofToken != "" {
		t.Fatalf("skipped=%#v", got.Results[4])
	}
	if len(prober.snapshot()) != 4 {
		t.Fatalf("unauthorized batch started %d probes, want exactly first chunk of 4", len(prober.snapshot()))
	}
	if strings.Contains(rec.Body.String(), "sensitive raw detail") {
		t.Fatalf("response leaked raw probe detail: %s", rec.Body.String())
	}
}

func TestVerifyModelSyncCandidatesUsesEditedDeploymentName(t *testing.T) {
	deps, _, _, _ := verifiedDeps()
	prober := &verifiedProber{}
	deps.ModelProber = prober
	before := time.Now()
	rec := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: []ModelSyncVerifyItem{{"catalog-id", "edited-deployment", nil}}}, "")
	after := time.Now()
	got := verifiedDecode[ModelSyncVerifyResponse](t, rec)
	calls := prober.snapshot()
	claim, err := openModelSyncClaim(modelSyncTokenTestSecret, got.Results[0].ProofToken, after)
	if rec.Code != http.StatusOK || len(calls) != 1 || calls[0].DeploymentName != "edited-deployment" || calls[0].APIKey != "api-key-secret" || calls[0].AuthMode != "api-key" || err != nil {
		t.Fatalf("status=%d calls=%#v claim=%#v err=%v", rec.Code, calls, claim, err)
	}
	wantConfigDigest := repository.VerifiedModelSyncProviderConfigDigest("azure", "https://azure.example.test", "api-key")
	wantActiveDigest := repository.VerifiedModelSyncActiveSetDigest([]*repository.Model{{ID: "m1", ProviderID: "provider-a", ModelName: "gpt-5.5", UpstreamModelID: "edited-existing", Status: "active"}}, "provider-a")
	if claim.Version != 2 || claim.TenantID != "tenant-a" || claim.ProviderID != "provider-a" || claim.CredentialID != "credential-a" || claim.ProviderConfigDigest != wantConfigDigest || claim.ActiveSetDigest != wantActiveDigest || strings.TrimSpace(claim.VerificationBatchID) == "" || claim.CatalogID != "catalog-id" || claim.DeploymentName != "edited-deployment" || claim.EndpointType != "chat" {
		t.Fatalf("claim bindings=%#v", claim)
	}
	if claim.ExpiresAt < before.Add(modelSyncProofTTL-time.Second).Unix() || claim.ExpiresAt > after.Add(modelSyncProofTTL+time.Second).Unix() {
		t.Fatalf("claim expiry=%d outside 10 minute window [%d,%d]", claim.ExpiresAt, before.Add(modelSyncProofTTL-time.Second).Unix(), after.Add(modelSyncProofTTL+time.Second).Unix())
	}
}

func TestVerifyModelSyncCandidatesRecordsExplicitResponsesProtocol(t *testing.T) {
	deps, _, _, _ := verifiedDeps()
	prober := &verifiedProber{}
	deps.ModelProber = prober
	rec := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{
		ProviderID: "provider-a",
		Items:      []ModelSyncVerifyItem{{CatalogModelID: "customer-coding-prod", DeploymentName: "azure-deployment-coding", Protocols: []string{"chat_completions", "responses"}}},
	}, "")
	got := verifiedDecode[ModelSyncVerifyResponse](t, rec)
	if rec.Code != http.StatusOK || len(got.Results) != 1 || got.Results[0].Status != "success" {
		t.Fatalf("status=%d result=%#v body=%s", rec.Code, got.Results, rec.Body.String())
	}
	if len(prober.snapshot()) != 2 || prober.snapshot()[0].Protocol != "chat_completions" || prober.snapshot()[1].Protocol != "responses" {
		t.Fatalf("protocol probes=%#v", prober.snapshot())
	}
	claim, err := openModelSyncClaim(modelSyncTokenTestSecret, got.Results[0].ProofToken, time.Now().Add(time.Second))
	if err != nil || len(claim.Protocols) != 2 || claim.Protocols[0] != "chat_completions" || claim.Protocols[1] != "responses_native" {
		t.Fatalf("claim=%#v err=%v", claim, err)
	}
}

func TestVerifyModelSyncCandidatesRejectsInvalidWithoutProbe(t *testing.T) {
	tooMany := make([]ModelSyncVerifyItem, 51)
	for i := range tooMany {
		tooMany[i] = ModelSyncVerifyItem{CatalogModelID: "m" + string(rune(0x100+i)), DeploymentName: "d" + string(rune(0x100+i))}
	}
	tests := [][]ModelSyncVerifyItem{nil, tooMany, {{" ", "d", nil}}, {{"bad\n", "d", nil}}, {{"m", "bad\t", nil}}, {{strings.Repeat("m", 256), "d", nil}}, {{"m", strings.Repeat("d", 256), nil}}, {{"m", "d1", nil}, {"m", "d2", nil}}}
	for i, items := range tests {
		deps, _, _, _ := verifiedDeps()
		prober := &verifiedProber{}
		deps.ModelProber = prober
		rec := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: items}, "")
		if rec.Code != http.StatusBadRequest || len(prober.snapshot()) != 0 {
			t.Fatalf("case=%d status=%d probes=%d body=%s", i, rec.Code, len(prober.snapshot()), rec.Body.String())
		}
	}
}

func TestVerifyModelSyncCandidatesCapsConcurrencyAndGate(t *testing.T) {
	deps, _, _, _ := verifiedDeps()
	prober := &verifiedProber{block: make(chan struct{}), entered: make(chan struct{}, 8)}
	deps.ModelProber = prober
	items := make([]ModelSyncVerifyItem, 8)
	for i := range items {
		items[i] = ModelSyncVerifyItem{"m" + string(rune('a'+i)), "d" + string(rune('a'+i)), nil}
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: items}, "")
	}()
	for i := 0; i < 4; i++ {
		select {
		case <-prober.entered:
		case <-time.After(time.Second):
			t.Fatal("first chunk not started")
		}
	}
	time.Sleep(20 * time.Millisecond)
	second := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: []ModelSyncVerifyItem{{"other", "other", nil}}}, "")
	if len(prober.snapshot()) != 4 || second.Code != http.StatusConflict || !strings.Contains(second.Body.String(), "verification_in_progress") {
		t.Fatalf("probes=%d second=%d body=%s", len(prober.snapshot()), second.Code, second.Body.String())
	}
	close(prober.block)
	first := <-done
	if first.Code != http.StatusOK || prober.peak.Load() > 4 {
		t.Fatalf("first=%d peak=%d", first.Code, prober.peak.Load())
	}
	beforeThird := len(prober.snapshot())
	third := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: []ModelSyncVerifyItem{{"third", "third", nil}}}, "")
	if third.Code != http.StatusOK || len(prober.snapshot()) != beforeThird+1 {
		t.Fatalf("third=%d probes before=%d after=%d body=%s", third.Code, beforeThird, len(prober.snapshot()), third.Body.String())
	}
}

func TestVerifiedModelSyncSecretUnavailable(t *testing.T) {
	for _, secret := range []string{"", "   "} {
		deps, _, _, _ := verifiedDeps()
		deps.ModelSyncProofSecret = secret
		prober := &verifiedProber{}
		deps.ModelProber = prober
		v := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: []ModelSyncVerifyItem{{"m", "d", nil}}}, "")
		c := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{"x"}}, "")
		p := verifiedRequest(t, PreviewVerifiedModelSync(deps), ModelSyncPreviewRequest{ProviderID: "provider-a"}, "")
		if v.Code != 503 || c.Code != 503 || p.Code != 200 || len(prober.snapshot()) != 0 {
			t.Fatalf("secret=%q v=%d c=%d p=%d", secret, v.Code, c.Code, p.Code)
		}
	}
}

func TestCommitVerifiedModelSyncRejectsExpiredOrRotatedCredential(t *testing.T) {
	now := time.Now()
	expired := verifiedModelSyncTestClaim("m", "d", "credential-a", now.Add(-time.Second).Unix())
	wrongTenant := verifiedModelSyncTestClaim("m", "d", "credential-a", now.Add(time.Minute).Unix())
	wrongTenant.TenantID = "tenant-b"
	wrongProvider := verifiedModelSyncTestClaim("m", "d", "credential-a", now.Add(time.Minute).Unix())
	wrongProvider.ProviderID = "provider-b"
	claims := []modelSyncClaim{expired, wrongTenant, wrongProvider}
	for i, claim := range claims {
		deps, _, models, _ := verifiedDeps()
		token, err := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
		if err != nil {
			t.Fatal(err)
		}
		rec := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{token}}, "")
		if rec.Code != 400 || models.replaceCalls.Load() != 0 || !strings.Contains(rec.Body.String(), "invalid_verification") || strings.Contains(rec.Body.String(), token) {
			t.Fatalf("case=%d status=%d replace=%d body=%s", i, rec.Code, models.replaceCalls.Load(), rec.Body.String())
		}
	}
}

func TestCommitVerifiedModelSyncPassesOnlyVerifiedClaimsToRepository(t *testing.T) {
	deps, _, models, _ := verifiedDeps()
	models.ReplaceResult = repository.VerifiedModelSyncResult{Created: 1, Updated: 2, Reactivated: 3, Deactivated: 4}
	audit := &verifiedAuditRepo{}
	deps.SystemRepo = audit
	claim := verifiedModelSyncTestClaim("gpt-5.6", "edited-deploy", "credential-a", time.Now().Add(time.Minute).Unix())
	token, _ := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
	rec := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{token, token}}, "")
	got := verifiedDecode[ModelSyncCommitResponse](t, rec)
	if rec.Code != 200 || got.ProviderID != "provider-a" || got.Created != 1 || got.Updated != 2 || got.Reactivated != 3 || got.Deactivated != 4 || len(models.ReplaceCalls) != 1 || models.ReplaceCalls[0].ExpectedCredentialID != "credential-a" || len(models.ReplaceCalls[0].Desired) != 1 {
		t.Fatalf("status=%d got=%#v calls=%#v", rec.Code, got, models.ReplaceCalls)
	}
	d := models.ReplaceCalls[0].Desired[0]
	modality, ok := d.Capabilities["modality"].(map[string]interface{})
	if d.CatalogID != "gpt-5.6" || d.DeploymentName != "edited-deploy" || d.ModelLabel != "gpt-5.6" || d.Capabilities["endpoint_type"] != "chat" || !ok || modality["type"] != "text" || modality["source"] != "verified_chat" {
		t.Fatalf("desired=%#v", d)
	}
	if len(audit.ops) != 1 || audit.ops[0].ActionType != "sync_verified_models" || audit.ops[0].TargetID != "provider-a" || len(audit.ops[0].ActionDetail) != 4 {
		t.Fatalf("audit=%#v", audit.ops)
	}
	b, _ := json.Marshal(audit.ops[0])
	for _, s := range []string{token, "credential-a", "edited-deploy", "api-key-secret", "tenant-a"} {
		if strings.Contains(string(b), s) {
			t.Fatalf("audit leaked %q: %s", s, b)
		}
	}
}

func TestCommitVerifiedModelSyncDoesNotInferNativeResponsesFromGPTNames(t *testing.T) {
	for _, modelName := range []string{
		"gpt-4",
		"gpt-4o",
		"gpt-4o-mini",
		"gpt-4.1",
		"gpt-5",
		"gpt-5.4",
		"gpt-5.5",
		"gpt-5.5-2026-04-24",
		"gpt-5.6",
		"GPT-5.6-LUNA",
	} {
		t.Run(modelName, func(t *testing.T) {
			deps, _, models, _ := verifiedDeps()
			claim := verifiedModelSyncTestClaim(modelName, modelName+"-deployment", "credential-a", time.Now().Add(time.Minute).Unix())
			token, err := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
			if err != nil {
				t.Fatal(err)
			}
			rec := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{token}}, "")
			if rec.Code != http.StatusOK || len(models.ReplaceCalls) != 1 || len(models.ReplaceCalls[0].Desired) != 1 {
				t.Fatalf("status=%d body=%s calls=%#v", rec.Code, rec.Body.String(), models.ReplaceCalls)
			}
			capabilities := models.ReplaceCalls[0].Desired[0].Capabilities
			modality, modalityOK := capabilities["modality"].(map[string]interface{})
			if capabilities["endpoint_type"] != "chat" || !modalityOK || modality["type"] != "text" || modality["source"] != "verified_chat" {
				t.Fatalf("model=%q expected verified chat text capabilities, got %#v", modelName, capabilities)
			}
			protocols, ok := capabilities["protocols"].(map[string]interface{})
			if !ok || protocols["chat_completions"] != true || protocols["responses_native"] == true {
				t.Fatalf("model=%q expected explicit chat-only protocol capabilities, got %#v", modelName, capabilities)
			}
		})
	}
}

func TestCommitVerifiedModelSyncPersistsExplicitVerifiedProtocols(t *testing.T) {
	deps, _, models, _ := verifiedDeps()
	claim := verifiedModelSyncTestClaim("customer-coding-prod", "azure-deployment-coding", "credential-a", time.Now().Add(time.Minute).Unix())
	claim.Protocols = []string{"chat_completions", "responses_native"}
	token, err := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
	if err != nil {
		t.Fatal(err)
	}
	rec := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{token}}, "")
	if rec.Code != http.StatusOK || len(models.ReplaceCalls) != 1 {
		t.Fatalf("status=%d body=%s calls=%#v", rec.Code, rec.Body.String(), models.ReplaceCalls)
	}
	protocols, ok := models.ReplaceCalls[0].Desired[0].Capabilities["protocols"].(map[string]interface{})
	if !ok || protocols["chat_completions"] != true || protocols["responses_native"] != true {
		t.Fatalf("explicit verified protocols were not persisted: %#v", models.ReplaceCalls[0].Desired[0].Capabilities)
	}
}

func TestCommitVerifiedModelSyncRejectsConflictingClaimsAndOversizedToken(t *testing.T) {
	deps, _, models, _ := verifiedDeps()
	expires := time.Now().Add(time.Minute).Unix()
	first := verifiedModelSyncTestClaim("same-catalog", "deploy-one", "credential-a", expires)
	second := first
	second.DeploymentName = "deploy-two"
	firstToken, _ := sealModelSyncClaim(modelSyncTokenTestSecret, first)
	secondToken, _ := sealModelSyncClaim(modelSyncTokenTestSecret, second)
	conflict := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{firstToken, secondToken}}, "")
	if conflict.Code != http.StatusBadRequest || models.replaceCalls.Load() != 0 {
		t.Fatalf("conflict status=%d replace=%d body=%s", conflict.Code, models.replaceCalls.Load(), conflict.Body.String())
	}

	oversizedDeps, _, oversizedModels, _ := verifiedDeps()
	oversized := verifiedRequest(t, CommitVerifiedModelSync(oversizedDeps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{strings.Repeat("x", modelSyncTokenMaxLength+1)}}, "")
	if oversized.Code != http.StatusBadRequest || oversizedModels.replaceCalls.Load() != 0 {
		t.Fatalf("oversized status=%d replace=%d body=%s", oversized.Code, oversizedModels.replaceCalls.Load(), oversized.Body.String())
	}
}

func TestVerifiedModelSyncCatalog338Probe4Commit4(t *testing.T) {
	deps, _, models, factory := verifiedDeps()
	all := make([]types.ProviderCatalogModel, 338)
	for i := range all {
		all[i] = types.ProviderCatalogModel{ID: "catalog-" + string(rune(0x100+i))}
	}
	factory.client = &MockCatalogClient{Models: all}
	pRec := verifiedRequest(t, PreviewVerifiedModelSync(deps), ModelSyncPreviewRequest{ProviderID: "provider-a"}, "")
	p := verifiedDecode[ModelSyncPreviewResponse](t, pRec)
	if len(p.Candidates) != 338 {
		t.Fatalf("candidates=%d", len(p.Candidates))
	}
	items := make([]ModelSyncVerifyItem, 4)
	for i := range items {
		items[i] = ModelSyncVerifyItem{p.Candidates[i].CatalogModelID, "deploy-" + string(rune('a'+i)), nil}
	}
	prober := &verifiedProber{}
	deps.ModelProber = prober
	vRec := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: items}, "")
	v := verifiedDecode[ModelSyncVerifyResponse](t, vRec)
	tokens := make([]string, 4)
	for i := range v.Results {
		tokens[i] = v.Results[i].ProofToken
	}
	cRec := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: tokens}, "")
	if pRec.Code != 200 || vRec.Code != 200 || cRec.Code != 200 || len(prober.snapshot()) != 4 || len(models.ReplaceCalls) != 1 || len(models.ReplaceCalls[0].Desired) != 4 {
		t.Fatalf("p=%d v=%d c=%d probes=%d calls=%#v", pRec.Code, vRec.Code, cRec.Code, len(prober.snapshot()), models.ReplaceCalls)
	}
}

func TestVerifiedModelSyncRejectsUnknownTrailingAndOversizedJSON(t *testing.T) {
	deps, _, _, _ := verifiedDeps()
	handlers := []http.HandlerFunc{PreviewVerifiedModelSync(deps), VerifyModelSyncCandidates(deps), CommitVerifiedModelSync(deps)}
	bodies := []string{`{"provider_id":"provider-a","unknown":true}`, `{"provider_id":"provider-a"} {}`, `{"provider_id":"provider-a","padding":"` + strings.Repeat("x", 300<<10) + `"}`}
	for i, h := range handlers {
		for _, raw := range bodies {
			rec := verifiedRequest(t, h, nil, raw)
			if (rec.Code != 400 && rec.Code != 413) || !json.Valid(rec.Body.Bytes()) {
				t.Fatalf("handler=%d status=%d body=%s", i, rec.Code, rec.Body.String())
			}
		}
	}
}

type panicModelProber struct{}

func (panicModelProber) Probe(context.Context, catalog.ModelProbeRequest) catalog.ModelProbeResult {
	panic("panic contains api-key-secret and edited-deployment")
}

func TestVerifiedModelSyncRequiresJSONContentTypeBeforeDependencies(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
	}{
		{"missing", ""},
		{"text", "text/plain"},
		{"form", "application/x-www-form-urlencoded"},
		{"malformed", "application/json; charset==broken"},
	}
	endpoints := []struct {
		name string
		body string
		get  func(*Dependencies) http.HandlerFunc
	}{
		{"preview", `{"provider_id":"provider-a"}`, PreviewVerifiedModelSync},
		{"verify", `{"provider_id":"provider-a","items":[{"catalog_model_id":"m","deployment_name":"d"}]}`, VerifyModelSyncCandidates},
		{"commit", `{"provider_id":"provider-a","proof_tokens":["token"]}`, CommitVerifiedModelSync},
	}
	for _, endpoint := range endpoints {
		for _, tt := range tests {
			t.Run(endpoint.name+"/"+tt.name, func(t *testing.T) {
				deps, providers, models, factory := verifiedDeps()
				prober := &verifiedProber{}
				deps.ModelProber = prober
				req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(endpoint.body))
				if tt.contentType != "" {
					req.Header.Set("Content-Type", tt.contentType)
				}
				req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, &repository.User{ID: "user-a", TenantID: "tenant-a"}))
				rec := httptest.NewRecorder()
				endpoint.get(deps)(rec, req)
				if rec.Code != http.StatusUnsupportedMediaType || !strings.Contains(rec.Body.String(), "unsupported_media_type") {
					t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
				}
				if providers.getCredentialCalls.Load() != 0 || factory.calls.Load() != 0 || models.listCalls.Load() != 0 || models.replaceCalls.Load() != 0 || len(prober.snapshot()) != 0 {
					t.Fatalf("dependencies reached: credential=%d catalog=%d list=%d replace=%d probes=%d", providers.getCredentialCalls.Load(), factory.calls.Load(), models.listCalls.Load(), models.replaceCalls.Load(), len(prober.snapshot()))
				}
			})
		}
	}
}

func TestPreviewVerifiedModelSyncFiltersObjectsAndDirtyExistingDeployments(t *testing.T) {
	deps, _, models, factory := verifiedDeps()
	factory.client = &MockCatalogClient{Models: []types.ProviderCatalogModel{
		{ID: "non-model", Object: "assistant"},
		{ID: "dirty-space", Object: "model"},
		{ID: "dirty-control", Object: "model"},
		{ID: "dirty-long", Object: "model"},
		{ID: "clean", Object: "model"},
	}}
	models.Models = map[string]*repository.Model{
		"space":   {ID: "space", ProviderID: "provider-a", ModelName: "dirty-space", UpstreamModelID: " dirty-deploy ", Status: "active"},
		"control": {ID: "control", ProviderID: "provider-a", ModelName: "dirty-control", UpstreamModelID: "dirty\ndeploy", Status: "active"},
		"long":    {ID: "long", ProviderID: "provider-a", ModelName: "dirty-long", UpstreamModelID: strings.Repeat("d", modelSyncFieldMaxRunes+1), Status: "active"},
		"clean":   {ID: "clean", ProviderID: "provider-a", ModelName: "clean", UpstreamModelID: "clean-deploy", Status: "active"},
	}
	rec := verifiedRequest(t, PreviewVerifiedModelSync(deps), ModelSyncPreviewRequest{ProviderID: "provider-a"}, "")
	got := verifiedDecode[ModelSyncPreviewResponse](t, rec)
	if rec.Code != http.StatusOK || len(got.Candidates) != 4 {
		t.Fatalf("status=%d candidates=%#v", rec.Code, got.Candidates)
	}
	for _, candidate := range got.Candidates {
		wantDeployment := candidate.CatalogModelID
		if candidate.CatalogModelID == "clean" {
			wantDeployment = "clean-deploy"
		}
		if candidate.DeploymentName != wantDeployment {
			t.Fatalf("candidate=%#v want deployment=%q", candidate, wantDeployment)
		}
		if _, err := canonicalVerifyItems([]ModelSyncVerifyItem{{CatalogModelID: candidate.CatalogModelID, DeploymentName: candidate.DeploymentName}}); err != nil {
			t.Fatalf("preview candidate is not verifiable: %#v err=%v", candidate, err)
		}
	}
}

func TestPreviewVerifiedModelSyncCapsCatalogCandidates(t *testing.T) {
	deps, _, _, factory := verifiedDeps()
	items := make([]types.ProviderCatalogModel, 2001)
	for i := range items {
		items[i] = types.ProviderCatalogModel{ID: fmt.Sprintf("model-%04d", i), Object: "model"}
	}
	factory.client = &MockCatalogClient{Models: items}
	rec := verifiedRequest(t, PreviewVerifiedModelSync(deps), ModelSyncPreviewRequest{ProviderID: "provider-a"}, "")
	got := verifiedDecode[ModelSyncPreviewResponse](t, rec)
	if rec.Code != http.StatusOK || len(got.Candidates) != 2000 || !got.CatalogTruncated || got.Candidates == nil {
		t.Fatalf("status=%d count=%d truncated=%v", rec.Code, len(got.Candidates), got.CatalogTruncated)
	}
}

func TestCommitVerifiedModelSyncDoesNotReadOrDecryptCredential(t *testing.T) {
	deps, providers, models, _ := verifiedDeps()
	providers.panicOnGetCredential = true
	providers.Credentials["provider-a"].SecretCiphertext = "enc:v1:not-decryptable"
	claim := verifiedModelSyncTestClaim("catalog", "deployment", "proof-credential", time.Now().Add(time.Minute).Unix())
	token, err := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
	if err != nil {
		t.Fatal(err)
	}
	var rec *httptest.ResponseRecorder
	var panicValue interface{}
	func() {
		defer func() { panicValue = recover() }()
		rec = verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{token}}, "")
	}()
	if panicValue != nil {
		t.Fatalf("commit read credential: %v", panicValue)
	}
	if rec.Code != http.StatusOK || providers.getCredentialCalls.Load() != 0 || len(models.ReplaceCalls) != 1 || models.ReplaceCalls[0].ExpectedCredentialID != "proof-credential" {
		t.Fatalf("status=%d credential calls=%d replace=%#v body=%s", rec.Code, providers.getCredentialCalls.Load(), models.ReplaceCalls, rec.Body.String())
	}
}

func TestCommitVerifiedModelSyncReturnsConflictForCredentialSnapshotMismatch(t *testing.T) {
	deps, _, models, _ := verifiedDeps()
	base := verifiedModelSyncTestClaim("one", "one", "cred-one", time.Now().Add(time.Minute).Unix())
	other := base
	other.CatalogID, other.DeploymentName, other.CredentialID = "two", "two", "cred-two"
	firstToken, _ := sealModelSyncClaim(modelSyncTokenTestSecret, base)
	secondToken, _ := sealModelSyncClaim(modelSyncTokenTestSecret, other)
	rec := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{firstToken, secondToken}}, "")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "sync_conflict") || models.replaceCalls.Load() != 0 {
		t.Fatalf("status=%d replace=%d body=%s", rec.Code, models.replaceCalls.Load(), rec.Body.String())
	}
}

func TestCommitVerifiedModelSyncUsesTypedRepositoryConflict(t *testing.T) {
	claim := verifiedModelSyncTestClaim("catalog", "deployment", "proof-credential", time.Now().Add(time.Minute).Unix())
	token, _ := sealModelSyncClaim(modelSyncTokenTestSecret, claim)
	tests := []struct {
		name string
		err  error
		want int
	}{
		{"typed conflict", fmt.Errorf("rotated: %w", repository.ErrVerifiedModelSyncConflict), http.StatusConflict},
		{"misleading ordinary error", errors.New("duplicate connection failure sensitive"), http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _, models, _ := verifiedDeps()
			models.ReplaceError = tt.err
			rec := verifiedRequest(t, CommitVerifiedModelSync(deps), ModelSyncCommitRequest{ProviderID: "provider-a", ProofTokens: []string{token}}, "")
			if rec.Code != tt.want || strings.Contains(rec.Body.String(), "sensitive") {
				t.Fatalf("status=%d want=%d body=%s", rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestModelSyncVerifyGateZeroValueBusyCapacityAndRelease(t *testing.T) {
	var gate ModelSyncVerifyGate
	release, result := gate.acquire("tenant", "provider")
	if result != modelSyncGateAcquired || release == nil {
		t.Fatalf("zero value acquire result=%v", result)
	}
	if _, busy := gate.acquire("tenant", "provider"); busy != modelSyncGateBusy {
		t.Fatalf("same provider result=%v", busy)
	}
	release()
	releaseAgain, result := gate.acquire("tenant", "provider")
	if result != modelSyncGateAcquired {
		t.Fatalf("release did not delete entry: %v", result)
	}
	releaseAgain()

	var capacityGate ModelSyncVerifyGate
	releases := make([]func(), 0, modelSyncGateMaxActive)
	for i := 0; i < modelSyncGateMaxActive; i++ {
		release, result := capacityGate.acquire("tenant", fmt.Sprintf("provider-%d", i))
		if result != modelSyncGateAcquired {
			t.Fatalf("fill %d result=%v", i, result)
		}
		releases = append(releases, release)
	}
	if _, result := capacityGate.acquire("tenant", "overflow"); result != modelSyncGateCapacity {
		t.Fatalf("capacity result=%v", result)
	}
	for _, release := range releases {
		release()
	}
}

func TestVerifyModelSyncCandidatesReturnsCapacityUnavailable(t *testing.T) {
	deps, _, _, _ := verifiedDeps()
	var gate ModelSyncVerifyGate
	deps.ModelSyncVerifyGate = &gate
	releases := make([]func(), 0, modelSyncGateMaxActive)
	for i := 0; i < modelSyncGateMaxActive; i++ {
		release, result := gate.acquire("other-tenant", fmt.Sprintf("provider-%d", i))
		if result != modelSyncGateAcquired {
			t.Fatalf("fill %d result=%v", i, result)
		}
		releases = append(releases, release)
	}
	defer func() {
		for _, release := range releases {
			release()
		}
	}()

	prober := &verifiedProber{}
	deps.ModelProber = prober
	rec := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: []ModelSyncVerifyItem{{"catalog", "deployment", nil}}}, "")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "verification_capacity_exceeded") || len(prober.snapshot()) != 0 {
		t.Fatalf("status=%d probes=%d body=%s", rec.Code, len(prober.snapshot()), rec.Body.String())
	}
}

func TestVerifyModelSyncCandidatesRecoversProberPanicAndReleasesGate(t *testing.T) {
	deps, _, _, _ := verifiedDeps()
	deps.ModelProber = panicModelProber{}
	var rec *httptest.ResponseRecorder
	var panicValue interface{}
	func() {
		defer func() { panicValue = recover() }()
		rec = verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: []ModelSyncVerifyItem{{"catalog", "edited-deployment", nil}}}, "")
	}()
	if panicValue != nil {
		t.Fatalf("prober panic escaped handler: %v", panicValue)
	}
	got := verifiedDecode[ModelSyncVerifyResponse](t, rec)
	if rec.Code != http.StatusOK || len(got.Results) != 1 || got.Results[0].Status != "failed" || got.Results[0].ErrorKind != catalog.ModelProbeErrorUpstream || got.Results[0].ProofToken != "" {
		t.Fatalf("status=%d response=%#v", rec.Code, got)
	}
	for _, secret := range []string{"api-key-secret", "edited-deployment", "panic contains"} {
		if strings.Contains(got.Results[0].Message, secret) {
			t.Fatalf("panic message leaked %q: %s", secret, got.Results[0].Message)
		}
	}
	deps.ModelProber = &verifiedProber{}
	next := verifiedRequest(t, VerifyModelSyncCandidates(deps), ModelSyncVerifyRequest{ProviderID: "provider-a", Items: []ModelSyncVerifyItem{{"next", "next", nil}}}, "")
	if next.Code != http.StatusOK {
		t.Fatalf("gate not released after panic: status=%d body=%s", next.Code, next.Body.String())
	}
}

func (repo *verifiedAuditRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, repo.Get, keys)
}
