package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelrouting"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type modelRoutingAuditRepo struct{ operations []*repository.AuditOperation }

func (m *modelRoutingAuditRepo) Get(context.Context, string) (*repository.SystemSetting, error) {
	return nil, nil
}
func (m *modelRoutingAuditRepo) GetAll(context.Context) ([]*repository.SystemSetting, error) {
	return nil, nil
}
func (m *modelRoutingAuditRepo) Set(context.Context, string, string) error            { return nil }
func (m *modelRoutingAuditRepo) SetMultiple(context.Context, map[string]string) error { return nil }
func (m *modelRoutingAuditRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	m.operations = append(m.operations, op)
	return nil
}
func (m *modelRoutingAuditRepo) ListAuditOperations(context.Context, int, int, string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}
func (m *modelRoutingAuditRepo) GetBool(context.Context, string) (bool, error) { return false, nil }

func modelRoutingRequest(method, target, body string, user *repository.User) *http.Request {
	if user != nil && body != "" {
		body = testRouteRefBody(body, user.TenantID)
	}
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if user != nil {
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
	}
	return req
}

func testRouteRefBody(body, tenantID string) string {
	var value any
	if json.Unmarshal([]byte(body), &value) != nil {
		return body
	}
	var rewrite func(any)
	rewrite = func(node any) {
		switch typed := node.(type) {
		case map[string]any:
			if id, ok := typed["provider_id"].(string); ok {
				delete(typed, "provider_id")
				typed["route_ref"] = modelRoutingRouteRef(tenantID, id)
			}
			if id, ok := typed["fixed_provider_id"].(string); ok {
				delete(typed, "fixed_provider_id")
				typed["fixed_route_ref"] = modelRoutingRouteRef(tenantID, id)
			}
			for _, child := range typed {
				rewrite(child)
			}
		case []any:
			for _, child := range typed {
				rewrite(child)
			}
		}
	}
	rewrite(value)
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func TestModelRoutingRouteRefsAreTenantBoundAndResponsesAreOpaque(t *testing.T) {
	tenantA := "tenant_a"
	providerA := &repository.Provider{ID: "secret-provider-a", TenantID: tenantA, Name: "主线路", Status: "active", HasCredential: true}
	providerB := &repository.Provider{ID: "secret-provider-b", TenantID: "tenant_b", Name: "外租户", Status: "active", HasCredential: true}
	deps := &Dependencies{ProviderRepo: &MockProviderRepository{Providers: map[string]*repository.Provider{providerA.ID: providerA, providerB.ID: providerB}}}
	user := &repository.User{TenantID: tenantA, Role: "tenant_owner"}
	w := httptest.NewRecorder()
	ListModelRoutingRoutes(deps)(w, modelRoutingRequest(http.MethodGet, "/admin/v1/model-routing/routes", "", user))
	if w.Code != http.StatusOK {
		t.Fatalf("routes status=%d body=%s", w.Code, w.Body.String())
	}
	for _, forbidden := range []string{"provider_id", "secret-provider-a", "secret-provider-b", "credential"} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("route response leaked %q: %s", forbidden, w.Body.String())
		}
	}
	foreignRef := modelRoutingRouteRef("tenant_b", providerB.ID)
	body := `{"config":{"strategy":"priority","cost_basis":"none","providers":[{"route_ref":"` + foreignRef + `","enabled":true,"priority":1}]}}`
	w = httptest.NewRecorder()
	PutModelRoutingDefault(deps)(w, modelRoutingRequest(http.MethodPut, "/admin/v1/model-routing/default", body, user))
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "route_not_accessible") {
		t.Fatalf("foreign ref status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestModelRoutingPublicConfigHidesPurchaseAmountsFromReadOnlyRoles(t *testing.T) {
	provider := &repository.Provider{ID: "db-provider-secret", TenantID: "tenant-a", Name: "线路甲", Status: "active", HasCredential: true}
	routes := modelRoutingRouteMap{byRef: map[string]*repository.Provider{modelRoutingRouteRef(provider.TenantID, provider.ID): provider}}
	internal := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveBalanced, CostBasis: modelrouting.CostActual, Providers: []modelrouting.ProviderRule{{ProviderID: provider.ID, Enabled: true, ActualCost: &modelrouting.TokenPrice{Currency: "CNY", InputPerMillion: 1.2, OutputPerMillion: 3.4}}}}

	readOnly, err := routes.publicConfig(internal, false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(readOnly)
	for _, forbidden := range []string{"provider_id", "fixed_provider_id", "db-provider-secret", "input_per_million", "output_per_million", "1.2", "3.4"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("read-only DTO leaked %q: %s", forbidden, encoded)
		}
	}
	if !bytes.Contains(encoded, []byte(`"cost_configured":true`)) {
		t.Fatalf("read-only DTO lost configured state: %s", encoded)
	}

	writer, err := routes.publicConfig(internal, true)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip, err := routes.internalConfig(writer)
	if err != nil {
		t.Fatal(err)
	}
	if roundTrip.Providers[0].ProviderID != provider.ID || roundTrip.Providers[0].ActualCost == nil || roundTrip.Providers[0].ActualCost.InputPerMillion != 1.2 {
		t.Fatalf("writer round trip mismatch: %#v", roundTrip)
	}
}

func TestModelRoutingRejectsUnauthenticatedAndMalformedRequests(t *testing.T) {
	deps := &Dependencies{}
	w := httptest.NewRecorder()
	PutModelRoutingDefault(deps)(w, modelRoutingRequest(http.MethodPut, "/admin/v1/model-routing/default", `{}`, nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status=%d body=%s", w.Code, w.Body.String())
	}

	user := &repository.User{ID: "u1", TenantID: "tenant_a"}
	for name, body := range map[string]string{
		"negative version": `{"expected_version":-1,"config":{}}`,
		"unknown field":    `{"expected_version":0,"unknown":true,"config":{}}`,
		"two objects":      `{"expected_version":0,"config":{}} {}`,
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			PutModelRoutingDefault(deps)(w, modelRoutingRequest(http.MethodPut, "/admin/v1/model-routing/default", body, user))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestPutModelRoutingRejectsBodyModelNameBeforeRepositoryAccess(t *testing.T) {
	user := &repository.User{ID: "u1", TenantID: "tenant_a"}
	providers := &MockProviderRepository{Providers: map[string]*repository.Provider{
		"p1": {ID: "p1", TenantID: "tenant_a", Name: "Alpha", Status: "active", HasCredential: true},
	}}
	models := &MockModelRepository{ModelsByProviderAndName: map[string]*repository.Model{
		"p1::org/model-x": {ProviderID: "p1", ModelName: "org/model-x", Status: "active"},
	}}
	deps := &Dependencies{ProviderRepo: providers, ModelRepo: models}

	defaultBody := `{"model_name":"org/model-x","config":{"strategy":"priority","cost_basis":"none","providers":[{"provider_id":"p1","enabled":true,"priority":1}]}}`
	w := httptest.NewRecorder()
	PutModelRoutingDefault(deps)(w, modelRoutingRequest(http.MethodPut, "/admin/v1/model-routing/default", defaultBody, user))
	if w.Code != http.StatusBadRequest {
		t.Errorf("default accepted body model_name: status=%d body=%s", w.Code, w.Body.String())
	}

	overrideBody := `{"model_name":"other/model","config":{"strategy":"fixed","cost_basis":"none","fixed_provider_id":"p1","providers":[{"provider_id":"p1","enabled":true}]}}`
	router := chi.NewRouter()
	router.Put("/models/{model_name}", PutModelRoutingOverride(deps))
	router.Put("/models/*", PutModelRoutingOverride(deps))
	w = httptest.NewRecorder()
	router.ServeHTTP(w, modelRoutingRequest(http.MethodPut, "/models/org/model-x", overrideBody, user))
	if w.Code != http.StatusBadRequest {
		t.Errorf("override accepted conflicting body model_name: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestModelRoutingProviderValidationDoesNotRevealForeignProviders(t *testing.T) {
	user := &repository.User{ID: "u1", TenantID: "tenant_a"}
	cfg := func(provider string) string {
		return `{"expected_version":0,"config":{"strategy":"priority","cost_basis":"none","providers":[{"provider_id":"` + provider + `","enabled":true,"priority":1,"weight":0}]}}`
	}
	cases := []struct {
		name     string
		provider *repository.Provider
		want     int
		code     string
	}{
		{"foreign", &repository.Provider{ID: "p", TenantID: "tenant_b", Status: "active", HasCredential: true}, 403, "route_not_accessible"},
		{"inactive", &repository.Provider{ID: "p", TenantID: "tenant_a", Status: "disabled", HasCredential: true}, 400, "provider_unavailable"},
		{"no credential", &repository.Provider{ID: "p", TenantID: "tenant_a", Status: "active", HasCredential: false}, 400, "provider_unavailable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := &Dependencies{ProviderRepo: &MockProviderRepository{Providers: map[string]*repository.Provider{"p": tc.provider}}}
			w := httptest.NewRecorder()
			PutModelRoutingDefault(deps)(w, modelRoutingRequest(http.MethodPut, "/admin/v1/model-routing/default", cfg("p"), user))
			if w.Code != tc.want || !strings.Contains(w.Body.String(), tc.code) {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestValidateModelRoutingChecksEveryOverrideModelWithoutWriting(t *testing.T) {
	user := &repository.User{ID: "u1", TenantID: "tenant_a"}
	providers := &MockProviderRepository{Providers: map[string]*repository.Provider{
		"p1": {ID: "p1", TenantID: "tenant_a", Name: "Alpha", Status: "active", HasCredential: true},
		"p2": {ID: "p2", TenantID: "tenant_a", Name: "Beta", Status: "active", HasCredential: true},
	}}
	models := &MockModelRepository{ModelsByProviderAndName: map[string]*repository.Model{
		"p1::org/model-x": {ProviderID: "p1", ModelName: "org/model-x", Status: "active"},
	}}
	deps := &Dependencies{ProviderRepo: providers, ModelRepo: models}
	body := `{"model_name":"org/model-x","config":{"strategy":"fixed","cost_basis":"none","fixed_provider_id":"p2","providers":[{"provider_id":"p1","enabled":true},{"provider_id":"p2","enabled":true}]}}`
	w := httptest.NewRecorder()
	ValidateModelRouting(deps)(w, modelRoutingRequest(http.MethodPost, "/admin/v1/model-routing/validate", body, user))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "provider_model_unavailable") {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestModelRoutingOverviewReportsEnabledStaleOverridesWithoutFailing(t *testing.T) {
	tenantID := "tenant_a"
	routes := modelRoutingRouteMap{byRef: map[string]*repository.Provider{}}
	resp := modelRoutingOverviewDTO{ModelExceptions: make([]modelRoutingExceptionDTO, 0, 1)}
	overrides := []repository.ModelRoutingPolicy{{
		ScopeRef:      "stale-model",
		Enabled:       true,
		ConfigVersion: 7,
		Config: modelrouting.Config{Strategy: modelrouting.StrategyPriority, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
			{ProviderID: "deleted-provider", Enabled: true, Priority: 1},
		}},
	}}

	appendModelRoutingExceptions(&resp, routes, overrides, true)
	if len(resp.ModelExceptions) != 1 {
		t.Fatalf("exceptions=%d want 1: %#v", len(resp.ModelExceptions), resp.ModelExceptions)
	}
	got := resp.ModelExceptions[0]
	if got.ModelName != "stale-model" || !got.Invalid || got.InvalidReason != "configured_route_removed" || got.ConfigVersion != 7 || len(got.Config.Providers) != 0 {
		t.Fatalf("stale exception not reported safely: %#v tenant=%s", got, tenantID)
	}
}

func TestModelRoutingOverviewReportsStaleDefaultWithoutLeakingProvider(t *testing.T) {
	routes := modelRoutingRouteMap{byRef: map[string]*repository.Provider{}}
	policy := &repository.ModelRoutingPolicy{
		Enabled:       true,
		ConfigVersion: 9,
		Config: modelrouting.Config{
			Strategy:        modelrouting.StrategyFixed,
			CostBasis:       modelrouting.CostNone,
			FixedProviderID: "deleted-provider-sensitive-id",
			Providers:       []modelrouting.ProviderRule{{ProviderID: "deleted-provider-sensitive-id", Enabled: true, Priority: 1}},
		},
	}

	got := modelRoutingDefaultDTOForPolicy(policy, routes, true)
	if got == nil || !got.Invalid || got.InvalidReason != "configured_route_removed" || got.ConfigVersion != 9 || !got.Enabled {
		t.Fatalf("stale default was not reported safely: %#v", got)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"deleted-provider-sensitive-id", "provider_id", "fixed_provider_id", "route_ref", "display_name"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("stale default leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestModelRoutingOverviewTreatsDisabledOrCredentiallessDefaultAsInvalid(t *testing.T) {
	for _, provider := range []*repository.Provider{
		{ID: "provider-unavailable", TenantID: "tenant-a", Status: "disabled", HasCredential: true},
		{ID: "provider-unavailable", TenantID: "tenant-a", Status: "active", HasCredential: false},
	} {
		routes := modelRoutingRouteMap{byRef: map[string]*repository.Provider{modelRoutingRouteRef(provider.TenantID, provider.ID): provider}}
		policy := &repository.ModelRoutingPolicy{Enabled: true, ConfigVersion: 3, Config: modelrouting.Config{Strategy: modelrouting.StrategyPriority, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{{ProviderID: provider.ID, Enabled: true, Priority: 1}}}}
		got := modelRoutingDefaultDTOForPolicy(policy, routes, true)
		if got == nil || !got.Invalid || got.InvalidReason != "configured_route_removed" || len(got.Config.Providers) != 0 {
			t.Fatalf("unavailable provider was exposed as a valid default: %#v", got)
		}
	}
}

func TestModelRoutingWriteRaceReturnsStableUnavailableInsteadOf500(t *testing.T) {
	recorder := httptest.NewRecorder()
	if handleModelRoutingWriteError(recorder, repository.ErrModelRouteUnavailable) {
		t.Fatal("unavailable write error was treated as success")
	}
	if recorder.Code != http.StatusConflict || !strings.Contains(recorder.Body.String(), "model_route_unavailable") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestModelRoutingOverviewSkipsDisabledStaleOverrides(t *testing.T) {
	tenantID := "tenant_a"
	provider := &repository.Provider{ID: "active-provider", TenantID: tenantID, Name: "Alpha", Status: "active", HasCredential: true}
	routes := modelRoutingRouteMap{byRef: map[string]*repository.Provider{modelRoutingRouteRef(tenantID, provider.ID): provider}}
	resp := modelRoutingOverviewDTO{ModelExceptions: make([]modelRoutingExceptionDTO, 0, 2)}
	overrides := []repository.ModelRoutingPolicy{
		{
			ScopeRef: "stale-model",
			Enabled:  false,
			Config: modelrouting.Config{Strategy: modelrouting.StrategyPriority, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
				{ProviderID: "deleted-provider", Enabled: true, Priority: 1},
			}},
		},
		{
			ScopeRef: "active-model",
			Enabled:  true,
			Config: modelrouting.Config{Strategy: modelrouting.StrategyPriority, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
				{ProviderID: provider.ID, Enabled: true, Priority: 1},
			}},
		},
	}

	appendModelRoutingExceptions(&resp, routes, overrides, true)
	if len(resp.ModelExceptions) != 1 {
		t.Fatalf("exceptions=%d want 1: %#v", len(resp.ModelExceptions), resp.ModelExceptions)
	}
	if got := resp.ModelExceptions[0].ModelName; got != "active-model" {
		t.Fatalf("model exception=%q want active-model", got)
	}
}

func TestModelRoutingWriteReadDeleteAndSafeAudit(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is required for integration coverage")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for _, q := range []string{
		`INSERT INTO tenants(id,name,status) VALUES('mr_tenant','Routing Test','active') ON CONFLICT(id) DO NOTHING`,
		`INSERT INTO providers(id,tenant_id,name,provider_type,base_url,status) VALUES('mr_p1','mr_tenant','Alpha','openai','https://alpha.invalid','active'),('mr_p2','mr_tenant','Beta','openai','https://beta.invalid','active') ON CONFLICT(id) DO NOTHING`,
		`INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,status) VALUES('mr_c1','mr_p1','test','test-ciphertext','active'),('mr_c2','mr_p2','test','test-ciphertext','active') ON CONFLICT(id) DO UPDATE SET secret_ciphertext=EXCLUDED.secret_ciphertext,status='active'`,
		`INSERT INTO models(id,provider_id,model_name,status) VALUES('mr_m1','mr_p1','org/model-x','active'),('mr_m2','mr_p2','org/model-x','active') ON CONFLICT(id) DO NOTHING`,
		`INSERT INTO model_endpoint_capability_overrides(id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id) VALUES('mr_cap1','mr_tenant','mr_m1','chat','supported','routing test','mr_user'),('mr_cap2','mr_tenant','mr_m2','chat','supported','routing test','mr_user') ON CONFLICT(model_id,endpoint_type) DO UPDATE SET state='supported'`,
		`DELETE FROM routing_policies WHERE tenant_id='mr_tenant'`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	defer pool.Exec(ctx, `DELETE FROM routing_policies WHERE tenant_id='mr_tenant'`)

	audit := &modelRoutingAuditRepo{}
	providers := &MockProviderRepository{Providers: map[string]*repository.Provider{
		"mr_p1": {ID: "mr_p1", TenantID: "mr_tenant", Name: "Alpha", Status: "active", HasCredential: true},
		"mr_p2": {ID: "mr_p2", TenantID: "mr_tenant", Name: "Beta", Status: "active", HasCredential: true},
	}}
	models := &MockModelRepository{ModelsByProviderAndName: map[string]*repository.Model{
		"mr_p1::org/model-x": {ProviderID: "mr_p1", ModelName: "org/model-x", Status: "active"},
		"mr_p2::org/model-x": {ProviderID: "mr_p2", ModelName: "org/model-x", Status: "active"},
	}}
	deps := &Dependencies{ModelRoutingRepo: repository.NewModelRoutingRepository(pool), ProviderRepo: providers, ModelRepo: models, SystemRepo: audit}
	user := &repository.User{ID: "mr_user", TenantID: "mr_tenant"}
	router := chi.NewRouter()
	router.Put("/models/{model_name}", PutModelRoutingOverride(deps))
	router.Put("/models/*", PutModelRoutingOverride(deps))
	router.Delete("/models/{model_name}", DeleteModelRoutingOverride(deps))
	router.Delete("/models/*", DeleteModelRoutingOverride(deps))

	defaultWithModel := `{"model_name":"org/model-x","config":{"strategy":"priority","cost_basis":"none","providers":[{"provider_id":"mr_p1","enabled":true,"priority":1}]}}`
	w := httptest.NewRecorder()
	PutModelRoutingDefault(deps)(w, modelRoutingRequest(http.MethodPut, "/admin/v1/model-routing/default", defaultWithModel, user))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("default body model_name status=%d body=%s", w.Code, w.Body.String())
	}
	overrideConflict := `{"model_name":"other/model","config":{"strategy":"fixed","cost_basis":"none","fixed_provider_id":"mr_p1","providers":[{"provider_id":"mr_p1","enabled":true}]}}`
	w = httptest.NewRecorder()
	router.ServeHTTP(w, modelRoutingRequest(http.MethodPut, "/models/org/model-x", overrideConflict, user))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("override conflicting model_name status=%d body=%s", w.Code, w.Body.String())
	}
	var policyCount int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM routing_policies WHERE tenant_id='mr_tenant'`).Scan(&policyCount); err != nil || policyCount != 0 {
		t.Fatalf("rejected PUT wrote policies: count=%d err=%v", policyCount, err)
	}

	validateBody := `{"model_name":"org/model-x","config":{"strategy":"priority","cost_basis":"none","providers":[{"provider_id":"mr_p2","enabled":true,"priority":2},{"provider_id":"mr_p1","enabled":true,"priority":1}]}}`
	w = httptest.NewRecorder()
	ValidateModelRouting(deps)(w, modelRoutingRequest(http.MethodPost, "/admin/v1/model-routing/validate", validateBody, user))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"provider_names":["Alpha","Beta"]`) {
		t.Fatalf("validate status=%d body=%s", w.Code, w.Body.String())
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM routing_policies WHERE tenant_id='mr_tenant'`).Scan(&policyCount); err != nil || policyCount != 0 {
		t.Fatalf("validate wrote policies: count=%d err=%v", policyCount, err)
	}

	body := `{"expected_version":0,"config":{"strategy":"fixed","cost_basis":"actual","fixed_provider_id":"mr_p1","providers":[{"provider_id":"mr_p1","enabled":true,"actual_cost":{"currency":"CNY","input_per_million":1.2,"output_per_million":3.4}}]}}`
	w = httptest.NewRecorder()
	router.ServeHTTP(w, modelRoutingRequest(http.MethodPut, "/models/org/model-x", body, user))
	if w.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "tenant_id") || strings.Contains(w.Body.String(), "policy_id") {
		t.Fatalf("internal IDs leaked: %s", w.Body.String())
	}
	if _, err := pool.Exec(ctx, `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES('mr_legacy','mr_tenant','model','legacy-model','provider','canary','{}',TRUE,1,1)`); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	GetModelRouting(deps)(w, modelRoutingRequest(http.MethodGet, "/admin/v1/model-routing", "", user))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"model_name":"org/model-x"`) || !strings.Contains(w.Body.String(), `"model_name":"legacy-model"`) {
		t.Fatalf("overview status=%d body=%s", w.Code, w.Body.String())
	}
	for _, forbidden := range []string{"TenantID", "ScopeRef", "mr_legacy", `"tenant_id"`, `"policy_id"`} {
		if strings.Contains(w.Body.String(), forbidden) {
			t.Fatalf("overview leaked %q: %s", forbidden, w.Body.String())
		}
	}
	w = httptest.NewRecorder()
	SearchModelRoutingModels(deps)(w, modelRoutingRequest(http.MethodGet, "/admin/v1/model-routing/models?q=model&limit=5", "", user))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"model_name":"org/model-x"`) || !strings.Contains(w.Body.String(), `"route_count":2`) || !strings.Contains(w.Body.String(), `"provider_names":["Alpha","Beta"]`) {
		t.Fatalf("search status=%d body=%s", w.Code, w.Body.String())
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, modelRoutingRequest(http.MethodPut, "/models/org/model-x", body, user))
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "version_conflict") {
		t.Fatalf("conflict status=%d body=%s", w.Code, w.Body.String())
	}

	if len(audit.operations) != 1 {
		t.Fatalf("audit operations=%d", len(audit.operations))
	}
	detail, _ := json.Marshal(audit.operations[0].ActionDetail)
	for _, forbidden := range []string{"input_per_million", "output_per_million", "secret", "credential"} {
		if bytes.Contains(detail, []byte(forbidden)) {
			t.Fatalf("audit leaks %q: %s", forbidden, detail)
		}
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, modelRoutingRequest(http.MethodDelete, "/models/org/model-x", "", user))
	if w.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestDeleteModelRoutingDefaultRequiresAuthentication(t *testing.T) {
	w := httptest.NewRecorder()
	DeleteModelRoutingDefault(&Dependencies{})(w, modelRoutingRequest(http.MethodDelete, "/admin/v1/model-routing/default", "", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated delete status=%d body=%s", w.Code, w.Body.String())
	}
}

func (m *modelRoutingAuditRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, m.Get, keys)
}
