package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelrouting"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/packages/shared-go/testcontainer"
)

type modelRoutingFixture struct {
	db      *pgxpool.Pool
	tenantA string
	tenantB string
}

func setupModelRoutingTestDB(t *testing.T) *modelRoutingFixture {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	suffix := rpRandomSuffix()
	f := &modelRoutingFixture{db: db, tenantA: "tenant_mr_a_" + suffix, tenantB: "tenant_mr_b_" + suffix}
	for _, tenantID := range []string{f.tenantA, f.tenantB} {
		if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status) VALUES ($1, $1, 'cloud', 'active')`, tenantID); err != nil {
			db.Close()
			t.Fatalf("create tenant %s: %v", tenantID, err)
		}
	}
	t.Cleanup(func() {
		cleanupCtx := context.Background()
		_, _ = db.Exec(cleanupCtx, `DELETE FROM routing_policies WHERE tenant_id = ANY($1)`, []string{f.tenantA, f.tenantB})
		_, _ = db.Exec(cleanupCtx, `DELETE FROM provider_credentials WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = ANY($1))`, []string{f.tenantA, f.tenantB})
		_, _ = db.Exec(cleanupCtx, `DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = ANY($1))`, []string{f.tenantA, f.tenantB})
		_, _ = db.Exec(cleanupCtx, `DELETE FROM providers WHERE tenant_id = ANY($1)`, []string{f.tenantA, f.tenantB})
		_, _ = db.Exec(cleanupCtx, `DELETE FROM tenants WHERE id = ANY($1)`, []string{f.tenantA, f.tenantB})
		db.Close()
	})
	return f
}

func routingConfig(providerID string, strategy modelrouting.Strategy) modelrouting.Config {
	rule := modelrouting.ProviderRule{ProviderID: providerID, Enabled: true, Priority: 1, Weight: 100}
	cfg := modelrouting.Config{Strategy: strategy, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{rule}}
	if strategy == modelrouting.StrategyFixed {
		cfg.FixedProviderID = providerID
	}
	return cfg
}

func TestModelRoutingRepository_DefaultAndOverrideAreTenantScoped(t *testing.T) {
	f := setupModelRoutingTestDB(t)
	seedRoutingCandidate(t, f, f.tenantA, "provider-a", "shared-model")
	seedRoutingCandidate(t, f, f.tenantB, "provider-b", "shared-model")
	ctx := context.Background()
	repo := NewModelRoutingRepository(f.db)
	aDefault, err := repo.UpsertDefault(ctx, f.tenantA, 0, routingConfig("provider-a", modelrouting.StrategyPriority))
	if err != nil {
		t.Fatalf("create tenant A default: %v", err)
	}
	if aDefault.ConfigVersion != 1 || !strings.HasPrefix(aDefault.ID, "rpv2_") {
		t.Fatalf("unexpected created default: %+v", aDefault)
	}
	if _, err := repo.UpsertDefault(ctx, f.tenantB, 0, routingConfig("provider-b", modelrouting.StrategyWeighted)); err != nil {
		t.Fatalf("create tenant B default: %v", err)
	}
	if _, err := repo.UpsertOverride(ctx, f.tenantA, " shared-model ", 0, routingConfig("provider-a", modelrouting.StrategyFixed)); err != nil {
		t.Fatalf("create tenant A override: %v", err)
	}
	if _, err := repo.UpsertOverride(ctx, f.tenantB, "shared-model", 0, routingConfig("provider-b", modelrouting.StrategyFixed)); err != nil {
		t.Fatalf("create tenant B override: %v", err)
	}

	gotDefault, err := repo.GetDefault(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("get tenant A default: %v", err)
	}
	if gotDefault == nil || gotDefault.TenantID != f.tenantA || gotDefault.Config.Providers[0].ProviderID != "provider-a" {
		t.Fatalf("tenant A saw wrong default: %+v", gotDefault)
	}
	overrides, err := repo.ListOverrides(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("list tenant A overrides: %v", err)
	}
	if len(overrides) != 1 || overrides[0].TenantID != f.tenantA || overrides[0].ScopeRef != "shared-model" || overrides[0].Config.Providers[0].ProviderID != "provider-a" {
		t.Fatalf("tenant A saw wrong overrides: %+v", overrides)
	}
}

func TestModelRoutingRepository_OptimisticVersionRejectsLostUpdate(t *testing.T) {
	f := setupModelRoutingTestDB(t)
	seedRoutingCandidate(t, f, f.tenantA, "provider-a", "missing", "concurrent")
	seedRoutingCandidate(t, f, f.tenantA, "provider-a2", "candidate-a2")
	seedRoutingCandidate(t, f, f.tenantA, "stale", "candidate-stale")
	ctx := context.Background()
	repo := NewModelRoutingRepository(f.db)
	created, err := repo.UpsertDefault(ctx, f.tenantA, 0, routingConfig("provider-a", modelrouting.StrategyPriority))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	updated, err := repo.UpsertDefault(ctx, f.tenantA, created.ConfigVersion, routingConfig("provider-a2", modelrouting.StrategyPriority))
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.ConfigVersion != 2 {
		t.Fatalf("expected version 2, got %d", updated.ConfigVersion)
	}
	if _, err := repo.UpsertDefault(ctx, f.tenantA, 1, routingConfig("stale", modelrouting.StrategyPriority)); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("stale update error = %v", err)
	}
	if _, err := repo.UpsertOverride(ctx, f.tenantA, "missing", 7, routingConfig("provider-a", modelrouting.StrategyFixed)); !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("missing nonzero update error = %v", err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := repo.UpsertOverride(ctx, f.tenantA, "concurrent", 0, routingConfig("provider-a", modelrouting.StrategyFixed))
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	successes, conflicts := 0, 0
	for err := range errs {
		if err == nil {
			successes++
		} else if errors.Is(err, ErrVersionConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected concurrent create error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("concurrent create successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestModelRoutingRepository_DeleteOverrideIsTenantScoped(t *testing.T) {
	f := setupModelRoutingTestDB(t)
	seedRoutingCandidate(t, f, f.tenantB, "provider-b", "shared-model")
	ctx := context.Background()
	repo := NewModelRoutingRepository(f.db)
	if _, err := repo.UpsertOverride(ctx, f.tenantB, "shared-model", 0, routingConfig("provider-b", modelrouting.StrategyFixed)); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteOverride(ctx, f.tenantA, "shared-model"); err != nil {
		t.Fatalf("cross-tenant delete: %v", err)
	}
	got, err := repo.ListOverrides(ctx, f.tenantB)
	if err != nil || len(got) != 1 {
		t.Fatalf("tenant B override was deleted: got=%+v err=%v", got, err)
	}
}

func TestModelRoutingRepository_OverviewDoesNotListInheritedModels(t *testing.T) {
	f := setupModelRoutingTestDB(t)
	seedRoutingCandidate(t, f, f.tenantA, "provider-a", "explicit")
	ctx := context.Background()
	repo := NewModelRoutingRepository(f.db)
	if _, err := repo.UpsertDefault(ctx, f.tenantA, 0, routingConfig("provider-a", modelrouting.StrategyPriority)); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.UpsertOverride(ctx, f.tenantA, "explicit", 0, routingConfig("provider-a", modelrouting.StrategyFixed)); err != nil {
		t.Fatal(err)
	}
	insertRoute(t, f, f.tenantA, "p1", "inherited", true, true, true)
	insertRoute(t, f, f.tenantA, "p2", "inherited", true, true, true)
	overview, err := repo.Overview(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("overview: %v", err)
	}
	if overview.Default == nil || len(overview.Overrides) != 1 || overview.Overrides[0].ScopeRef != "explicit" || overview.MultiRouteModelCount != 1 {
		t.Fatalf("unexpected overview: %+v", overview)
	}
}

func TestModelRoutingRepository_SearchModelsFiltersAndAggregates(t *testing.T) {
	f := setupModelRoutingTestDB(t)
	ctx := context.Background()
	repo := NewModelRoutingRepository(f.db)
	insertRoute(t, f, f.tenantA, "p1", "alpha", true, true, true)
	insertRoute(t, f, f.tenantA, "p2", "alpha", true, true, true)
	insertRoute(t, f, f.tenantA, "p3", "alpha", true, true, true) // duplicate model row on same provider must not inflate count
	insertRoute(t, f, f.tenantA, "p3", "alpha", true, true, true)
	if _, err := f.db.Exec(ctx, `UPDATE providers SET name=CASE id WHEN $1 THEN '云线路乙' WHEN $2 THEN '云线路甲' WHEN $3 THEN '云线路甲' ELSE name END WHERE tenant_id=$4`, f.tenantA+"_p1", f.tenantA+"_p2", f.tenantA+"_p3", f.tenantA); err != nil {
		t.Fatal(err)
	}
	insertRoute(t, f, f.tenantA, "p4", "beta", true, true, true)
	insertRoute(t, f, f.tenantA, "p5", "inactive-model", true, false, true)
	insertRoute(t, f, f.tenantA, "p6", "inactive-model", true, true, true)
	insertRoute(t, f, f.tenantA, "p7", "inactive-provider", false, true, true)
	insertRoute(t, f, f.tenantA, "p8", "inactive-provider", true, true, true)
	insertRoute(t, f, f.tenantA, "p9", "no-credential", true, true, false)
	insertRoute(t, f, f.tenantA, "p10", "no-credential", true, true, true)
	insertRoute(t, f, f.tenantB, "other1", "alpha", true, true, true)
	got, err := repo.SearchModels(ctx, f.tenantA, "alp", 500)
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(got) != 1 || got[0].ModelName != "alpha" || got[0].RouteCount != 3 || !reflect.DeepEqual(got[0].ProviderNames, []string{"云线路乙", "云线路甲"}) {
		t.Fatalf("unexpected search result: %+v", got)
	}
	got, err = repo.SearchModels(ctx, f.tenantA, "", 1)
	if err != nil || len(got) != 1 || got[0].ModelName != "alpha" {
		t.Fatalf("limit/order result=%+v err=%v", got, err)
	}
}

func TestModelRoutingRepository_LegacyInventoryIsReadOnlyAndConservative(t *testing.T) {
	f := setupModelRoutingTestDB(t)
	ctx := context.Background()
	repo := NewModelRoutingRepository(f.db)
	insertRoute(t, f, f.tenantA, "legacy1", "legacy-model", true, true, true)
	insertRoute(t, f, f.tenantA, "legacy2", "legacy-model", true, true, true)
	insertRoute(t, f, f.tenantA, "wrong-model", "other-model", true, true, true)
	legacy1 := f.tenantA + "_legacy1"
	legacy2 := f.tenantA + "_legacy2"
	wrongModel := f.tenantA + "_wrong-model"
	insertLegacyPolicy(t, f, "ok", "model", "legacy-model", "provider", "fallback", fmt.Sprintf(`{"provider_chain":[%q,%q]}`, legacy1, legacy2))
	insertLegacyPolicy(t, f, "cross-model", "model", "legacy-model", "provider", "lb", fmt.Sprintf(`{"weighted_providers":[{"id":%q,"weight":50},{"id":%q,"weight":50}]}`, legacy1, wrongModel))
	insertLegacyPolicy(t, f, "model-layer", "model", "legacy-model", "model", "fallback", fmt.Sprintf(`{"provider_chain":[%q]}`, legacy1))
	insertLegacyPolicy(t, f, "unknown", "model", "legacy-model", "provider", "script", fmt.Sprintf(`{"provider_ids":[%q]}`, legacy1))
	insertLegacyPolicy(t, f, "empty", "model", "legacy-model", "provider", "canary", `{}`)
	var before int
	if err := f.db.QueryRow(ctx, `SELECT count(*) FROM routing_policies WHERE tenant_id=$1`, f.tenantA).Scan(&before); err != nil {
		t.Fatal(err)
	}
	reports, err := repo.LegacyInventory(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("inventory: %v", err)
	}
	if len(reports) != 5 {
		t.Fatalf("expected 5 reports, got %+v", reports)
	}
	byID := make(map[string]LegacyPolicyReport, len(reports))
	for _, report := range reports {
		byID[report.ID] = report
	}
	if !byID["legacy_ok"].Convertible || byID["legacy_ok"].Reason == "" {
		t.Fatalf("same-model policy should be convertible: %+v", byID["legacy_ok"])
	}
	for _, id := range []string{"legacy_cross-model", "legacy_model-layer", "legacy_unknown", "legacy_empty"} {
		if byID[id].Convertible || byID[id].Reason == "" {
			t.Fatalf("%s should require manual handling: %+v", id, byID[id])
		}
	}
	var after int
	if err := f.db.QueryRow(ctx, `SELECT count(*) FROM routing_policies WHERE tenant_id=$1`, f.tenantA).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("inventory wrote data: before=%d after=%d", before, after)
	}
}

func TestModelRoutingRepository_LegacyInventoryRequiresExactRuntimeConfigShapes(t *testing.T) {
	f := setupModelRoutingTestDB(t)
	ctx := context.Background()
	repo := NewModelRoutingRepository(f.db)
	insertRoute(t, f, f.tenantA, "shape1", "shape-model", true, true, true)
	insertRoute(t, f, f.tenantA, "shape2", "shape-model", true, true, true)
	provider1 := f.tenantA + "_shape1"
	provider2 := f.tenantA + "_shape2"

	valid := map[string]string{
		"fallback-valid": fmt.Sprintf(`{"provider_chain":[%q,%q]}`, provider1, provider2),
		"lb-valid":       fmt.Sprintf(`{"weighted_providers":[{"id":%q,"weight":60},{"id":%q,"weight":40}]}`, provider1, provider2),
		"lb-max-safe":    fmt.Sprintf(`{"weighted_providers":[{"id":%q,"weight":9007199254740991}]}`, provider1),
		"canary-valid":   fmt.Sprintf(`{"stable_provider":%q,"canary_provider":%q}`, provider1, provider2),
	}
	insertLegacyPolicy(t, f, "shape-fallback-valid", "model", "shape-model", "provider", "fallback", valid["fallback-valid"])
	insertLegacyPolicy(t, f, "shape-lb-valid", "model", "shape-model", "provider", "lb", valid["lb-valid"])
	insertLegacyPolicy(t, f, "shape-lb-max-safe", "model", "shape-model", "provider", "lb", valid["lb-max-safe"])
	insertLegacyPolicy(t, f, "shape-canary-valid", "model", "shape-model", "provider", "canary", valid["canary-valid"])

	malformed := []struct {
		id, strategy, config string
	}{
		{"fallback-missing", "fallback", `{}`},
		{"fallback-empty", "fallback", `{"provider_chain":[]}`},
		{"fallback-object", "fallback", fmt.Sprintf(`{"provider_chain":[{"id":%q}]}`, provider1)},
		{"fallback-number", "fallback", `{"provider_chain":[42]}`},
		{"fallback-blank", "fallback", `{"provider_chain":[" "]}`},
		{"fallback-whitespace", "fallback", fmt.Sprintf(`{"provider_chain":[" %s"]}`, provider1)},
		{"fallback-duplicate", "fallback", fmt.Sprintf(`{"provider_chain":[%q,%q]}`, provider1, provider1)},
		{"lb-missing", "lb", `{}`},
		{"lb-empty", "lb", `{"weighted_providers":[]}`},
		{"lb-string", "lb", fmt.Sprintf(`{"weighted_providers":[%q]}`, provider1)},
		{"lb-provider-id", "lb", fmt.Sprintf(`{"weighted_providers":[{"provider_id":%q,"weight":1}]}`, provider1)},
		{"lb-missing-weight", "lb", fmt.Sprintf(`{"weighted_providers":[{"id":%q}]}`, provider1)},
		{"lb-zero-weight", "lb", fmt.Sprintf(`{"weighted_providers":[{"id":%q,"weight":0}]}`, provider1)},
		{"lb-string-weight", "lb", fmt.Sprintf(`{"weighted_providers":[{"id":%q,"weight":"1"}]}`, provider1)},
		{"lb-whitespace-id", "lb", fmt.Sprintf(`{"weighted_providers":[{"id":"%s ","weight":1}]}`, provider1)},
		{"lb-duplicate", "lb", fmt.Sprintf(`{"weighted_providers":[{"id":%q,"weight":1},{"id":%q,"weight":2}]}`, provider1, provider1)},
		{"lb-fractional-weight", "lb", fmt.Sprintf(`{"weighted_providers":[{"id":%q,"weight":0.5}]}`, provider1)},
		{"lb-too-large-weight", "lb", fmt.Sprintf(`{"weighted_providers":[{"id":%q,"weight":9223372036854775808}]}`, provider1)},
		{"lb-above-float64-exact", "lb", fmt.Sprintf(`{"weighted_providers":[{"id":%q,"weight":9007199254740993}]}`, provider1)},
		{"lb-max-int64-weight", "lb", fmt.Sprintf(`{"weighted_providers":[{"id":%q,"weight":9223372036854775807}]}`, provider1)},
		{"canary-missing-stable", "canary", fmt.Sprintf(`{"canary_provider":%q}`, provider2)},
		{"canary-missing-canary", "canary", fmt.Sprintf(`{"stable_provider":%q}`, provider1)},
		{"canary-object", "canary", fmt.Sprintf(`{"stable_provider":{"id":%q},"canary_provider":%q}`, provider1, provider2)},
		{"canary-blank", "canary", fmt.Sprintf(`{"stable_provider":" ","canary_provider":%q}`, provider2)},
	}
	for _, testCase := range malformed {
		insertLegacyPolicy(t, f, "shape-"+testCase.id, "model", "shape-model", "provider", testCase.strategy, testCase.config)
	}

	reports, err := repo.LegacyInventory(ctx, f.tenantA)
	if err != nil {
		t.Fatalf("inventory must report malformed policies without failing: %v", err)
	}
	byID := make(map[string]LegacyPolicyReport, len(reports))
	for _, report := range reports {
		byID[report.ID] = report
	}
	for _, id := range []string{"fallback-valid", "lb-valid", "lb-max-safe"} {
		report := byID["legacy_shape-"+id]
		if !report.Convertible || report.Reason == "" {
			t.Errorf("%s should be convertible: %+v", id, report)
		}
	}
	canaryReport := byID["legacy_shape-canary-valid"]
	if canaryReport.Convertible || canaryReport.Reason != "canary routing requires manual migration" {
		t.Errorf("canary must always require manual migration: %+v", canaryReport)
	}
	for _, testCase := range malformed {
		report := byID["legacy_shape-"+testCase.id]
		if report.Convertible || report.Reason == "" {
			t.Errorf("malformed %s should be reported as non-convertible: %+v", testCase.id, report)
		}
	}
}

func TestModelRoutingRepository_JSONRoundTripAndInvalidJSONError(t *testing.T) {
	f := setupModelRoutingTestDB(t)
	seedRoutingCandidate(t, f, f.tenantA, "p1", "invalid-override")
	seedRoutingCandidate(t, f, f.tenantA, "p2", "candidate-p2")
	ctx := context.Background()
	repo := NewModelRoutingRepository(f.db)
	want := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveCustom, CustomOrder: []modelrouting.Objective{modelrouting.ObjectiveStability, modelrouting.ObjectiveLatency, modelrouting.ObjectiveCost}, CostBasis: modelrouting.CostRelative, Providers: []modelrouting.ProviderRule{{ProviderID: "p1", Enabled: true, RelativeCost: modelrouting.CostLow}, {ProviderID: "p2", Enabled: true, RelativeCost: modelrouting.CostHigh}}}
	if _, err := repo.UpsertDefault(ctx, f.tenantA, 0, want); err != nil {
		t.Fatalf("write config: %v", err)
	}
	got, err := repo.GetDefault(ctx, f.tenantA)
	if err != nil || got == nil || fmt.Sprintf("%#v", got.Config) != fmt.Sprintf("%#v", want) {
		t.Fatalf("round trip got=%#v err=%v want=%#v", got, err, want)
	}
	if _, err := f.db.Exec(ctx, `UPDATE routing_policies SET config_json='"broken"'::jsonb WHERE tenant_id=$1 AND schema_version=2 AND scope_type='tenant'`, f.tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetDefault(ctx, f.tenantA); err == nil || !strings.Contains(err.Error(), "config_json") {
		t.Fatalf("expected explicit config_json error, got %v", err)
	}
	if _, err := f.db.Exec(ctx, `UPDATE routing_policies SET config_json='{}'::jsonb WHERE tenant_id=$1 AND schema_version=2 AND scope_type='tenant'`, f.tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetDefault(ctx, f.tenantA); err == nil || !strings.Contains(err.Error(), "validate model routing config_json") {
		t.Fatalf("expected invalid default config error, got %v", err)
	}
	if _, err := repo.UpsertOverride(ctx, f.tenantA, "invalid-override", 0, routingConfig("p1", modelrouting.StrategyFixed)); err != nil {
		t.Fatalf("create override: %v", err)
	}
	if _, err := f.db.Exec(ctx, `UPDATE routing_policies SET config_json='{"strategy":"fixed","cost_basis":"bogus","fixed_provider_id":"p1","providers":[{"provider_id":"p1","enabled":true}]}'::jsonb WHERE tenant_id=$1 AND schema_version=2 AND scope_type='model'`, f.tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ListOverrides(ctx, f.tenantA); err == nil || !strings.Contains(err.Error(), "validate model routing config_json") {
		t.Fatalf("expected invalid override config error, got %v", err)
	}
}

func TestModelRoutingRepository_StrategyColumnMustMatchConfigJSON(t *testing.T) {
	f := setupModelRoutingTestDB(t)
	seedRoutingCandidate(t, f, f.tenantA, "p1", "drift-model")
	ctx := context.Background()
	repo := NewModelRoutingRepository(f.db)
	if _, err := repo.UpsertDefault(ctx, f.tenantA, 0, routingConfig("p1", modelrouting.StrategyPriority)); err != nil {
		t.Fatalf("create default: %v", err)
	}
	if _, err := f.db.Exec(ctx, `UPDATE routing_policies SET strategy='weighted' WHERE tenant_id=$1 AND schema_version=2 AND scope_type='tenant'`, f.tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.GetDefault(ctx, f.tenantA); err == nil || !strings.Contains(err.Error(), "strategy column does not match config_json") {
		t.Fatalf("expected default strategy drift error, got %v", err)
	}
	if _, err := repo.UpsertOverride(ctx, f.tenantA, "drift-model", 0, routingConfig("p1", modelrouting.StrategyFixed)); err != nil {
		t.Fatalf("create override: %v", err)
	}
	if _, err := f.db.Exec(ctx, `UPDATE routing_policies SET strategy='priority' WHERE tenant_id=$1 AND schema_version=2 AND scope_type='model'`, f.tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ListOverrides(ctx, f.tenantA); err == nil || !strings.Contains(err.Error(), "strategy column does not match config_json") {
		t.Fatalf("expected override strategy drift error, got %v", err)
	}
}

// seedRoutingCandidate supplies the real write-path eligibility prerequisites.
// Each test chooses its models so inventory counts remain part of its assertions.
func seedRoutingCandidate(t *testing.T, f *modelRoutingFixture, tenantID, providerID string, modelNames ...string) {
	t.Helper()
	ctx := context.Background()
	if _, err := f.db.Exec(ctx, `INSERT INTO providers (id,tenant_id,name,provider_type,status) VALUES ($1,$2,$1,'openai','active')`, providerID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(ctx, `INSERT INTO provider_credentials (id,provider_id,credential_name,secret_ciphertext,status) VALUES ($1,$2,'test','synthetic-test-ciphertext','active')`, "cred_"+providerID, providerID); err != nil {
		t.Fatal(err)
	}
	for _, modelName := range modelNames {
		modelID := "model_" + rpRandomSuffix()
		if _, err := f.db.Exec(ctx, `INSERT INTO models (id,provider_id,model_name,status) VALUES ($1,$2,$3,'active')`, modelID, providerID, modelName); err != nil {
			t.Fatal(err)
		}
		if _, err := f.db.Exec(ctx, `INSERT INTO model_endpoint_capability_overrides (id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id) VALUES ($1,$2,$3,'chat','supported','routing test fixture','test')`, "cap_"+modelID, tenantID, modelID); err != nil {
			t.Fatal(err)
		}
	}
}

func insertRoute(t *testing.T, f *modelRoutingFixture, tenantID, providerSuffix, modelName string, providerActive, modelActive, credentialActive bool) {
	t.Helper()
	ctx := context.Background()
	providerID := tenantID + "_" + providerSuffix
	providerStatus, modelStatus, credentialStatus := "inactive", "inactive", "inactive"
	if providerActive {
		providerStatus = "active"
	}
	if modelActive {
		modelStatus = "active"
	}
	if credentialActive {
		credentialStatus = "active"
	}
	_, err := f.db.Exec(ctx, `INSERT INTO providers (id,tenant_id,name,provider_type,status) VALUES ($1,$2,$1,'openai',$3) ON CONFLICT (id) DO NOTHING`, providerID, tenantID, providerStatus)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.db.Exec(ctx, `INSERT INTO models (id,provider_id,model_name,status) VALUES ($1,$2,$3,$4)`, "model_"+rpRandomSuffix(), providerID, modelName, modelStatus)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.db.Exec(ctx, `INSERT INTO provider_credentials (id,provider_id,credential_name,status) VALUES ($1,$2,'test',$3) ON CONFLICT (id) DO NOTHING`, "cred_"+providerID, providerID, credentialStatus)
	if err != nil {
		t.Fatal(err)
	}
}

func insertLegacyPolicy(t *testing.T, f *modelRoutingFixture, suffix, scopeType, scopeRef, layer, strategy, config string) {
	t.Helper()
	_, err := f.db.Exec(context.Background(), `INSERT INTO routing_policies (id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,TRUE,1,1)`, "legacy_"+suffix, f.tenantA, scopeType, scopeRef, layer, strategy, config)
	if err != nil {
		t.Fatal(err)
	}
}

const (
	dockerCommandTimeout          = 30 * time.Second
	dockerPreflightTimeout        = 5 * time.Second
	dockerPreflightOverallTimeout = 10 * time.Second
	dockerReadinessTimeout        = 90 * time.Second
	dockerReadinessAttemptTimeout = 5 * time.Second
	dockerCleanupTimeout          = 30 * time.Second
)

type migration116DockerRunner func(context.Context, time.Duration, string, ...string) (string, error)

func runMigration116Docker(parent context.Context, timeout time.Duration, stdin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	output, err := cmd.CombinedOutput()
	trimmed := strings.TrimSpace(string(output))
	if ctx.Err() != nil {
		return trimmed, fmt.Errorf("docker %s timed out after %s: %w", strings.Join(args, " "), timeout, ctx.Err())
	}
	return trimmed, err
}

// reapOrphanTestContainers 在起临时容器前回收被杀掉的测试进程留下的容器（规则见 testcontainer.ReapOrphans）；
// 回收失败只记日志，不影响本次测试。
func reapOrphanTestContainers(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), dockerCleanupTimeout)
	defer cancel()
	removed, err := testcontainer.ReapOrphans(ctx, testcontainer.DockerRunner(dockerCleanupTimeout))
	if err != nil {
		t.Logf("reap orphan test containers: %v", err)
	}
	if len(removed) > 0 {
		t.Logf("reaped orphan test containers: %v", removed)
	}
}

func migration116DockerPreflight(
	ctx context.Context,
	lookPath func(string) (string, error),
	run migration116DockerRunner,
) error {
	if _, err := lookPath("docker"); err != nil {
		return fmt.Errorf("docker binary unavailable: %w", err)
	}
	if output, err := run(ctx, dockerPreflightTimeout, "", "info"); err != nil {
		return fmt.Errorf("docker daemon unavailable: %w: %s", err, output)
	}
	if output, err := run(ctx, dockerPreflightTimeout, "", "image", "inspect", "postgres:16-alpine"); err != nil {
		return fmt.Errorf("local postgres:16-alpine image unavailable: %w: %s", err, output)
	}
	return nil
}

func TestMigration116DockerCommandsAreContextBound(t *testing.T) {
	source := readRepoFile(t, "model_routing_test.go")
	unsafeCall := "exec.Command" + `("docker"`
	if strings.Contains(source, unsafeCall) {
		t.Fatal("migration 116 Docker commands must not run without context deadlines")
	}
	for _, required := range []string{
		"exec.CommandContext",
		"context.WithTimeout",
		"dockerReadinessTimeout",
		"dockerReadinessAttemptTimeout",
		"dockerCleanupTimeout",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("migration 116 Docker helper missing timeout mechanism %q", required)
		}
	}
	pullNever := "--pull=" + "never"
	if !strings.Contains(source, pullNever) {
		t.Fatal("migration 116 PostgreSQL container must forbid implicit image pulls")
	}
	labelFlag := "--" + "label"
	labelFilter := "label" + "="
	if !strings.Contains(source, labelFlag) || !strings.Contains(source, labelFilter) {
		t.Fatal("migration 116 cleanup must identify test containers by unique label")
	}
	unsafeNameCleanup := `"rm"` + `, "-f", container)`
	if strings.Contains(source, unsafeNameCleanup) {
		t.Fatal("migration 116 cleanup must not remove a container by unverified name")
	}
}

func TestMigration116DockerPreflightBlocksUnavailableEnvironment(t *testing.T) {
	tests := []struct {
		name          string
		lookPathError error
		failCommand   string
		wantCalls     int
	}{
		{name: "docker binary missing", lookPathError: errors.New("not found"), wantCalls: 0},
		{name: "docker daemon unavailable", failCommand: "info", wantCalls: 1},
		{name: "postgres image unavailable", failCommand: "image", wantCalls: 2},
		{name: "ready", wantCalls: 2},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			calls := make([][]string, 0, 2)
			lookPath := func(file string) (string, error) {
				if file != "docker" {
					t.Fatalf("unexpected binary lookup: %s", file)
				}
				if testCase.lookPathError != nil {
					return "", testCase.lookPathError
				}
				return "/usr/bin/docker", nil
			}
			runner := func(_ context.Context, _ time.Duration, _ string, args ...string) (string, error) {
				copied := append([]string(nil), args...)
				calls = append(calls, copied)
				if len(args) > 0 && args[0] == testCase.failCommand {
					return testCase.failCommand + " unavailable", errors.New("unavailable")
				}
				return "", nil
			}

			err := migration116DockerPreflight(context.Background(), lookPath, runner)
			if testCase.failCommand == "" && testCase.lookPathError == nil {
				if err != nil {
					t.Fatalf("preflight unexpectedly failed: %v", err)
				}
			} else if err == nil {
				t.Fatal("preflight must reject unavailable Docker environment")
			}
			if len(calls) != testCase.wantCalls {
				t.Fatalf("Docker calls=%d want=%d: %v", len(calls), testCase.wantCalls, calls)
			}
			for _, call := range calls {
				if len(call) > 0 && call[0] == "run" {
					t.Fatalf("preflight triggered docker run: %v", call)
				}
			}
		})
	}
}

func TestMigration116ExplicitModelRoutingConstraints(t *testing.T) {
	preflightCtx, cancelPreflight := context.WithTimeout(context.Background(), dockerPreflightOverallTimeout)
	defer cancelPreflight()
	if err := migration116DockerPreflight(preflightCtx, exec.LookPath, runMigration116Docker); err != nil {
		t.Skipf("real PostgreSQL migration test requires preloaded Docker environment: %v", err)
	}

	container := fmt.Sprintf("jjdguard-migration-116-%d", time.Now().UnixNano())
	runDocker := func(stdin string, args ...string) (string, error) {
		return runMigration116Docker(context.Background(), dockerCommandTimeout, stdin, args...)
	}
	testLabel := "jjdguard.migration116.test-id=" + container
	cleanupLabeledContainers := func() error {
		output, err := runMigration116Docker(context.Background(), dockerCleanupTimeout, "",
			"ps", "-aq", "--filter", "label="+testLabel)
		if err != nil {
			return fmt.Errorf("list labeled PostgreSQL containers: %w: %s", err, output)
		}
		for _, containerID := range strings.Fields(output) {
			removed, err := runMigration116Docker(context.Background(), dockerCleanupTimeout, "", "rm", "-fv", containerID)
			if err != nil {
				return fmt.Errorf("remove labeled PostgreSQL container %s: %w: %s", containerID, err, removed)
			}
		}
		return nil
	}
	reapOrphanTestContainers(t)
	runArgs := append([]string{"run", "--pull=never", "--rm", "-d", "--name", container,
		"--label", testLabel}, testcontainer.LabelArgs("migration-116")...)
	runArgs = append(runArgs, "-e", "POSTGRES_PASSWORD=test", "-e", "POSTGRES_DB=test", "postgres:16-alpine")
	if output, err := runDocker("", runArgs...); err != nil {
		cleanupErr := cleanupLabeledContainers()
		if cleanupErr != nil {
			t.Fatalf("start PostgreSQL container: %v: %s; cleanup after failed start: %v", err, output, cleanupErr)
		}
		t.Fatalf("start PostgreSQL container: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if err := cleanupLabeledContainers(); err != nil {
			t.Errorf("cleanup PostgreSQL test container: %v", err)
		}
	})

	readinessCtx, cancelReadiness := context.WithTimeout(context.Background(), dockerReadinessTimeout)
	defer cancelReadiness()
	ready := false
	var lastReadinessOutput string
	var lastReadinessErr error
	for !ready && readinessCtx.Err() == nil {
		lastReadinessOutput, lastReadinessErr = runMigration116Docker(readinessCtx, dockerReadinessAttemptTimeout, "",
			"exec", container, "psql", "-v", "ON_ERROR_STOP=1",
			"-U", "postgres", "-d", "test", "-tAc", "SELECT 1")
		if lastReadinessErr == nil {
			ready = true
			break
		}
		select {
		case <-readinessCtx.Done():
		case <-time.After(100 * time.Millisecond):
		}
	}
	if !ready {
		t.Fatalf("PostgreSQL container %s did not become ready within %s: last error: %v; output: %s",
			container, dockerReadinessTimeout, lastReadinessErr, lastReadinessOutput)
	}

	execSQL := func(sql string) string {
		t.Helper()
		output, err := runDocker("", "exec", container, "psql", "-v", "ON_ERROR_STOP=1",
			"-U", "postgres", "-d", "test", "-tAc", sql)
		if err != nil {
			t.Fatalf("execute SQL: %v: %s\nSQL: %s", err, output, sql)
		}
		return output
	}
	assertRejected := func(sql, constraint string) {
		t.Helper()
		output, err := runDocker("", "exec", container, "psql", "-v", "ON_ERROR_STOP=1",
			"-U", "postgres", "-d", "test", "-c", sql)
		if err == nil {
			t.Fatalf("expected PostgreSQL to reject SQL: %s", sql)
		}
		if constraint != "" && !strings.Contains(output, constraint) {
			t.Fatalf("expected rejection by %s, got: %s", constraint, output)
		}
	}

	execSQL(`
		CREATE TABLE tenants (id varchar(64) PRIMARY KEY);
		CREATE TABLE providers (
			id varchar(64) PRIMARY KEY,
			tenant_id varchar(64) NOT NULL REFERENCES tenants(id)
		);
		CREATE TABLE routing_policies (
			id varchar(64) PRIMARY KEY,
			tenant_id varchar(64) NOT NULL REFERENCES tenants(id),
			scope_type varchar(16) NOT NULL,
			scope_ref varchar(64),
			layer varchar(16) NOT NULL,
			enabled boolean NOT NULL DEFAULT true,
			schema_version smallint NOT NULL DEFAULT 1
		);
		INSERT INTO tenants (id) VALUES ('tenant-a'), ('tenant-b');
		INSERT INTO providers (id, tenant_id) VALUES
			('provider-a', 'tenant-a'), ('provider-b', 'tenant-b');
		INSERT INTO routing_policies
			(id, tenant_id, scope_type, scope_ref, layer, enabled, schema_version)
		VALUES
			('legacy-v1', 'tenant-a', 'tenant', NULL, 'model', false, 1),
			('legacy-v2', 'tenant-a', 'tenant', 'tenant-a', 'provider', false, 2);
	`)
	legacyBefore := execSQL(`
		SELECT string_agg(concat_ws('|', id, schema_version, scope_type,
			coalesce(scope_ref, '<null>'), layer, enabled), ',' ORDER BY id)
		FROM routing_policies WHERE schema_version IN (1, 2)
	`)

	migration, err := os.ReadFile("../../../../deploy/migrations/116_explicit_model_routing.sql")
	if err != nil {
		t.Fatalf("read migration 116: %v", err)
	}
	for run := 1; run <= 2; run++ {
		output, err := runDocker(string(migration), "exec", "-i", container, "psql",
			"-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "test")
		if err != nil {
			t.Fatalf("apply migration 116 run %d: %v: %s", run, err, output)
		}
	}

	legacyAfter := execSQL(`
		SELECT string_agg(concat_ws('|', id, schema_version, scope_type,
			coalesce(scope_ref, '<null>'), layer, enabled), ',' ORDER BY id)
		FROM routing_policies WHERE schema_version IN (1, 2)
	`)
	if legacyAfter != legacyBefore {
		t.Fatalf("migration rewrote v1/v2 policies: before=%q after=%q", legacyBefore, legacyAfter)
	}

	assertRejected(`INSERT INTO routing_policies (id,tenant_id,scope_type,scope_ref,layer,schema_version) VALUES ('bad-scope','tenant-a','tenant','model-a','provider',3)`, "chk_routing_v3_explicit_model")
	assertRejected(`INSERT INTO routing_policies (id,tenant_id,scope_type,scope_ref,layer,schema_version) VALUES ('bad-null','tenant-a','model',NULL,'provider',3)`, "chk_routing_v3_explicit_model")
	assertRejected(`INSERT INTO routing_policies (id,tenant_id,scope_type,scope_ref,layer,schema_version) VALUES ('bad-empty','tenant-a','model','   ','provider',3)`, "chk_routing_v3_explicit_model")
	assertRejected(`INSERT INTO routing_policies (id,tenant_id,scope_type,scope_ref,layer,schema_version) VALUES ('bad-layer','tenant-a','model','model-a','model',3)`, "chk_routing_v3_explicit_model")

	execSQL(`INSERT INTO routing_policies (id,tenant_id,scope_type,scope_ref,layer,schema_version) VALUES
		('route-a','tenant-a','model','shared-model','provider',3),
		('route-b','tenant-b','model','shared-model','provider',3)`)
	assertRejected(`INSERT INTO routing_policies (id,tenant_id,scope_type,scope_ref,layer,schema_version) VALUES ('route-a-duplicate','tenant-a','model','shared-model','provider',3)`, "uq_routing_v3_model")

	execSQL(`INSERT INTO model_route_baselines (tenant_id,model_name,provider_id,captured_from) VALUES ('tenant-a','model-a','provider-a','runtime')`)
	assertRejected(`INSERT INTO model_route_baselines (tenant_id,model_name,provider_id,captured_from) VALUES ('tenant-a','model-b','provider-b','runtime')`, "fk_model_route_baseline_provider")
	assertRejected(`INSERT INTO model_route_baselines (tenant_id,model_name,provider_id,captured_from) VALUES ('tenant-a','model-a','provider-a','runtime')`, "model_route_baselines_pkey")

	invalidDatabase := "migration116_invalid_v3"
	execSQL("CREATE DATABASE " + invalidDatabase)
	execInvalidSQL := func(sql string) string {
		t.Helper()
		output, err := runDocker("", "exec", container, "psql", "-v", "ON_ERROR_STOP=1",
			"-U", "postgres", "-d", invalidDatabase, "-tAc", sql)
		if err != nil {
			t.Fatalf("execute invalid-v3 database SQL: %v: %s\nSQL: %s", err, output, sql)
		}
		return output
	}
	applyInvalidMigration := func(name string, body []byte) (string, error) {
		t.Helper()
		output, err := runDocker(string(body), "exec", "-i", container, "psql",
			"-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", invalidDatabase)
		if err != nil {
			return output, fmt.Errorf("apply %s: %w", name, err)
		}
		return output, nil
	}

	execInvalidSQL(`
		CREATE TABLE tenants (id varchar(64) PRIMARY KEY);
		CREATE TABLE providers (
			id varchar(64) PRIMARY KEY,
			tenant_id varchar(64) NOT NULL REFERENCES tenants(id)
		);
		CREATE TABLE routing_policies (
			id varchar(64) PRIMARY KEY,
			tenant_id varchar(64) NOT NULL REFERENCES tenants(id),
			scope_type varchar(16) NOT NULL,
			scope_ref varchar(64),
			layer varchar(16) NOT NULL,
			strategy varchar(32) NOT NULL,
			config_json jsonb NOT NULL DEFAULT '{}',
			enabled boolean NOT NULL DEFAULT true,
			created_at timestamptz NOT NULL,
			updated_at timestamptz NOT NULL
		);
		CREATE TABLE request_logs (
			id text PRIMARY KEY,
			tenant_id text NOT NULL,
			created_at timestamptz NOT NULL,
			model_id text,
			provider_id text, agent_instance_id varchar(128));
	`)
	for _, migrationName := range []string{"114_model_routing_v2.sql", "115_request_logs_ttft.sql"} {
		body, err := os.ReadFile("../../../../deploy/migrations/" + migrationName)
		if err != nil {
			t.Fatalf("read %s: %v", migrationName, err)
		}
		if output, err := applyInvalidMigration(migrationName, body); err != nil {
			t.Fatalf("%v: %s", err, output)
		}
	}
	execInvalidSQL(`
		INSERT INTO tenants (id) VALUES ('tenant-invalid-v3');
		INSERT INTO providers (id, tenant_id) VALUES ('provider-invalid-v3', 'tenant-invalid-v3');
		INSERT INTO routing_policies
			(id, tenant_id, scope_type, scope_ref, layer, strategy, config_json,
			 enabled, created_at, updated_at, schema_version, config_version)
		VALUES
			('invalid-v3', 'tenant-invalid-v3', 'tenant', 'wrong-scope', 'model',
			 'single', '{"provider":"provider-invalid-v3"}', false,
			 '2026-07-17T00:00:00Z', '2026-07-17T01:00:00Z', 3, 7);
	`)
	invalidBefore := execInvalidSQL(`
		SELECT concat_ws('|', id, tenant_id, scope_type, scope_ref, layer, strategy,
			config_json::text, enabled, created_at, updated_at, schema_version, config_version)
		FROM routing_policies WHERE id = 'invalid-v3'
	`)
	output, err := runDocker(string(migration), "exec", "-i", container, "psql",
		"-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", invalidDatabase)
	if err == nil {
		t.Fatal("migration 116 must fail when an invalid v3 policy already exists")
	}
	if !strings.Contains(output, "chk_routing_v3_explicit_model") {
		t.Fatalf("migration 116 failed for an unrelated reason: %s", output)
	}
	invalidAfter := execInvalidSQL(`
		SELECT concat_ws('|', id, tenant_id, scope_type, scope_ref, layer, strategy,
			config_json::text, enabled, created_at, updated_at, schema_version, config_version)
		FROM routing_policies WHERE id = 'invalid-v3'
	`)
	if invalidAfter != invalidBefore {
		t.Fatalf("failed migration rewrote invalid v3 policy: before=%q after=%q", invalidBefore, invalidAfter)
	}

	preparePre116Database := func(database string) {
		t.Helper()
		execSQL("CREATE DATABASE " + database)
		schema := `
			CREATE TABLE tenants (id varchar(64) PRIMARY KEY);
			CREATE TABLE providers (
				id varchar(64) PRIMARY KEY,
				tenant_id varchar(64) NOT NULL REFERENCES tenants(id)
			);
			CREATE TABLE routing_policies (
				id varchar(64) PRIMARY KEY,
				tenant_id varchar(64) NOT NULL REFERENCES tenants(id),
				scope_type varchar(16) NOT NULL,
				scope_ref varchar(64),
				layer varchar(16) NOT NULL,
				strategy varchar(32) NOT NULL,
				config_json jsonb NOT NULL DEFAULT '{}',
				enabled boolean NOT NULL DEFAULT true,
				created_at timestamptz NOT NULL DEFAULT now(),
				updated_at timestamptz NOT NULL DEFAULT now()
			);
			CREATE TABLE request_logs (
				id text PRIMARY KEY,
				tenant_id text NOT NULL,
				created_at timestamptz NOT NULL,
				model_id text,
				provider_id text, agent_instance_id varchar(128));
		`
		if output, err := runDocker("", "exec", container, "psql", "-v", "ON_ERROR_STOP=1",
			"-U", "postgres", "-d", database, "-tAc", schema); err != nil {
			t.Fatalf("prepare %s schema: %v: %s", database, err, output)
		}
		for _, migrationName := range []string{"114_model_routing_v2.sql", "115_request_logs_ttft.sql"} {
			body, err := os.ReadFile("../../../../deploy/migrations/" + migrationName)
			if err != nil {
				t.Fatalf("read %s: %v", migrationName, err)
			}
			if output, err := runDocker(string(body), "exec", "-i", container, "psql",
				"-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", database); err != nil {
				t.Fatalf("apply %s to %s: %v: %s", migrationName, database, err, output)
			}
		}
	}
	execDatabaseSQL := func(database, sql string) string {
		t.Helper()
		output, err := runDocker("", "exec", container, "psql", "-v", "ON_ERROR_STOP=1",
			"-U", "postgres", "-d", database, "-tAc", sql)
		if err != nil {
			t.Fatalf("execute SQL in %s: %v: %s\nSQL: %s", database, err, output, sql)
		}
		return output
	}

	wrongIndexes := []struct {
		database      string
		createSQL     string
		indexName     string
		expectedError string
	}{
		{"migration116_wrong_provider_index", `CREATE INDEX uq_providers_tenant_provider ON providers (id)`, "uq_providers_tenant_provider", "incompatible definition for index uq_providers_tenant_provider"},
		{"migration116_wrong_v3_index", `CREATE INDEX uq_routing_v3_model ON routing_policies (scope_ref)`, "uq_routing_v3_model", "incompatible definition for index uq_routing_v3_model"},
	}
	for _, testCase := range wrongIndexes {
		preparePre116Database(testCase.database)
		execDatabaseSQL(testCase.database, testCase.createSQL)
		definitionBefore := execDatabaseSQL(testCase.database, fmt.Sprintf("SELECT pg_get_indexdef('%s'::regclass)", testCase.indexName))
		output, err := runDocker(string(migration), "exec", "-i", container, "psql",
			"-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", testCase.database)
		if err == nil {
			t.Fatalf("migration 116 silently accepted wrong index %s", testCase.indexName)
		}
		if !strings.Contains(output, testCase.expectedError) {
			t.Fatalf("migration 116 failed without explicit %s validation: %s", testCase.indexName, output)
		}
		definitionAfter := execDatabaseSQL(testCase.database, fmt.Sprintf("SELECT pg_get_indexdef('%s'::regclass)", testCase.indexName))
		if definitionAfter != definitionBefore {
			t.Fatalf("migration 116 changed wrong index %s: before=%q after=%q", testCase.indexName, definitionBefore, definitionAfter)
		}
	}

	invalidIndexDatabase := "migration116_invalid_v3_index"
	preparePre116Database(invalidIndexDatabase)
	execDatabaseSQL(invalidIndexDatabase, `
		INSERT INTO tenants (id) VALUES ('tenant-invalid-index');
		INSERT INTO routing_policies
			(id, tenant_id, scope_type, scope_ref, layer, strategy, schema_version)
		VALUES
			('duplicate-a', 'tenant-invalid-index', 'model', 'duplicate-model', 'provider', 'single', 3),
			('duplicate-b', 'tenant-invalid-index', 'model', 'duplicate-model', 'provider', 'single', 3);
	`)
	output, err = runDocker("", "exec", container, "psql", "-v", "ON_ERROR_STOP=1",
		"-U", "postgres", "-d", invalidIndexDatabase, "-c", `
			CREATE UNIQUE INDEX CONCURRENTLY uq_routing_v3_model
			ON routing_policies (tenant_id, scope_ref)
			WHERE schema_version = 3 AND scope_type = 'model' AND layer = 'provider'
		`)
	if err == nil {
		t.Fatal("concurrent unique index setup must fail on duplicate v3 rows")
	}
	if !strings.Contains(output, "duplicated") && !strings.Contains(output, "duplicate key") {
		t.Fatalf("failed to create expected invalid index residue: %s", output)
	}
	invalidIndexBefore := execDatabaseSQL(invalidIndexDatabase, `
		SELECT concat_ws('|', i.indisvalid, i.indisready, i.indislive, pg_get_indexdef(i.indexrelid))
		FROM pg_index i WHERE i.indexrelid = 'uq_routing_v3_model'::regclass
	`)
	if !strings.HasPrefix(invalidIndexBefore, "f|") {
		t.Fatalf("expected invalid index residue, got %q", invalidIndexBefore)
	}
	execDatabaseSQL(invalidIndexDatabase, `DELETE FROM routing_policies WHERE id = 'duplicate-b'`)
	output, err = runDocker(string(migration), "exec", "-i", container, "psql",
		"-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", invalidIndexDatabase)
	if err == nil {
		t.Fatal("migration 116 silently accepted an invalid same-name v3 index")
	}
	if !strings.Contains(output, "incompatible definition for index uq_routing_v3_model") {
		t.Fatalf("migration 116 failed without explicit invalid-index validation: %s", output)
	}
	invalidIndexAfter := execDatabaseSQL(invalidIndexDatabase, `
		SELECT concat_ws('|', i.indisvalid, i.indisready, i.indislive, pg_get_indexdef(i.indexrelid))
		FROM pg_index i WHERE i.indexrelid = 'uq_routing_v3_model'::regclass
	`)
	if invalidIndexAfter != invalidIndexBefore {
		t.Fatalf("migration 116 changed invalid index residue: before=%q after=%q", invalidIndexBefore, invalidIndexAfter)
	}
}

func TestModelRoutingRepositoryDeleteDefaultIsIdempotentAndScoped(t *testing.T) {
	f := setupModelRoutingTestDB(t)
	ctx := context.Background()
	if _, err := f.db.Exec(ctx, `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES('rp_default_del_a',$1,'tenant',$1,'provider','priority','{"strategy":"priority","cost_basis":"none","providers":[]}'::jsonb,TRUE,2,1)`, f.tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(ctx, `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES('rp_default_del_b',$1,'model','org/model-x','provider','priority','{"strategy":"priority","cost_basis":"none","providers":[]}'::jsonb,TRUE,2,1)`, f.tenantA); err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.Exec(ctx, `INSERT INTO routing_policies(id,tenant_id,scope_type,scope_ref,layer,strategy,config_json,enabled,schema_version,config_version) VALUES('rp_default_del_c',$1,'tenant',$1,'provider','priority','{"strategy":"priority","cost_basis":"none","providers":[]}'::jsonb,TRUE,2,1)`, f.tenantB); err != nil {
		t.Fatal(err)
	}
	repo := NewModelRoutingRepository(f.db)
	if err := repo.DeleteDefault(ctx, f.tenantA); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteDefault(ctx, f.tenantA); err != nil {
		t.Fatalf("second delete must stay idempotent: %v", err)
	}
	var defaultA, overrideA, defaultB int
	if err := f.db.QueryRow(ctx, `SELECT count(*) FROM routing_policies WHERE tenant_id=$1 AND scope_type='tenant'`, f.tenantA).Scan(&defaultA); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(ctx, `SELECT count(*) FROM routing_policies WHERE tenant_id=$1 AND scope_type='model'`, f.tenantA).Scan(&overrideA); err != nil {
		t.Fatal(err)
	}
	if err := f.db.QueryRow(ctx, `SELECT count(*) FROM routing_policies WHERE tenant_id=$1 AND scope_type='tenant'`, f.tenantB).Scan(&defaultB); err != nil {
		t.Fatal(err)
	}
	if defaultA != 0 || overrideA != 1 || defaultB != 1 {
		t.Fatalf("delete default scoping wrong: defaultA=%d overrideA=%d defaultB=%d", defaultA, overrideA, defaultB)
	}
}
