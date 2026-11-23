package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type securityRulesFixture struct {
	pool        *pgxpool.Pool
	deps        *Dependencies
	tenantA     string
	tenantB     string
	ruleSetA    string
	ruleSetB    string
	runtimeA    string
	catalogA    string
	managedA    string
	fakeDomainA string
	runtimeB    string
}

func newSecurityRulesFixture(t *testing.T) securityRulesFixture {
	t.Helper()
	dsn := os.Getenv("RULES_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("RULES_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect admin database: %v", err)
	}
	schema := fmt.Sprintf("security_rules_%d", time.Now().UnixNano())
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		admin.Close()
		t.Fatalf("parse database config: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		admin.Close()
		t.Fatalf("connect isolated database: %v", err)
	}
	t.Cleanup(func() {
		pool.Close()
		if _, err := admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+ident+" CASCADE"); err != nil {
			t.Errorf("drop schema: %v", err)
		}
		admin.Close()
	})
	for _, stmt := range []string{
		`CREATE TABLE tenants (id VARCHAR(64) PRIMARY KEY)`,
		`CREATE TABLE rule_sets (
			id VARCHAR(64) PRIMARY KEY,
			tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
			name VARCHAR(255) NOT NULL,
			version VARCHAR(32) NOT NULL DEFAULT '1.0',
			source_type VARCHAR(32), published BOOLEAN DEFAULT FALSE,
			created_by VARCHAR(64), created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE TABLE rules (
			id VARCHAR(64) PRIMARY KEY,
			rule_set_id VARCHAR(64) NOT NULL REFERENCES rule_sets(id),
			policy_code VARCHAR(128),
			rule_type VARCHAR(64) NOT NULL, name VARCHAR(255) NOT NULL,
			priority INTEGER DEFAULT 0, severity VARCHAR(32) DEFAULT 'medium',
			scope_json JSONB DEFAULT '{}', match_config_json JSONB DEFAULT '{}',
			action VARCHAR(32) NOT NULL DEFAULT 'audit', enabled BOOLEAN DEFAULT TRUE,
			description TEXT DEFAULT '', created_at TIMESTAMPTZ DEFAULT NOW()
		)`,
		`CREATE UNIQUE INDEX uq_rules_rule_set_policy_code_test
			ON rules(rule_set_id,policy_code) WHERE policy_code IS NOT NULL`,
		`CREATE TABLE security_capabilities (
			id VARCHAR(160) PRIMARY KEY,
			category VARCHAR(128) NOT NULL UNIQUE,
			enabled BOOLEAN NOT NULL DEFAULT TRUE,
			supported_stages JSONB NOT NULL DEFAULT '["input","output"]',
			allowed_actions JSONB NOT NULL DEFAULT '["audit","block"]',
			mask_capable BOOLEAN NOT NULL DEFAULT FALSE
		)`,
		`CREATE TABLE builtin_rule_overrides (
 severity VARCHAR(16) CHECK (severity IS NULL OR severity IN ('low','medium','high','critical')),
 redaction_json JSONB,
 semantic_action VARCHAR(16),
			tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			rule_id VARCHAR(64) NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
			action VARCHAR(32), enabled BOOLEAN,
			capability_categories JSONB, binding_mode VARCHAR(8),
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY(tenant_id, rule_id)
		)`,
		`CREATE TABLE rule_capability_bindings (
			rule_id VARCHAR(64) NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
			capability_id VARCHAR(160) NOT NULL REFERENCES security_capabilities(id),
			binding_mode VARCHAR(8) NOT NULL,
			priority INTEGER NOT NULL DEFAULT 0,
			config_json JSONB NOT NULL DEFAULT '{}',
			PRIMARY KEY(rule_id,capability_id)
		)`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create fixture table: %v", err)
		}
	}
	for _, category := range repository.DefaultPolicyCapabilityCategories() {
		if _, err := pool.Exec(ctx,
			`INSERT INTO security_capabilities(id,category,enabled) VALUES($1,$2,true)`,
			"cap.test."+category, category,
		); err != nil {
			t.Fatalf("insert capability %s: %v", category, err)
		}
	}
	f := securityRulesFixture{
		pool: pool, tenantA: "tenant_a", tenantB: "tenant_b",
		runtimeA: "rule_runtime_a", catalogA: "rule_catalog_a", managedA: "rule_managed_a", fakeDomainA: "rule_fake_domain_a", runtimeB: "rule_runtime_b",
	}
	f.ruleSetA = tenantDefaultRuleSetID(f.tenantA)
	f.ruleSetB = tenantDefaultRuleSetID(f.tenantB)
	for _, tenant := range []string{f.tenantA, f.tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id) VALUES($1)`, tenant); err != nil {
			t.Fatalf("insert tenant: %v", err)
		}
	}
	for _, item := range []struct{ id, tenant string }{{f.ruleSetA, f.tenantA}, {f.ruleSetB, f.tenantB}} {
		if _, err := pool.Exec(ctx, `INSERT INTO rule_sets(id,tenant_id,name,version,source_type,published) VALUES($1,$2,$1,'1.0','system',true)`, item.id, item.tenant); err != nil {
			t.Fatalf("insert rule set: %v", err)
		}
	}
	for _, item := range []struct{ id, rs, policyCode, ruleType, name, match, description string }{
		{f.runtimeA, f.ruleSetA, "", "keyword", "runtime-a", `{"keywords":["alpha"]}`, ""},
		{f.catalogA, f.ruleSetA, "builtin.prompt.catalog", "prompt_injection", "经典注入指令检测", `{}`, "旧版本描述也必须保持能力目录只读"},
		{f.managedA, f.ruleSetA, "custom.organization.policy", "field_name", "managed-a", `{"field_names":["managed"]}`, ""},
		{f.fakeDomainA, f.ruleSetA, "", "prompt_injection", "fake-domain-a", `{"keywords":["ignore previous"]}`, ""},
		{f.runtimeB, f.ruleSetB, "", "keyword", "runtime-b", `{"keywords":["beta"]}`, ""},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO rules(id,rule_set_id,policy_code,rule_type,name,severity,match_config_json,action,enabled,description) VALUES($1,$2,NULLIF($3,''),$4,$5,'high',$6::jsonb,'audit',true,$7)`, item.id, item.rs, item.policyCode, item.ruleType, item.name, item.match, item.description); err != nil {
			t.Fatalf("insert rule: %v", err)
		}
	}
	f.deps = &Dependencies{RuleSetRepo: repository.NewRuleSetRepository(pool), RuleRepo: repository.NewRuleRepository(pool)}
	return f
}

func securityRulesRequest(method, target, body, tenantID string) *http.Request {
	req := httptest.NewRequest(method, target, bytes.NewBufferString(body))
	user := &repository.User{ID: "user_" + tenantID, TenantID: tenantID, Role: "platform_admin", Status: "active"}
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
}

func withSecurityRuleID(req *http.Request, id string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", id)
	return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
}

func TestSecurityRulesRejectCrossTenantHTTP(t *testing.T) {
	f := newSecurityRulesFixture(t)
	validCreate := fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"regex","name":"foreign","match_config_json":{"regex":"x"}}`, f.ruleSetB)
	cases := []struct {
		name    string
		handler http.HandlerFunc
		req     *http.Request
	}{
		{"list", ListRules(f.deps), securityRulesRequest(http.MethodGet, "/admin/v1/rules?rule_set_id="+f.ruleSetB, "", f.tenantA)},
		{"create", CreateRule(f.deps), securityRulesRequest(http.MethodPost, "/admin/v1/rules", validCreate, f.tenantA)},
		{"update", UpdateRule(f.deps), withSecurityRuleID(securityRulesRequest(http.MethodPatch, "/admin/v1/rules/"+f.runtimeB, `{"action":"block"}`, f.tenantA), f.runtimeB)},
		{"toggle", ToggleRule(f.deps), withSecurityRuleID(securityRulesRequest(http.MethodPost, "/admin/v1/rules/"+f.runtimeB+"/toggle", "", f.tenantA), f.runtimeB)},
		{"delete", DeleteRule(f.deps), withSecurityRuleID(securityRulesRequest(http.MethodDelete, "/admin/v1/rules/"+f.runtimeB, "", f.tenantA), f.runtimeB)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler.ServeHTTP(rec, tc.req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status=%d want 404 body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	var name, action string
	var enabled bool
	if err := f.pool.QueryRow(context.Background(), `SELECT name,action,enabled FROM rules WHERE id=$1`, f.runtimeB).Scan(&name, &action, &enabled); err != nil {
		t.Fatalf("read tenant B rule: %v", err)
	}
	if name != "runtime-b" || action != "audit" || !enabled {
		t.Fatalf("tenant B rule changed: name=%q action=%q enabled=%v", name, action, enabled)
	}
	var foreignCreateCount int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM rules WHERE name='foreign'`).Scan(&foreignCreateCount)
	if foreignCreateCount != 0 {
		t.Fatalf("foreign create count=%d want 0", foreignCreateCount)
	}
}

func TestCreateTenantSeedFailureLeavesNoTenantRuleSetOrRules(t *testing.T) {
	f := newSecurityRulesFixture(t)
	ctx := context.Background()
	for _, stmt := range []string{
		`ALTER TABLE tenants ADD COLUMN name text NOT NULL DEFAULT ''`,
		`ALTER TABLE tenants ADD COLUMN edition text NOT NULL DEFAULT 'enterprise'`,
		`ALTER TABLE tenants ADD COLUMN status text NOT NULL DEFAULT 'active'`,
		`ALTER TABLE tenants ADD COLUMN industry text NOT NULL DEFAULT 'generic'`,
		`ALTER TABLE tenants ADD COLUMN config_json jsonb NOT NULL DEFAULT '{}'`,
		`ALTER TABLE tenants ADD COLUMN created_at timestamptz NOT NULL DEFAULT now()`,
		`ALTER TABLE tenants ADD COLUMN updated_at timestamptz NOT NULL DEFAULT now()`,
	} {
		if _, err := f.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("extend tenant fixture: %v", err)
		}
	}
	// Force the real SeedDefaultSubRules transaction to fail after Ensure has
	// already committed the new rule set.
	if _, err := f.pool.Exec(ctx, `DELETE FROM security_capabilities WHERE category='semantic_roleplay'`); err != nil {
		t.Fatalf("remove required capability: %v", err)
	}
	f.deps.TenantRepo = repository.NewTenantRepository(f.pool)

	var beforeTenants, beforeRuleSets, beforeRules int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&beforeTenants); err != nil {
		t.Fatalf("count tenants before: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rule_sets`).Scan(&beforeRuleSets); err != nil {
		t.Fatalf("count rule sets before: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules`).Scan(&beforeRules); err != nil {
		t.Fatalf("count rules before: %v", err)
	}

	rec := httptest.NewRecorder()
	CreateTenant(f.deps).ServeHTTP(rec, securityRulesRequest(
		http.MethodPost, "/admin/v1/tenants",
		`{"name":"seed failure tenant","edition":"enterprise"}`, f.tenantA,
	))
	if rec.Code >= 200 && rec.Code < 300 {
		t.Fatalf("seed failure unexpectedly succeeded status=%d body=%s", rec.Code, rec.Body.String())
	}

	var afterTenants, afterRuleSets, afterRules, leakedTenant int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenants`).Scan(&afterTenants); err != nil {
		t.Fatalf("count tenants after: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rule_sets`).Scan(&afterRuleSets); err != nil {
		t.Fatalf("count rule sets after: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules`).Scan(&afterRules); err != nil {
		t.Fatalf("count rules after: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM tenants WHERE name='seed failure tenant'`).Scan(&leakedTenant); err != nil {
		t.Fatalf("find leaked tenant: %v", err)
	}
	if leakedTenant != 0 || afterTenants != beforeTenants || afterRuleSets != beforeRuleSets || afterRules != beforeRules {
		t.Fatalf("failed create leaked state tenant=%d totals tenants/rule_sets/rules before=%d/%d/%d after=%d/%d/%d",
			leakedTenant, beforeTenants, beforeRuleSets, beforeRules, afterTenants, afterRuleSets, afterRules)
	}
}

func TestSecurityRulesCatalogRowsAreReadOnly(t *testing.T) {
	f := newSecurityRulesFixture(t)
	cases := []struct {
		name    string
		handler http.HandlerFunc
		req     *http.Request
	}{
		{"update", UpdateRule(f.deps), withSecurityRuleID(securityRulesRequest(http.MethodPatch, "/rules/"+f.catalogA, `{"action":"block"}`, f.tenantA), f.catalogA)},
		{"toggle", ToggleRule(f.deps), withSecurityRuleID(securityRulesRequest(http.MethodPost, "/rules/"+f.catalogA+"/toggle", "", f.tenantA), f.catalogA)},
		{"delete", DeleteRule(f.deps), withSecurityRuleID(securityRulesRequest(http.MethodDelete, "/rules/"+f.catalogA, "", f.tenantA), f.catalogA)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler.ServeHTTP(rec, tc.req)
			if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "security_policy_read_only") {
				t.Fatalf("status=%d want 409 security_policy_read_only body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	var count int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM rules WHERE id=$1 AND action='audit' AND enabled=true`, f.catalogA).Scan(&count)
	if count != 1 {
		t.Fatalf("catalog rule was mutated or deleted")
	}
}

func TestSecurityRulesLegacyEndpointsRejectCustomManagedPoliciesBeforeValidation(t *testing.T) {
	f := newSecurityRulesFixture(t)
	cases := []struct {
		name    string
		handler http.HandlerFunc
		req     *http.Request
	}{
		{
			"patch allow",
			UpdateRule(f.deps),
			withSecurityRuleID(securityRulesRequest(http.MethodPatch, "/rules/"+f.managedA, `{"action":"allow"}`, f.tenantA), f.managedA),
		},
		{
			"toggle",
			ToggleRule(f.deps),
			withSecurityRuleID(securityRulesRequest(http.MethodPost, "/rules/"+f.managedA+"/toggle", "", f.tenantA), f.managedA),
		},
		{
			"batch",
			BatchUpdateDetector(f.deps),
			securityRulesRequest(http.MethodPost, "/detectors/batch-update", `{"rule_type":"field_name","action":"block","enabled":false}`, f.tenantA),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			tc.handler.ServeHTTP(rec, tc.req)
			if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "security_policy_read_only") {
				t.Fatalf("status=%d want 409 security_policy_read_only body=%s", rec.Code, rec.Body.String())
			}
		})
	}

	rows, err := f.pool.Query(context.Background(), `
		SELECT id,name,action,severity,priority,enabled
		FROM rules WHERE id=ANY($1::varchar[]) ORDER BY id`, []string{f.managedA, f.runtimeA})
	if err != nil {
		t.Fatalf("read rules after rejected requests: %v", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var id, name, action, severity string
		var priority int
		var enabled bool
		if err := rows.Scan(&id, &name, &action, &severity, &priority, &enabled); err != nil {
			t.Fatalf("scan rule: %v", err)
		}
		seen++
		if action != "audit" || severity != "high" || priority != 0 || !enabled {
			t.Fatalf("rule %s changed after rejected legacy request: %q/%q/%q/%d/%v", id, name, action, severity, priority, enabled)
		}
	}
	if seen != 2 {
		t.Fatalf("rows=%d want 2", seen)
	}
}

func TestSecurityRulesLegacyMatcherlessRuleCanBeDeleted(t *testing.T) {
	f := newSecurityRulesFixture(t)
	ctx := context.Background()
	const legacyID = "rule_legacy_matcherless"
	if _, err := f.pool.Exec(ctx, `INSERT INTO rules(id,rule_set_id,rule_type,name,severity,match_config_json,action,enabled,description) VALUES($1,$2,'prompt_injection','legacy custom','high','{}','audit',true,'customer legacy rule')`, legacyID, f.ruleSetA); err != nil {
		t.Fatalf("insert legacy rule: %v", err)
	}
	rec := httptest.NewRecorder()
	DeleteRule(f.deps).ServeHTTP(rec, withSecurityRuleID(securityRulesRequest(http.MethodDelete, "/rules/"+legacyID, "", f.tenantA), legacyID))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete status=%d want 204 body=%s", rec.Code, rec.Body.String())
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rules WHERE id=$1`, legacyID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("legacy rule count=%d err=%v want 0", count, err)
	}
}

func TestSecurityRulesRejectMatcherlessAndInvalidInputs(t *testing.T) {
	f := newSecurityRulesFixture(t)
	cases := []struct {
		name string
		body string
	}{
		{"no matcher", fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"regex","name":"bare"}`, f.ruleSetA)},
		{"bad action", fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"regex","name":"bad","action":"execute","match_config_json":{"regex":"x"}}`, f.ruleSetA)},
		{"reply is not a runtime action", fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"regex","name":"reply","action":"reply","match_config_json":{"regex":"x"}}`, f.ruleSetA)},
		{"bad severity", fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"regex","name":"bad","severity":"urgent","match_config_json":{"regex":"x"}}`, f.ruleSetA)},
		{"bad priority", fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"regex","name":"bad","priority":10001,"match_config_json":{"regex":"x"}}`, f.ruleSetA)},
		{"blank regex", fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"regex","name":"blank","match_config_json":{"regex":"   "}}`, f.ruleSetA)},
		{"blank keyword", fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"keyword","name":"blank","match_config_json":{"keywords":[" ",""]}}`, f.ruleSetA)},
		{"unknown type", fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"shell","name":"unknown","match_config_json":{"regex":"x"}}`, f.ruleSetA)},
		{"domain type", fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"prompt_injection","name":"domain","match_config_json":{"keywords":["ignore previous"]}}`, f.ruleSetA)},
		{"mismatched matcher", fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"regex","name":"mismatch","match_config_json":{"keywords":["secret"]}}`, f.ruleSetA)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			CreateRule(f.deps).ServeHTTP(rec, securityRulesRequest(http.MethodPost, "/rules", tc.body, f.tenantA))
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status=%d want 422 body=%s", rec.Code, rec.Body.String())
			}
		})
	}
	rec := httptest.NewRecorder()
	UpdateRule(f.deps).ServeHTTP(rec, withSecurityRuleID(securityRulesRequest(http.MethodPatch, "/rules/"+f.runtimeA, `{"priority":-1}`, f.tenantA), f.runtimeA))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("update priority status=%d want 422 body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	UpdateRule(f.deps).ServeHTTP(rec, withSecurityRuleID(securityRulesRequest(http.MethodPatch, "/rules/"+f.runtimeA, `{"action":"reply"}`, f.tenantA), f.runtimeA))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("update reply status=%d want 422 body=%s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	BatchUpdateDetector(f.deps).ServeHTTP(rec, securityRulesRequest(http.MethodPost, "/detectors/batch-update", `{"rule_type":"regex","action":"reply"}`, f.tenantA))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("batch reply status=%d want 422 body=%s", rec.Code, rec.Body.String())
	}
}

func TestSecurityRulesDefaultResolutionAndBatchRuntimeOnly(t *testing.T) {
	f := newSecurityRulesFixture(t)
	for _, target := range []string{"/admin/v1/rules", "/admin/v1/rules?rule_set_id=ruleset_default"} {
		rec := httptest.NewRecorder()
		ListRules(f.deps).ServeHTTP(rec, securityRulesRequest(http.MethodGet, target, "", f.tenantA))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "runtime-a") || strings.Contains(rec.Body.String(), "runtime-b") {
			t.Fatalf("target=%s default list status=%d body=%s", target, rec.Code, rec.Body.String())
		}
	}
	for i, legacyRuleSetID := range []string{"", "ruleset_default"} {
		body := fmt.Sprintf(`{"rule_set_id":%q,"rule_type":"regex","name":"legacy-%d","match_config_json":{"regex":"token-%d"}}`, legacyRuleSetID, i, i)
		rec := httptest.NewRecorder()
		CreateRule(f.deps).ServeHTTP(rec, securityRulesRequest(http.MethodPost, "/admin/v1/rules", body, f.tenantA))
		if rec.Code != http.StatusCreated {
			t.Fatalf("legacy rule_set_id=%q create status=%d body=%s", legacyRuleSetID, rec.Code, rec.Body.String())
		}
		var created struct {
			RuleSetID string `json:"rule_set_id"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.RuleSetID != f.ruleSetA {
			t.Fatalf("legacy rule_set_id=%q resolved=%q want=%q err=%v", legacyRuleSetID, created.RuleSetID, f.ruleSetA, err)
		}
	}

	missing := httptest.NewRecorder()
	BatchUpdateDetector(f.deps).ServeHTTP(missing, securityRulesRequest(http.MethodPost, "/detectors/batch-update", `{"rule_type":"missing_type","action":"block"}`, f.tenantA))
	if missing.Code != http.StatusConflict || !strings.Contains(missing.Body.String(), "no_runtime_rules") {
		t.Fatalf("missing runtime status=%d want 409 body=%s", missing.Code, missing.Body.String())
	}
	var missingCount int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM rules WHERE rule_type='missing_type'`).Scan(&missingCount)
	if missingCount != 0 {
		t.Fatalf("batch auto-created %d matcherless rules", missingCount)
	}

	batch := httptest.NewRecorder()
	BatchUpdateDetector(f.deps).ServeHTTP(batch, securityRulesRequest(http.MethodPost, "/detectors/batch-update", `{"rule_type":"keyword","action":"block","enabled":false}`, f.tenantA))
	if batch.Code != http.StatusOK {
		t.Fatalf("batch status=%d body=%s", batch.Code, batch.Body.String())
	}
	rows, err := f.pool.Query(context.Background(), `SELECT id,action,enabled FROM rules ORDER BY id`)
	if err != nil {
		t.Fatalf("query rules: %v", err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var id, action string
		var enabled bool
		if err := rows.Scan(&id, &action, &enabled); err != nil {
			t.Fatalf("scan: %v", err)
		}
		got[id] = fmt.Sprintf("%s/%v", action, enabled)
	}
	if got[f.runtimeA] != "block/false" || got[f.catalogA] != "audit/true" || got[f.fakeDomainA] != "audit/true" || got[f.runtimeB] != "audit/true" {
		t.Fatalf("unexpected batch effects: %#v", got)
	}

	domain := httptest.NewRecorder()
	BatchUpdateDetector(f.deps).ServeHTTP(domain, securityRulesRequest(http.MethodPost, "/detectors/batch-update", `{"rule_type":"prompt_injection","action":"block"}`, f.tenantA))
	if domain.Code != http.StatusConflict || !strings.Contains(domain.Body.String(), "security_policy_read_only") {
		t.Fatalf("domain batch status=%d want409 body=%s", domain.Code, domain.Body.String())
	}
}

func TestToggleRuleTwiceIsAtomicAndPreservesFields(t *testing.T) {
	f := newSecurityRulesFixture(t)
	for run, want := range []bool{false, true} {
		rec := httptest.NewRecorder()
		ToggleRule(f.deps).ServeHTTP(rec, withSecurityRuleID(securityRulesRequest(http.MethodPost, "/rules/"+f.runtimeA+"/toggle", "", f.tenantA), f.runtimeA))
		if rec.Code != http.StatusOK {
			t.Fatalf("run=%d status=%d body=%s", run+1, rec.Code, rec.Body.String())
		}
		var body struct {
			Enabled bool `json:"enabled"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Enabled != want {
			t.Fatalf("run=%d enabled=%v want=%v err=%v", run+1, body.Enabled, want, err)
		}
	}
	var name, action, severity string
	var priority int
	if err := f.pool.QueryRow(context.Background(), `SELECT name,action,severity,priority FROM rules WHERE id=$1`, f.runtimeA).Scan(&name, &action, &severity, &priority); err != nil {
		t.Fatalf("read toggled rule: %v", err)
	}
	if name != "runtime-a" || action != "audit" || severity != "high" || priority != 0 {
		t.Fatalf("toggle overwrote fields: %q %q %q %d", name, action, severity, priority)
	}
}

func assertSeededPolicyStats(t *testing.T, pool *pgxpool.Pool, tenantID, ruleSetID string) {
	t.Helper()
	var policies, codedPolicies, boundPolicies, bindingRows int
	err := pool.QueryRow(context.Background(), `
		SELECT COUNT(DISTINCT r.id),
		       COUNT(DISTINCT r.policy_code),
		       COUNT(DISTINCT b.rule_id),
		       COUNT(b.rule_id)
		FROM rules r
		JOIN rule_sets rs ON rs.id=r.rule_set_id
		LEFT JOIN rule_capability_bindings b ON b.rule_id=r.id
		WHERE rs.tenant_id=$1 AND rs.id=$2`,
		tenantID, ruleSetID,
	).Scan(&policies, &codedPolicies, &boundPolicies, &bindingRows)
	if err != nil {
		t.Fatalf("tenant=%s query seeded policy stats: %v", tenantID, err)
	}
	if policies != 241 || codedPolicies != 241 ||
		boundPolicies != repository.DefaultPolicyExactBindingCount() ||
		bindingRows != repository.DefaultPolicyCapabilityBindingCount() {
		t.Fatalf(
			"tenant=%s seeded policies=%d coded=%d bound=%d rows=%d want=241/241/%d/%d",
			tenantID, policies, codedPolicies, boundPolicies, bindingRows,
			repository.DefaultPolicyExactBindingCount(), repository.DefaultPolicyCapabilityBindingCount(),
		)
	}
}

func TestInitDetectorsUsesDistinctTenantDefaultsAndIsIdempotent(t *testing.T) {
	f := newSecurityRulesFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `DELETE FROM rules`); err != nil {
		t.Fatalf("delete rules: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM rule_sets`); err != nil {
		t.Fatalf("delete rule sets: %v", err)
	}
	if f.ruleSetA == f.ruleSetB || f.ruleSetA == defaultContentRuleSetID || f.ruleSetB == defaultContentRuleSetID {
		t.Fatalf("tenant default IDs are not isolated: A=%q B=%q", f.ruleSetA, f.ruleSetB)
	}
	for _, tenant := range []string{f.tenantA, f.tenantB} {
		for run, wantCreated := range []int{241, 0} {
			rec := httptest.NewRecorder()
			InitDetectors(f.deps).ServeHTTP(rec, securityRulesRequest(http.MethodPost, "/detectors/init", "", tenant))
			if rec.Code != http.StatusOK {
				t.Fatalf("tenant=%s run=%d status=%d body=%s", tenant, run+1, rec.Code, rec.Body.String())
			}
			var body struct {
				RulesCreated int `json:"rules_created"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.RulesCreated != wantCreated {
				t.Fatalf("tenant=%s run=%d created=%d want=%d err=%v", tenant, run+1, body.RulesCreated, wantCreated, err)
			}
		}
	}
	for _, item := range []struct{ tenant, ruleSet string }{{f.tenantA, f.ruleSetA}, {f.tenantB, f.ruleSetB}} {
		assertSeededPolicyStats(t, f.pool, item.tenant, item.ruleSet)
	}
}

func TestInitDetectorsConcurrentCallsBothSucceedWithoutDuplicateSeeds(t *testing.T) {
	f := newSecurityRulesFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `DELETE FROM rules`); err != nil {
		t.Fatalf("delete rules: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM rule_sets`); err != nil {
		t.Fatalf("delete rule sets: %v", err)
	}
	type result struct {
		status  int
		created int
		body    string
	}
	results := make(chan result, 2)
	for range 2 {
		go func() {
			rec := httptest.NewRecorder()
			InitDetectors(f.deps).ServeHTTP(rec, securityRulesRequest(http.MethodPost, "/detectors/init", "", f.tenantA))
			var decoded struct {
				RulesCreated int `json:"rules_created"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
			results <- result{status: rec.Code, created: decoded.RulesCreated, body: rec.Body.String()}
		}()
	}
	totalCreated := 0
	for range 2 {
		got := <-results
		if got.status != http.StatusOK {
			t.Fatalf("concurrent init status=%d body=%s", got.status, got.body)
		}
		totalCreated += got.created
	}
	if totalCreated != 241 {
		t.Fatalf("total created=%d want241", totalCreated)
	}
	assertSeededPolicyStats(t, f.pool, f.tenantA, f.ruleSetA)
}

// Since "organization policies can be deleted", the legacy DELETE of a custom.* policy removes it like the
// policy-center endpoint does, while shipped policies stay protected (TestSecurityRulesCatalogRowsAreReadOnly).
func TestSecurityRulesLegacyDeleteRemovesCustomManagedPolicyAndItsExceptions(t *testing.T) {
	f := newSecurityRulesFixture(t)
	ctx := context.Background()
	// this minimal fixture predates the industry columns the policy lock reads
	for _, stmt := range []string{
		`ALTER TABLE tenants ADD COLUMN industry VARCHAR(64) NOT NULL DEFAULT 'generic'`,
		`ALTER TABLE rule_sets ADD COLUMN industry VARCHAR(64) NOT NULL DEFAULT 'generic'`,
	} {
		if _, err := f.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("extend fixture: %v", err)
		}
	}
	if _, err := f.pool.Exec(ctx, `CREATE TABLE content_audit_exceptions (
		id VARCHAR(64) PRIMARY KEY,
		tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
		scope_type VARCHAR(32) NOT NULL,
		rule_id VARCHAR(64) REFERENCES rules(id) ON DELETE CASCADE,
		rule_ref TEXT,
		decision VARCHAR(16) NOT NULL,
		reason TEXT NOT NULL
	)`); err != nil {
		t.Fatalf("create exceptions table: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO content_audit_exceptions(id,tenant_id,scope_type,rule_id,rule_ref,decision,reason)
		VALUES('cex_managed',$1,'rule',$2::text,$2::text,'allow','e2e')`, f.tenantA, f.managedA); err != nil {
		t.Fatalf("insert exception: %v", err)
	}
	rec := httptest.NewRecorder()
	DeleteRule(f.deps).ServeHTTP(rec, withSecurityRuleID(securityRulesRequest(http.MethodDelete, "/rules/"+f.managedA, "", f.tenantA), f.managedA))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("legacy delete of a custom policy status=%d want 204 body=%s", rec.Code, rec.Body.String())
	}
	if rule, err := f.deps.RuleRepo.GetByID(ctx, f.tenantA, f.managedA); err != nil || rule != nil {
		t.Fatalf("deleted custom policy must read as gone rule=%v err=%v", rule, err)
	}
	var exceptions int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM content_audit_exceptions WHERE rule_id=$1`, f.managedA).Scan(&exceptions); err != nil || exceptions != 0 {
		t.Fatalf("its exceptions must go with it: count=%d err=%v", exceptions, err)
	}
	rec = httptest.NewRecorder()
	DeleteRule(f.deps).ServeHTTP(rec, withSecurityRuleID(securityRulesRequest(http.MethodDelete, "/rules/"+f.managedA, "", f.tenantA), f.managedA))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("second delete status=%d want 404 body=%s", rec.Code, rec.Body.String())
	}
}
