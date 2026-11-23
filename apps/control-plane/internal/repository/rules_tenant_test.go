package repository

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestNewDefaultPolicyRuleIDUsesFullUUID(t *testing.T) {
	id := newDefaultPolicyRuleID()
	if !strings.HasPrefix(id, "rule_") {
		t.Fatalf("newDefaultPolicyRuleID()=%q, want rule_ prefix", id)
	}
	value := strings.TrimPrefix(id, "rule_")
	if len(value) != 36 {
		t.Fatalf("newDefaultPolicyRuleID() UUID length=%d, want 36", len(value))
	}
	if _, err := uuid.Parse(value); err != nil {
		t.Fatalf("newDefaultPolicyRuleID()=%q is not a full UUID: %v", id, err)
	}
}

type rulesTenantFixture struct {
	pool        *pgxpool.Pool
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

func newRulesTenantFixture(t *testing.T) rulesTenantFixture {
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
	schema := fmt.Sprintf("rules_tenant_%d", time.Now().UnixNano())
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

	schemaSQL := []string{
		`CREATE TABLE tenants (id VARCHAR(64) PRIMARY KEY, status VARCHAR(16) NOT NULL DEFAULT 'active', updated_at TIMESTAMPTZ DEFAULT NOW())`,
		`CREATE TABLE rule_sets (
            id VARCHAR(64) PRIMARY KEY,
            tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id),
            name VARCHAR(255) NOT NULL,
            version VARCHAR(32) NOT NULL DEFAULT '1.0',
            source_type VARCHAR(32),
            published BOOLEAN DEFAULT FALSE,
            created_by VARCHAR(64),
            created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
		`CREATE TABLE rules (
            id VARCHAR(64) PRIMARY KEY,
            rule_set_id VARCHAR(64) NOT NULL REFERENCES rule_sets(id),
			policy_code VARCHAR(128),
            rule_type VARCHAR(64) NOT NULL,
            name VARCHAR(255) NOT NULL,
            priority INTEGER DEFAULT 0,
            severity VARCHAR(32) DEFAULT 'medium',
            scope_json JSONB DEFAULT '{}',
            match_config_json JSONB DEFAULT '{}',
            action VARCHAR(32) NOT NULL DEFAULT 'audit',
            enabled BOOLEAN DEFAULT TRUE,
            description TEXT DEFAULT '',
            created_at TIMESTAMPTZ DEFAULT NOW()
        )`,
		`CREATE UNIQUE INDEX uq_rules_rule_set_policy_code_test
			ON rules(rule_set_id,policy_code) WHERE policy_code IS NOT NULL`,
		`CREATE TABLE security_capabilities (
			id VARCHAR(160) PRIMARY KEY,
			category VARCHAR(128) NOT NULL UNIQUE,
			enabled BOOLEAN NOT NULL DEFAULT TRUE
		)`,
		`CREATE TABLE rule_capability_bindings (
			rule_id VARCHAR(64) NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
			capability_id VARCHAR(160) NOT NULL REFERENCES security_capabilities(id),
			binding_mode VARCHAR(8) NOT NULL,
			priority INTEGER NOT NULL DEFAULT 0,
			config_json JSONB NOT NULL DEFAULT '{}',
			PRIMARY KEY(rule_id,capability_id)
		)`,
	}
	for _, stmt := range schemaSQL {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("create fixture schema: %v", err)
		}
	}
	for _, category := range DefaultPolicyCapabilityCategories() {
		if _, err := pool.Exec(ctx,
			`INSERT INTO security_capabilities(id,category,enabled) VALUES($1,$2,true)`,
			"cap.test."+category, category,
		); err != nil {
			t.Fatalf("insert capability %s: %v", category, err)
		}
	}

	f := rulesTenantFixture{
		pool: pool, tenantA: "tenant_a", tenantB: "tenant_b",
		ruleSetA: "rs_a", ruleSetB: "rs_b",
		runtimeA: "rule_runtime_a", catalogA: "rule_catalog_a", managedA: "rule_managed_a", fakeDomainA: "rule_fake_domain_a", runtimeB: "rule_runtime_b",
	}
	for _, tenant := range []string{f.tenantA, f.tenantB} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id) VALUES($1)`, tenant); err != nil {
			t.Fatalf("insert tenant %s: %v", tenant, err)
		}
	}
	for _, item := range []struct{ id, tenant string }{{f.ruleSetA, f.tenantA}, {f.ruleSetB, f.tenantB}} {
		if _, err := pool.Exec(ctx, `INSERT INTO rule_sets(id,tenant_id,name,version,source_type,published) VALUES($1,$2,$1,'1.0','system',true)`, item.id, item.tenant); err != nil {
			t.Fatalf("insert rule set %s: %v", item.id, err)
		}
	}
	seed := []struct {
		id, rs, policyCode, ruleType, name, match string
	}{
		{f.runtimeA, f.ruleSetA, "", "keyword", "runtime-a", `{"keywords":["alpha"]}`},
		{f.catalogA, f.ruleSetA, "builtin.prompt.catalog", "prompt_injection", "catalog-a", `{}`},
		{f.managedA, f.ruleSetA, "custom.organization.policy", "field_name", "managed-a", `{"field_names":["managed"]}`},
		{f.fakeDomainA, f.ruleSetA, "", "prompt_injection", "fake-domain-a", `{"keywords":["ignore previous"]}`},
		{f.runtimeB, f.ruleSetB, "", "keyword", "runtime-b", `{"keywords":["beta"]}`},
	}
	for _, item := range seed {
		if _, err := pool.Exec(ctx, `INSERT INTO rules(id,rule_set_id,policy_code,rule_type,name,severity,match_config_json,action,enabled) VALUES($1,$2,NULLIF($3,''),$4,$5,'high',$6::jsonb,'audit',true)`, item.id, item.rs, item.policyCode, item.ruleType, item.name, item.match); err != nil {
			t.Fatalf("insert rule %s: %v", item.id, err)
		}
	}
	return f
}

func TestLegacyRuleMutationsRejectEveryManagedPolicyCodeWithoutPartialWrites(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)

	for _, id := range []string{f.catalogA, f.managedA} {
		if err := repo.Update(ctx, f.tenantA, id, "allow", "critical", 99, false, "changed"); !errors.Is(err, ErrManagedSecurityPolicyReadOnly) {
			t.Fatalf("Update(%s) error=%v want ErrManagedSecurityPolicyReadOnly", id, err)
		}
		if _, err := repo.ToggleEnabled(ctx, f.tenantA, id); !errors.Is(err, ErrManagedSecurityPolicyReadOnly) {
			t.Fatalf("ToggleEnabled(%s) error=%v want ErrManagedSecurityPolicyReadOnly", id, err)
		}
		if err := repo.Delete(ctx, f.tenantA, id); !errors.Is(err, ErrManagedSecurityPolicyReadOnly) {
			t.Fatalf("Delete(%s) error=%v want ErrManagedSecurityPolicyReadOnly", id, err)
		}
	}

	block := "block"
	disabled := false
	if err := repo.BatchUpdateByType(ctx, f.tenantA, f.ruleSetA, "field_name", &disabled, &block, nil); !errors.Is(err, ErrManagedSecurityPolicyReadOnly) {
		t.Fatalf("BatchUpdateByType error=%v want ErrManagedSecurityPolicyReadOnly", err)
	}

	rows, err := f.pool.Query(ctx, `
		SELECT id,name,action,severity,priority,enabled
		FROM rules WHERE id=ANY($1::varchar[]) ORDER BY id`, []string{f.catalogA, f.managedA, f.runtimeA})
	if err != nil {
		t.Fatalf("read protected rules: %v", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		var id, name, action, severity string
		var priority int
		var enabled bool
		if err := rows.Scan(&id, &name, &action, &severity, &priority, &enabled); err != nil {
			t.Fatalf("scan protected rule: %v", err)
		}
		seen++
		if action != "audit" || severity != "high" || priority != 0 || !enabled || name == "changed" {
			t.Fatalf("rule %s changed through legacy API: %q/%q/%q/%d/%v", id, name, action, severity, priority, enabled)
		}
	}
	if seen != 3 {
		t.Fatalf("protected rows=%d want 3", seen)
	}
}

func TestRuleRepositoriesRejectCrossTenantAccess(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	rulesRepo := NewRuleRepository(f.pool)
	setsRepo := NewRuleSetRepository(f.pool)

	if got, err := setsRepo.ListRules(ctx, f.tenantA, f.ruleSetB); !errors.Is(err, ErrRuleSetNotFound) || len(got) != 0 {
		t.Fatalf("foreign ListRules = (%v,%v), want empty ErrRuleSetNotFound", got, err)
	}
	if got, err := rulesRepo.GetByID(ctx, f.tenantA, f.runtimeB); err != nil || got != nil {
		t.Fatalf("foreign GetByID = (%v,%v), want nil,nil", got, err)
	}
	foreignCreate := &Rule{ID: "rule_foreign_create", RuleSetID: f.ruleSetB, RuleType: "regex", Name: "foreign", Severity: "high", MatchConfigJSON: []byte(`{"regex":"x"}`), Action: "block", Enabled: true}
	if err := rulesRepo.Create(ctx, f.tenantA, foreignCreate); !errors.Is(err, ErrRuleSetNotFound) {
		t.Fatalf("foreign Create error = %v, want ErrRuleSetNotFound", err)
	}
	if err := rulesRepo.Update(ctx, f.tenantA, f.runtimeB, "block", "critical", 99, false, "changed"); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("foreign Update error = %v, want ErrRuleNotFound", err)
	}
	if err := rulesRepo.Delete(ctx, f.tenantA, f.runtimeB); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("foreign Delete error = %v, want ErrRuleNotFound", err)
	}
	if _, err := rulesRepo.ToggleEnabled(ctx, f.tenantA, f.runtimeB); !errors.Is(err, ErrRuleNotFound) {
		t.Fatalf("foreign ToggleEnabled error = %v, want ErrRuleNotFound", err)
	}
	if got, err := rulesRepo.GetRulesByType(ctx, f.tenantA, f.ruleSetB, "keyword"); !errors.Is(err, ErrRuleSetNotFound) || len(got) != 0 {
		t.Fatalf("foreign GetRulesByType = (%v,%v), want empty ErrRuleSetNotFound", got, err)
	}
	block := "block"
	if err := rulesRepo.BatchUpdateByType(ctx, f.tenantA, f.ruleSetB, "keyword", nil, &block, nil); !errors.Is(err, ErrRuleSetNotFound) {
		t.Fatalf("foreign BatchUpdateByType error = %v, want ErrRuleSetNotFound", err)
	}
	if created, err := rulesRepo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetB); !errors.Is(err, ErrRuleSetNotFound) || created != 0 {
		t.Fatalf("foreign SeedDefaultSubRules = (%d,%v), want 0,ErrRuleSetNotFound", created, err)
	}

	var name, action, severity string
	var enabled bool
	if err := f.pool.QueryRow(ctx, `SELECT name,action,severity,enabled FROM rules WHERE id=$1`, f.runtimeB).Scan(&name, &action, &severity, &enabled); err != nil {
		t.Fatalf("read tenant B rule: %v", err)
	}
	if name != "runtime-b" || action != "audit" || severity != "high" || !enabled {
		t.Fatalf("tenant B rule was mutated: name=%q action=%q severity=%q enabled=%v", name, action, severity, enabled)
	}
	var foreignCreated int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rules WHERE id='rule_foreign_create'`).Scan(&foreignCreated); err != nil || foreignCreated != 0 {
		t.Fatalf("foreign create count=%d err=%v, want 0", foreignCreated, err)
	}
}

func TestBatchUpdateByTypeUpdatesOnlyOwnedRuntimeRules(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	block := "block"
	disabled := false

	if err := repo.BatchUpdateByType(ctx, f.tenantA, f.ruleSetA, "keyword", &disabled, &block, nil); err != nil {
		t.Fatalf("BatchUpdateByType: %v", err)
	}
	got := map[string]struct {
		action  string
		enabled bool
	}{}
	rows, err := f.pool.Query(ctx, `SELECT id,action,enabled FROM rules ORDER BY id`)
	if err != nil {
		t.Fatalf("query rules: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, action string
		var enabled bool
		if err := rows.Scan(&id, &action, &enabled); err != nil {
			t.Fatalf("scan rules: %v", err)
		}
		got[id] = struct {
			action  string
			enabled bool
		}{action, enabled}
	}
	if got[f.runtimeA].action != "block" || got[f.runtimeA].enabled {
		t.Fatalf("owned runtime rule not updated: %+v", got[f.runtimeA])
	}
	if got[f.catalogA].action != "audit" || !got[f.catalogA].enabled {
		t.Fatalf("catalog rule must remain unchanged: %+v", got[f.catalogA])
	}
	if got[f.fakeDomainA].action != "audit" || !got[f.fakeDomainA].enabled {
		t.Fatalf("domain rule with keywords must remain catalog-only: %+v", got[f.fakeDomainA])
	}
	if got[f.runtimeB].action != "audit" || !got[f.runtimeB].enabled {
		t.Fatalf("foreign runtime rule must remain unchanged: %+v", got[f.runtimeB])
	}
}

func TestBatchUpdateByTypeRejectsNonExecutableTypesAndBlankMatchers(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	if _, err := f.pool.Exec(ctx, `INSERT INTO rules(id,rule_set_id,rule_type,name,match_config_json,action,enabled) VALUES
		('blank-regex',$1,'regex','blank regex','{"regex":"\t\n"}','audit',true),
		('mismatched-regex',$1,'regex','mismatch','{"keywords":["secret"]}','audit',true)`, f.ruleSetA); err != nil {
		t.Fatalf("insert non-executable rules: %v", err)
	}
	block := "block"
	for _, tc := range []struct {
		ruleType string
		wantErr  error
	}{
		{"prompt_injection", ErrManagedSecurityPolicyReadOnly},
		{"regex", ErrNoRuntimeRules},
	} {
		if err := repo.BatchUpdateByType(ctx, f.tenantA, f.ruleSetA, tc.ruleType, nil, &block, nil); !errors.Is(err, tc.wantErr) {
			t.Fatalf("type=%s error=%v want %v", tc.ruleType, err, tc.wantErr)
		}
	}
	var changed int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rules WHERE action='block'`).Scan(&changed); err != nil || changed != 0 {
		t.Fatalf("non-executable rules changed=%d err=%v", changed, err)
	}
}

func TestToggleEnabledIsAtomicAndPreservesOtherFields(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	var wg sync.WaitGroup
	type result struct {
		enabled bool
		err     error
	}
	results := make(chan result, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			enabled, err := repo.ToggleEnabled(ctx, f.tenantA, f.runtimeA)
			results <- result{enabled: enabled, err: err}
		}()
	}
	wg.Wait()
	close(results)
	seen := map[bool]int{}
	for got := range results {
		if got.err != nil {
			t.Fatalf("ToggleEnabled: %v", got.err)
		}
		seen[got.enabled]++
	}
	if seen[false] != 1 || seen[true] != 1 {
		t.Fatalf("toggle return states=%v, want one false and one true", seen)
	}
	var name, action, severity string
	var priority int
	var enabled bool
	if err := f.pool.QueryRow(ctx, `SELECT name,action,severity,priority,enabled FROM rules WHERE id=$1`, f.runtimeA).Scan(&name, &action, &severity, &priority, &enabled); err != nil {
		t.Fatalf("read toggled rule: %v", err)
	}
	if name != "runtime-a" || action != "audit" || severity != "high" || priority != 0 || !enabled {
		t.Fatalf("toggle overwrote fields: name=%q action=%q severity=%q priority=%d enabled=%v", name, action, severity, priority, enabled)
	}
}

func TestEnsureRuleSetIsAtomicAcrossConcurrentInitializers(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleSetRepository(f.pool)
	const id = "rs_concurrent_default"
	var wg sync.WaitGroup
	type ensureResult struct {
		created bool
		err     error
	}
	results := make(chan ensureResult, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, created, err := repo.Ensure(ctx, f.tenantA, &RuleSet{ID: id, Name: "default", Version: "1.0", SourceType: "system", Published: true})
			results <- ensureResult{created: created, err: err}
		}()
	}
	wg.Wait()
	close(results)
	createdCount := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("Ensure: %v", result.err)
		}
		if result.created {
			createdCount++
		}
	}
	if createdCount != 1 {
		t.Fatalf("created=true results=%d want1", createdCount)
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rule_sets WHERE id=$1 AND tenant_id=$2`, id, f.tenantA).Scan(&count); err != nil || count != 1 {
		t.Fatalf("ensured rows=%d err=%v want 1", count, err)
	}
	if _, _, err := repo.Ensure(ctx, f.tenantB, &RuleSet{ID: id, Name: "foreign", Version: "1.0"}); !errors.Is(err, ErrRuleSetNotFound) {
		t.Fatalf("foreign Ensure error=%v want ErrRuleSetNotFound", err)
	}
}

func TestBatchUpdateByTypeDoesNotCreateMatcherlessRule(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	block := "block"

	if err := repo.BatchUpdateByType(ctx, f.tenantA, f.ruleSetA, "missing_type", nil, &block, nil); !errors.Is(err, ErrNoRuntimeRules) {
		t.Fatalf("BatchUpdateByType error=%v, want ErrNoRuntimeRules", err)
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rules WHERE rule_set_id=$1 AND rule_type='missing_type'`, f.ruleSetA).Scan(&count); err != nil || count != 0 {
		t.Fatalf("matcherless rule count=%d err=%v, want 0", count, err)
	}
}

func TestSeedDefaultSubRulesCreatesStableCodesAndExactBindings(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	if _, err := f.pool.Exec(ctx, `DELETE FROM rules WHERE rule_set_id IN ($1,$2)`, f.ruleSetA, f.ruleSetB); err != nil {
		t.Fatalf("clear fixture rules: %v", err)
	}

	for _, item := range []struct {
		tenant  string
		ruleSet string
	}{{f.tenantA, f.ruleSetA}, {f.tenantB, f.ruleSetB}} {
		created, err := repo.SeedDefaultSubRules(ctx, item.tenant, item.ruleSet)
		if err != nil || created != 241 {
			t.Fatalf("tenant=%s initial seed=(%d,%v), want 241,nil", item.tenant, created, err)
		}
		var policies, coded, exact, bindingRows, fullUUIDs int
		if err := f.pool.QueryRow(ctx, `
			SELECT COUNT(DISTINCT r.id), COUNT(DISTINCT CASE WHEN r.policy_code IS NOT NULL THEN r.id END),
			       COUNT(DISTINCT CASE WHEN b.rule_id IS NOT NULL THEN r.id END), COUNT(b.rule_id),
			       COUNT(DISTINCT CASE WHEN r.id ~ '^rule_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' THEN r.id END)
			FROM rules r
			LEFT JOIN rule_capability_bindings b ON b.rule_id=r.id
			WHERE r.rule_set_id=$1`, item.ruleSet,
		).Scan(&policies, &coded, &exact, &bindingRows, &fullUUIDs); err != nil {
			t.Fatalf("tenant=%s count seeded catalog: %v", item.tenant, err)
		}
		if policies != 241 || coded != 241 || exact != DefaultPolicyExactBindingCount() || bindingRows != DefaultPolicyCapabilityBindingCount() || fullUUIDs != 241 {
			t.Fatalf("tenant=%s policies/coded/exact/bindings/fullUUIDs=%d/%d/%d/%d/%d want 241/241/%d/%d/241", item.tenant, policies, coded, exact, bindingRows, fullUUIDs, DefaultPolicyExactBindingCount(), DefaultPolicyCapabilityBindingCount())
		}
		created, err = repo.SeedDefaultSubRules(ctx, item.tenant, item.ruleSet)
		if err != nil || created != 0 {
			t.Fatalf("tenant=%s second seed=(%d,%v), want 0,nil", item.tenant, created, err)
		}
	}

	classicCode := defaultPolicyCode("prompt_injection", "经典注入指令检测")
	var tenantACode, tenantBCode string
	if err := f.pool.QueryRow(ctx, `SELECT policy_code FROM rules WHERE rule_set_id=$1 AND policy_code=$2`, f.ruleSetA, classicCode).Scan(&tenantACode); err != nil {
		t.Fatalf("read tenant A classic policy: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `SELECT policy_code FROM rules WHERE rule_set_id=$1 AND policy_code=$2`, f.ruleSetB, classicCode).Scan(&tenantBCode); err != nil {
		t.Fatalf("read tenant B classic policy: %v", err)
	}
	if tenantACode != classicCode || tenantBCode != classicCode {
		t.Fatalf("tenant policy codes differ A=%q B=%q want=%q", tenantACode, tenantBCode, classicCode)
	}

	if _, err := f.pool.Exec(ctx, `UPDATE rules SET name='经典注入检测（客户自定义名称）' WHERE rule_set_id=$1 AND policy_code=$2`, f.ruleSetA, classicCode); err != nil {
		t.Fatalf("rename seeded policy: %v", err)
	}
	if created, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA); err != nil || created != 0 {
		t.Fatalf("seed after rename=(%d,%v), want 0,nil", created, err)
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules WHERE rule_set_id=$1`, f.ruleSetA).Scan(&count); err != nil || count != 241 {
		t.Fatalf("policy count after rename seed=%d err=%v want=241", count, err)
	}
}

func TestSeedDefaultSubRulesRollsBackWhenCapabilityCatalogIsIncomplete(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	if _, err := f.pool.Exec(ctx, `DELETE FROM rules WHERE rule_set_id=$1`, f.ruleSetA); err != nil {
		t.Fatalf("clear fixture rules: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `DELETE FROM security_capabilities WHERE category='semantic_roleplay'`); err != nil {
		t.Fatalf("remove required capability: %v", err)
	}
	created, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA)
	if err == nil || created != 0 {
		t.Fatalf("seed with incomplete capabilities=(%d,%v), want 0,error", created, err)
	}
	var count int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules WHERE rule_set_id=$1`, f.ruleSetA).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled-back policy count=%d err=%v want=0", count, err)
	}
}

func TestSeedDefaultSubRulesKeepsPoliciesWhenCapabilityIsDisabled(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	if _, err := f.pool.Exec(ctx, `DELETE FROM rules WHERE rule_set_id=$1`, f.ruleSetA); err != nil {
		t.Fatalf("clear fixture rules: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE security_capabilities SET enabled=false WHERE category='semantic_roleplay'`); err != nil {
		t.Fatalf("disable capability: %v", err)
	}
	created, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA)
	if err != nil || created != 241 {
		t.Fatalf("seed with disabled capability=(%d,%v), want 241,nil", created, err)
	}
	var policies, disabledBindings int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules WHERE rule_set_id=$1`, f.ruleSetA).Scan(&policies); err != nil {
		t.Fatalf("count policies: %v", err)
	}
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM rule_capability_bindings binding
		JOIN rules policy ON policy.id=binding.rule_id
		JOIN security_capabilities capability ON capability.id=binding.capability_id
		WHERE policy.rule_set_id=$1 AND capability.category='semantic_roleplay' AND capability.enabled=false`,
		f.ruleSetA,
	).Scan(&disabledBindings); err != nil {
		t.Fatalf("count disabled capability bindings: %v", err)
	}
	if policies != 241 || disabledBindings != 1 {
		t.Fatalf("policies/disabled bindings=%d/%d want=241/1", policies, disabledBindings)
	}
}

func TestSeedDefaultSubRulesReturnsQueryErrors(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	if _, err := f.pool.Exec(ctx, `DROP TABLE rule_capability_bindings`); err != nil {
		t.Fatalf("drop bindings table: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `DROP TABLE rules`); err != nil {
		t.Fatalf("drop rules table: %v", err)
	}
	if created, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA); err == nil || created != 0 {
		t.Fatalf("SeedDefaultSubRules=(%d,%v), want 0 and query error", created, err)
	}
}

func TestSeedDefaultSubRulesReportsZeroWhenTransactionRollsBack(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	for _, stmt := range []string{
		`CREATE SEQUENCE seed_failure_seq START 1`,
		`CREATE FUNCTION fail_second_seed_insert() RETURNS trigger AS $$
		BEGIN
			IF nextval('seed_failure_seq') = 2 THEN
				RAISE EXCEPTION 'forced second insert failure';
			END IF;
			RETURN NEW;
		END;
		$$ LANGUAGE plpgsql`,
		`CREATE TRIGGER fail_second_seed_insert BEFORE INSERT ON rules FOR EACH ROW EXECUTE FUNCTION fail_second_seed_insert()`,
	} {
		if _, err := f.pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("prepare rollback trigger: %v", err)
		}
	}
	var before int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rules WHERE rule_set_id=$1`, f.ruleSetA).Scan(&before); err != nil {
		t.Fatalf("count rules before seed: %v", err)
	}
	created, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA)
	if err == nil {
		t.Fatal("SeedDefaultSubRules must return the forced insert error")
	}
	if created != 0 {
		t.Fatalf("created=%d want 0 because the transaction rolled back", created)
	}
	var after int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rules WHERE rule_set_id=$1`, f.ruleSetA).Scan(&after); err != nil {
		t.Fatalf("count rules after seed: %v", err)
	}
	if after != before {
		t.Fatalf("rule count after rollback=%d want %d", after, before)
	}
}

func TestRuleSetCreateCannotSmuggleAnotherTenant(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleSetRepository(f.pool)
	ruleSet := &RuleSet{ID: "rs_forced_owner", TenantID: f.tenantB, Name: "forced", Version: "1.0", SourceType: "manual"}
	if err := repo.Create(ctx, f.tenantA, ruleSet); err != nil {
		t.Fatalf("Create rule set: %v", err)
	}
	var storedTenant string
	if err := f.pool.QueryRow(ctx, `SELECT tenant_id FROM rule_sets WHERE id=$1`, ruleSet.ID).Scan(&storedTenant); err != nil {
		t.Fatalf("read created rule set: %v", err)
	}
	if storedTenant != f.tenantA || ruleSet.TenantID != f.tenantA {
		t.Fatalf("stored tenant=%q struct tenant=%q, want %q", storedTenant, ruleSet.TenantID, f.tenantA)
	}
}

// 新租户的默认“辱骂脏话”策略与同类内容安全一致（block），并绑定新词表能力和旧的强辱骂组合规则；
// 存量租户由迁移 992 以 audit 落库，不走这条路径。
func TestSeedDefaultSubRulesNewTenantGetsProfanityPolicyBlockingWithBothCapabilities(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	if _, err := f.pool.Exec(ctx, `DELETE FROM rules WHERE rule_set_id=$1`, f.ruleSetA); err != nil {
		t.Fatalf("clear fixture rules: %v", err)
	}
	if _, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA); err != nil {
		t.Fatalf("seed default policies: %v", err)
	}
	const policyCode = "builtin.content_safety.ffbbdfb2e823022d"
	var action, severity, name string
	var enabled bool
	if err := f.pool.QueryRow(ctx,
		`SELECT action,severity,name,enabled FROM rules WHERE rule_set_id=$1 AND policy_code=$2`,
		f.ruleSetA, policyCode,
	).Scan(&action, &severity, &name, &enabled); err != nil {
		t.Fatalf("read profanity policy: %v", err)
	}
	var harassmentAction string
	if err := f.pool.QueryRow(ctx,
		`SELECT action FROM rules WHERE rule_set_id=$1 AND policy_code=$2`,
		f.ruleSetA, defaultPolicyCode("content_safety", "骚扰/霸凌内容"),
	).Scan(&harassmentAction); err != nil {
		t.Fatalf("read harassment policy: %v", err)
	}
	if name != "辱骂脏话" || !enabled || action != "block" || action != harassmentAction {
		t.Fatalf("profanity policy name=%q enabled=%v action=%q harassment action=%q", name, enabled, action, harassmentAction)
	}
	rows, err := f.pool.Query(ctx, `
		SELECT c.category FROM rule_capability_bindings b
		JOIN rules r ON r.id=b.rule_id
		JOIN security_capabilities c ON c.id=b.capability_id
		WHERE r.rule_set_id=$1 AND r.policy_code=$2 ORDER BY c.category`, f.ruleSetA, policyCode)
	if err != nil {
		t.Fatalf("read profanity bindings: %v", err)
	}
	defer rows.Close()
	var categories []string
	for rows.Next() {
		var category string
		if err := rows.Scan(&category); err != nil {
			t.Fatalf("scan binding: %v", err)
		}
		categories = append(categories, category)
	}
	want := []string{"content_profanity_abuse", "harassment_profanity_cn"}
	if !reflect.DeepEqual(categories, want) {
		t.Fatalf("profanity capability bindings=%v want=%v", categories, want)
	}
}

// 存量租户升级：迁移 992 先以 audit 落库，随后控制面启动时的默认策略补全不得把它改成 block，
// 也不得重复创建；客户把动作改成 block 后，再次执行迁移同样不覆盖。
func TestMigration992ExistingTenantGetsAuditAndSeedDoesNotOverrideIt(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	repo := NewRuleRepository(f.pool)
	const policyCode = "builtin.content_safety.ffbbdfb2e823022d"
	if _, err := f.pool.Exec(ctx, `DELETE FROM rules WHERE rule_set_id=$1`, f.ruleSetA); err != nil {
		t.Fatalf("clear fixture rules: %v", err)
	}
	if _, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA); err != nil {
		t.Fatalf("seed default policies: %v", err)
	}
	// 模拟升级前的存量租户：目录已采用，但还没有“辱骂脏话”。
	if _, err := f.pool.Exec(ctx, `DELETE FROM rules WHERE rule_set_id=$1 AND policy_code=$2`, f.ruleSetA, policyCode); err != nil {
		t.Fatalf("remove profanity policy to simulate pre-992 tenant: %v", err)
	}
	body, err := os.ReadFile("../../../../deploy/migrations/992_profanity_abuse_policy.sql")
	if err != nil {
		t.Fatalf("read migration 992: %v", err)
	}
	// 夹具的能力表是精简版且已含这两个能力，只执行迁移里补策略与绑定的那条语句；
	// 能力登记语句由 deploy/tests/test_992_profanity_abuse_policy.sh 在完整库上验证。
	parts := strings.SplitN(string(body), "WITH policy_seed AS", 2)
	if len(parts) != 2 {
		t.Fatal("migration 992 must contain the policy_seed statement")
	}
	body = []byte("WITH policy_seed AS" + parts[1])
	for run := 1; run <= 2; run++ {
		if _, err := f.pool.Exec(ctx, string(body)); err != nil {
			t.Fatalf("migration 992 run %d: %v", run, err)
		}
	}
	readAction := func() (string, int) {
		var action string
		var bindings int
		if err := f.pool.QueryRow(ctx, `
			SELECT r.action, (SELECT COUNT(*) FROM rule_capability_bindings b WHERE b.rule_id=r.id)
			FROM rules r WHERE r.rule_set_id=$1 AND r.policy_code=$2`, f.ruleSetA, policyCode,
		).Scan(&action, &bindings); err != nil {
			t.Fatalf("read migrated profanity policy: %v", err)
		}
		return action, bindings
	}
	if action, bindings := readAction(); action != "audit" || bindings != 2 {
		t.Fatalf("migrated existing tenant action=%q bindings=%d want audit/2", action, bindings)
	}
	created, err := repo.SeedDefaultSubRules(ctx, f.tenantA, f.ruleSetA)
	if err != nil || created != 0 {
		t.Fatalf("startup seed after migration=(%d,%v) want 0,nil", created, err)
	}
	if action, bindings := readAction(); action != "audit" || bindings != 2 {
		t.Fatalf("startup seed changed migrated policy action=%q bindings=%d", action, bindings)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE rules SET action='block' WHERE rule_set_id=$1 AND policy_code=$2`, f.ruleSetA, policyCode); err != nil {
		t.Fatalf("customer switches to block: %v", err)
	}
	if _, err := f.pool.Exec(ctx, string(body)); err != nil {
		t.Fatalf("migration 992 rerun: %v", err)
	}
	if action, _ := readAction(); action != "block" {
		t.Fatalf("migration rerun overwrote customer action: %q", action)
	}
}
