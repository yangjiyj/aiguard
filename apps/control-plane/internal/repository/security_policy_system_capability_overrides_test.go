package repository

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func bindSystemDefaultCapability(t *testing.T, f securityPoliciesFixture, ruleID, category, mode string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `
		UPDATE rules
		SET rule_type='data_leak', match_config_json='{}'::jsonb,
		    scope_json=jsonb_set(COALESCE(scope_json,'{}'::jsonb),'{scene}','"data_leak"'::jsonb,true)
		WHERE id=$1`, ruleID); err != nil {
		t.Fatalf("make system fixture capability-only: %v", err)
	}
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
		SELECT $1,id,$3,1,'{}'::jsonb
		FROM security_capabilities WHERE category=$2`, ruleID, category, mode); err != nil {
		t.Fatalf("bind system default capability: %v", err)
	}
}

func TestBuiltinRuleCapabilityOverrideMigrationIsIdempotentAndTransactional(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		CREATE TABLE builtin_rule_overrides (
 redaction_json JSONB,
 semantic_action VARCHAR(16),
			tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
			rule_id VARCHAR(64) NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
			action TEXT CHECK(action IN ('audit','mask','block')),
			enabled BOOLEAN,
			created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			PRIMARY KEY(tenant_id,rule_id),
			CONSTRAINT ck_builtin_rule_overrides_has_value CHECK(action IS NOT NULL OR enabled IS NOT NULL)
		)`); err != nil {
		t.Fatalf("create pre-127 override table: %v", err)
	}
	body, err := os.ReadFile("../../../../deploy/migrations/127_builtin_rule_capability_overrides.sql")
	if err != nil {
		t.Fatalf("read migration 127: %v", err)
	}
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin migration transaction: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for attempt := 0; attempt < 2; attempt++ {
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply migration 127 attempt %d: %v", attempt+1, err)
		}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO builtin_rule_overrides(
			tenant_id,rule_id,capability_categories,binding_mode
		) VALUES($1,$2,'[]'::jsonb,'any')`, f.tenantA, f.runtimeA); err != nil {
		t.Fatalf("insert explicit empty capability override: %v", err)
	}
	invalidValues := []struct {
		name       string
		categories any
		mode       any
	}{
		{name: "mode without categories", categories: nil, mode: "any"},
		{name: "categories without mode", categories: []string{"phone_cn"}, mode: nil},
		{name: "non-array categories", categories: map[string]any{"phone_cn": true}, mode: "any"},
	}
	for _, tc := range invalidValues {
		if _, err := tx.Exec(ctx, "SAVEPOINT invalid_override"); err != nil {
			t.Fatalf("savepoint %s: %v", tc.name, err)
		}
		encoded, _ := json.Marshal(tc.categories)
		_, insertErr := tx.Exec(ctx, `
			UPDATE builtin_rule_overrides
			SET capability_categories=$1::jsonb,binding_mode=$2
			WHERE tenant_id=$3 AND rule_id=$4`, encoded, tc.mode, f.tenantA, f.runtimeA)
		if insertErr == nil {
			t.Fatalf("migration accepted %s", tc.name)
		}
		if _, err := tx.Exec(ctx, "ROLLBACK TO SAVEPOINT invalid_override"); err != nil {
			t.Fatalf("rollback invalid %s: %v", tc.name, err)
		}
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatalf("rollback migration 127: %v", err)
	}
	var columns int
	if err := f.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='builtin_rule_overrides'
		  AND column_name IN ('capability_categories','binding_mode')`).Scan(&columns); err != nil {
		t.Fatalf("inspect rolled back migration: %v", err)
	}
	if columns != 0 {
		t.Fatalf("migration rollback left %d capability override columns", columns)
	}
}

func TestSystemPolicyCapabilityOverrideIsEffectiveAndTenantIsolated(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	bindSystemDefaultCapability(t, f, "rule_g_passport", "email", "any")
	ctx := context.Background()

	before, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_passport")
	if err != nil || len(before.Capabilities) != 1 || before.Capabilities[0].Category != "email" {
		t.Fatalf("tenant did not inherit product binding before override: %#v err=%v", before, err)
	}
	categories := []string{"phone_cn"}
	mode := "all"
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{
		CapabilityCategories: &categories,
		BindingMode:          &mode,
	})
	if err != nil {
		t.Fatalf("set tenant system-policy capability override: %v", err)
	}
	if len(updated.Capabilities) != 1 || updated.Capabilities[0].Category != "phone_cn" || updated.Capabilities[0].BindingMode != "all" {
		t.Fatalf("tenant effective capabilities=%#v", updated.Capabilities)
	}
	other, err := f.repo.GetSecurityPolicy(ctx, f.tenantB, "rule_g_passport")
	if err != nil || len(other.Capabilities) != 1 || other.Capabilities[0].Category != "email" || other.Capabilities[0].BindingMode != "any" {
		t.Fatalf("tenant override leaked to another tenant: %#v err=%v", other, err)
	}
	var baseCategory, baseMode string
	if err := f.pool.QueryRow(ctx, `
		SELECT cap.category,binding.binding_mode
		FROM rule_capability_bindings binding
		JOIN security_capabilities cap ON cap.id=binding.capability_id
		WHERE binding.rule_id='rule_g_passport'`).Scan(&baseCategory, &baseMode); err != nil {
		t.Fatalf("read product binding after override: %v", err)
	}
	if baseCategory != "email" || baseMode != "any" {
		t.Fatalf("tenant override mutated product binding category=%q mode=%q", baseCategory, baseMode)
	}
	var storedCategories []byte
	var storedMode string
	var action *string
	var enabled *bool
	if err := f.pool.QueryRow(ctx, `
		SELECT capability_categories,binding_mode,action,enabled
		FROM builtin_rule_overrides WHERE tenant_id=$1 AND rule_id='rule_g_passport'`, f.tenantA,
	).Scan(&storedCategories, &storedMode, &action, &enabled); err != nil {
		t.Fatalf("read system capability override: %v", err)
	}
	if string(storedCategories) != `["phone_cn"]` || storedMode != "all" || action != nil || enabled != nil {
		t.Fatalf("stored partial override categories=%s mode=%q action=%v enabled=%v", storedCategories, storedMode, action, enabled)
	}
}

func TestSystemPolicyCapabilityOverrideCanExplicitlyClearWithoutLosingOtherFields(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	bindSystemDefaultCapability(t, f, "rule_g_passport", "email", "any")
	ctx := context.Background()
	block := "block"
	disabled := false
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{
		Action: &block, Enabled: &disabled,
	}); err != nil {
		t.Fatalf("set action/enabled override: %v", err)
	}
	empty := []string{}
	mode := "any"
	updated, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{
		CapabilityCategories: &empty,
		BindingMode:          &mode,
	})
	if err != nil {
		t.Fatalf("explicitly clear tenant capability binding: %v", err)
	}
	if len(updated.Capabilities) != 0 || updated.Action != block || updated.Enabled {
		t.Fatalf("explicit clear lost partial fields or inherited defaults: %#v", updated)
	}
	other, err := f.repo.GetSecurityPolicy(ctx, f.tenantB, "rule_g_passport")
	if err != nil || len(other.Capabilities) != 1 || other.Capabilities[0].Category != "email" {
		t.Fatalf("explicit clear leaked across tenants: %#v err=%v", other, err)
	}
}

func TestSystemPolicyCapabilityOverrideValidatesEnabledCatalogAndAction(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	bindSystemDefaultCapability(t, f, "rule_g_passport", "email", "any")
	if _, err := f.pool.Exec(ctx, `UPDATE security_capabilities SET enabled=false WHERE category='phone_cn'`); err != nil {
		t.Fatalf("disable test capability: %v", err)
	}
	disabledCategory := []string{"phone_cn"}
	mode := "any"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{
		CapabilityCategories: &disabledCategory, BindingMode: &mode,
	}); !errors.Is(err, ErrInvalidSecurityPolicy) {
		t.Fatalf("disabled capability error=%v want ErrInvalidSecurityPolicy", err)
	}
	if _, err := f.pool.Exec(ctx, `UPDATE security_capabilities SET enabled=true WHERE category='phone_cn'`); err != nil {
		t.Fatalf("restore test capability: %v", err)
	}
	nonMaskable := []string{"keyword_classic_injection"}
	mask := "mask"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{
		CapabilityCategories: &nonMaskable, BindingMode: &mode, Action: &mask,
	}); !errors.Is(err, ErrPolicyActionUnsupported) {
		t.Fatalf("non-maskable capability error=%v want ErrPolicyActionUnsupported", err)
	}
	var rows int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM builtin_rule_overrides WHERE tenant_id=$1 AND rule_id='rule_g_passport'`, f.tenantA).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("rejected overrides persisted rows=%d err=%v", rows, err)
	}
}

func TestSystemPolicyDefinitionFieldsRemainReadOnly(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	name := "tenant renamed system policy"
	description := "tenant replaced product definition"
	scene := "custom_rules"
	matcher := &SecurityPolicyMatcherInput{Type: "keyword", ConfigJSON: json.RawMessage(`{"keywords":["override"]}`)}
	updates := []SecurityPolicyUpdate{
		{Name: &name},
		{Description: &description},
		{Scene: &scene},
		{Matcher: matcher},
		{ClearMatcher: true},
	}
	for index, update := range updates {
		if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", update); !errors.Is(err, ErrSystemPolicyFieldReadOnly) {
			t.Fatalf("read-only update %d error=%v want ErrSystemPolicyFieldReadOnly", index, err)
		}
	}
}

func TestSystemPolicyCapabilityOverrideConcurrentPatchesPreserveAllFields(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	bindSystemDefaultCapability(t, f, "rule_g_passport", "email", "any")
	block := "block"
	disabled := false
	categories := []string{"phone_cn"}
	mode := "all"
	start := make(chan struct{})
	errs := make(chan error, 3)
	go func() {
		<-start
		_, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Action: &block})
		errs <- err
	}()
	go func() {
		<-start
		_, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{Enabled: &disabled})
		errs <- err
	}()
	go func() {
		<-start
		_, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{
			CapabilityCategories: &categories, BindingMode: &mode,
		})
		errs <- err
	}()
	close(start)
	for index := 0; index < 3; index++ {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent partial override: %v", err)
		}
	}
	updated, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_g_passport")
	if err != nil {
		t.Fatalf("read concurrent override: %v", err)
	}
	if updated.Action != block || updated.Enabled || len(updated.Capabilities) != 1 || updated.Capabilities[0].Category != "phone_cn" || updated.Capabilities[0].BindingMode != "all" {
		t.Fatalf("concurrent patch lost a field: %#v", updated)
	}
}

func TestSystemPolicyCapabilityOverrideBatchIsAtomic(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	bindSystemDefaultCapability(t, f, "rule_g_passport", "email", "any")
	categories := []string{"phone_cn"}
	mode := "all"
	disabled := false
	err := f.repo.BatchUpdateSecurityPolicies(ctx, f.tenantA, []SecurityPolicyBatchUpdate{
		{ID: "rule_g_passport", Update: SecurityPolicyUpdate{CapabilityCategories: &categories, BindingMode: &mode}},
		{ID: "zzzz_missing_policy", Update: SecurityPolicyUpdate{Enabled: &disabled}},
	})
	if !errors.Is(err, ErrSecurityPolicyNotFound) {
		t.Fatalf("batch missing policy error=%v want ErrSecurityPolicyNotFound", err)
	}
	var rows int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM builtin_rule_overrides WHERE tenant_id=$1 AND rule_id='rule_g_passport'`, f.tenantA).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("failed batch persisted capability override rows=%d err=%v", rows, err)
	}
}
