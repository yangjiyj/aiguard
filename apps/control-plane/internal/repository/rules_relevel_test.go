package repository

import (
	"context"
	"os"
	"regexp"
	"testing"
)

var relevelRow = regexp.MustCompile(`\('(builtin\.[a-z_]+\.[0-9a-f]+)','(low|medium|high|critical)','(low|medium|high|critical)'\)`)

func TestDefaultSubRulesMatchTheRelevelMigration(t *testing.T) {
	raw, err := os.ReadFile("../../../../deploy/migrations/997_relevel_preloaded_policy_severity.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	rows := relevelRow.FindAllStringSubmatch(string(raw), -1)
	if len(rows) != 44 {
		t.Fatalf("migration must relevel 44 policies, parsed %d", len(rows))
	}
	seeded := map[string]string{}
	for _, rules := range defaultSubRules {
		for _, rule := range rules {
			seeded[rule.PolicyCode] = rule.Severity
		}
	}
	for _, row := range rows {
		code, newSeverity := row[1], row[3]
		got, ok := seeded[code]
		if !ok {
			t.Errorf("%s is releveled but not seeded", code)
			continue
		}
		if got != newSeverity {
			t.Errorf("%s seeded as %s, migration sets %s", code, got, newSeverity)
		}
	}
}

// 重新定级只改基准级别：租户在覆盖表里选的级别仍然优先，没有覆盖的租户跟随新基准。
func TestRelevelMigrationKeepsTenantSeverityOverrides(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	const code = "builtin.code_security.d82567ae4c6cba2a" // SQL 注入代码生成：严重 -> 中危
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO rules(id,rule_set_id,policy_code,rule_type,name,severity,scope_json,match_config_json,action,enabled,description)
		VALUES('rule_t10_shared','ruleset_builtin_generic',$1,'code_security','SQL 注入代码生成','critical','{"scene":"code_security"}','{}','block',true,'')`, code); err != nil {
		t.Fatalf("insert shared preloaded policy: %v", err)
	}
	// 还原到升级前的状态：所有携带该策略编码的行都是旧级别。
	if _, err := f.pool.Exec(ctx, `UPDATE rules SET severity='critical' WHERE policy_code=$1`, code); err != nil {
		t.Fatalf("rewind to the old severity: %v", err)
	}
	high := "high"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_t10_shared", SecurityPolicyUpdate{Severity: &high}); err != nil {
		t.Fatalf("tenant A override: %v", err)
	}

	migration, err := os.ReadFile("../../../../deploy/migrations/997_relevel_preloaded_policy_severity.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	for round := 0; round < 2; round++ { // 迁移可重复执行
		if _, err := f.pool.Exec(ctx, string(migration)); err != nil {
			t.Fatalf("apply migration round %d: %v", round, err)
		}
	}

	a, err := f.repo.GetSecurityPolicy(ctx, f.tenantA, "rule_t10_shared")
	if err != nil || a.Severity != "high" || !a.SeverityOverridden || a.DefaultSeverity != "medium" {
		t.Fatalf("tenant A must keep its override over the new base: %+v err=%v", a, err)
	}
	b, err := f.repo.GetSecurityPolicy(ctx, f.tenantB, "rule_t10_shared")
	if err != nil || b.Severity != "medium" || b.SeverityOverridden {
		t.Fatalf("tenant B without override must follow the new base: %+v err=%v", b, err)
	}
	var action string
	var enabled bool
	if err := f.pool.QueryRow(ctx, `SELECT action,enabled FROM rules WHERE id='rule_t10_shared'`).Scan(&action, &enabled); err != nil || action != "block" || !enabled {
		t.Fatalf("relevel must not touch action or enabled: action=%q enabled=%v err=%v", action, enabled, err)
	}
	var stale int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM rules WHERE policy_code=$1 AND severity<>'medium'`, code).Scan(&stale); err != nil || stale != 0 {
		t.Fatalf("rows still on the old base: %d err=%v", stale, err)
	}
}
