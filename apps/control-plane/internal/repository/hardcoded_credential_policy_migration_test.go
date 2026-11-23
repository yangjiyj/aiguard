package repository

import (
	"context"
	"os"
	"testing"
)

const hardcodedCredentialPolicyCode = "builtin.code_security.9640acf0d1083905"

func TestHardcodedCredentialBuiltinDefaultsToBlock(t *testing.T) {
	var found bool
	var action, description string
	for index := range defaultSubRules["code_security"] {
		rule := &defaultSubRules["code_security"][index]
		if rule.PolicyCode == hardcodedCredentialPolicyCode {
			found = true
			action = rule.Action
			description = rule.Description
			break
		}
	}
	if !found {
		t.Fatal("hardcoded credential built-in policy is missing")
	}
	if action != "block" {
		t.Fatalf("action=%q want block", action)
	}
	if description != "检测代码中的硬编码凭据示例，阻断请求" {
		t.Fatalf("description=%q want blocking description", description)
	}
}

func TestHardcodedCredentialForwardMigrationIsTargetedAndIdempotent(t *testing.T) {
	f := newRulesTenantFixture(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO rules(id,rule_set_id,policy_code,rule_type,name,severity,action,enabled,description)
		VALUES
		  ('target-policy',$1,$2,'code_security','硬编码凭据示例','high','mask',true,'检测代码中的硬编码凭据示例，脱敏处理'),
		  ('other-policy',$1,'builtin.code_security.other','code_security','其他策略','high','mask',true,'保持原样')`,
		f.ruleSetA, hardcodedCredentialPolicyCode); err != nil {
		t.Fatalf("seed pre-migration policies: %v", err)
	}
	body, err := os.ReadFile("../../../../deploy/migrations/814_fix_hardcoded_credential_policy_action.sql")
	if err != nil {
		t.Fatalf("read migration 814: %v", err)
	}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := f.pool.Exec(ctx, string(body)); err != nil {
			t.Fatalf("apply migration 814 attempt %d: %v", attempt, err)
		}
	}
	var action, description string
	if err := f.pool.QueryRow(ctx, `
		SELECT action,description FROM rules WHERE id='target-policy'
	`).Scan(&action, &description); err != nil {
		t.Fatalf("read migrated target: %v", err)
	}
	if action != "block" || description != "检测代码中的硬编码凭据示例，阻断请求" {
		t.Fatalf("target action/description=(%q,%q)", action, description)
	}
	if err := f.pool.QueryRow(ctx, `
		SELECT action,description FROM rules WHERE id='other-policy'
	`).Scan(&action, &description); err != nil {
		t.Fatalf("read unrelated policy: %v", err)
	}
	if action != "mask" || description != "保持原样" {
		t.Fatalf("unrelated policy changed to (%q,%q)", action, description)
	}
}
