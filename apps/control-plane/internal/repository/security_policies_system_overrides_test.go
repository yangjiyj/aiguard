package repository

import (
	"context"
	"errors"
	"testing"
)

func TestSystemMatcherPolicyRejectsCapabilityOverride(t *testing.T) {
	f := newSecurityPoliciesFixture(t)
	ctx := context.Background()
	categories := []string{"keyword_classic_injection"}
	mode := "any"
	if _, err := f.repo.UpdateSecurityPolicy(ctx, f.tenantA, "rule_g_passport", SecurityPolicyUpdate{
		CapabilityCategories: &categories,
		BindingMode:          &mode,
	}); !errors.Is(err, ErrPolicyDetectionConflict) {
		t.Fatalf("system matcher capability update error=%v want ErrPolicyDetectionConflict", err)
	}
	var overrideCount int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM builtin_rule_overrides WHERE tenant_id=$1 AND rule_id='rule_g_passport' AND capability_categories IS NOT NULL`, f.tenantA).Scan(&overrideCount); err != nil || overrideCount != 0 {
		t.Fatalf("rejected capability override persisted count=%d err=%v", overrideCount, err)
	}
}
