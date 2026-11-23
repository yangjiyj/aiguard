package bootstrap

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type recordingRuleSetRepo struct {
	ensured []repository.RuleSet
	err     error
}

func (f *recordingRuleSetRepo) Ensure(_ context.Context, tenantID string, ruleSet *repository.RuleSet) (*repository.RuleSet, bool, error) {
	copy := *ruleSet
	copy.TenantID = tenantID
	f.ensured = append(f.ensured, copy)
	if f.err != nil {
		return nil, false, f.err
	}
	return &copy, true, nil
}

type recordingRuleRepo struct {
	seeded [][2]string
	err    error
}

func (f *recordingRuleRepo) SeedDefaultSubRules(_ context.Context, tenantID, ruleSetID string) (int, error) {
	f.seeded = append(f.seeded, [2]string{tenantID, ruleSetID})
	if f.err != nil {
		return 0, f.err
	}
	return 255, nil
}

type staticTenantLister struct {
	ids []string
	err error
}

func (f staticTenantLister) ListSecurityPolicyTenantIDs(context.Context) ([]string, error) {
	return append([]string(nil), f.ids...), f.err
}

func TestEnsureTenantPolicyDefaultsUsesStableIdempotentRuleSet(t *testing.T) {
	ruleSets := &recordingRuleSetRepo{}
	rules := &recordingRuleRepo{}
	if err := EnsureTenantPolicyDefaults(context.Background(), "tenant-new", "user-admin", ruleSets, rules); err != nil {
		t.Fatalf("ensure tenant defaults: %v", err)
	}
	if len(ruleSets.ensured) != 1 {
		t.Fatalf("ensure calls=%d want=1", len(ruleSets.ensured))
	}
	wantID := repository.DefaultSecurityRuleSetID("tenant-new")
	got := ruleSets.ensured[0]
	if got.ID != wantID || got.TenantID != "tenant-new" || got.SourceType != "system" || !got.Published || got.CreatedBy != "user-admin" {
		t.Fatalf("ensured rule set=%+v", got)
	}
	if !reflect.DeepEqual(rules.seeded, [][2]string{{"tenant-new", wantID}}) {
		t.Fatalf("seed calls=%v", rules.seeded)
	}

	if err := EnsureTenantPolicyDefaults(context.Background(), "tenant-new", "user-admin", ruleSets, rules); err != nil {
		t.Fatalf("repeat ensure tenant defaults: %v", err)
	}
	if len(ruleSets.ensured) != 2 || len(rules.seeded) != 2 || ruleSets.ensured[1].ID != wantID {
		t.Fatalf("repeat calls ensured=%v seeded=%v", ruleSets.ensured, rules.seeded)
	}
}

func TestEnsureAllTenantPolicyDefaultsBackfillsEveryCustomerTenant(t *testing.T) {
	ruleSets := &recordingRuleSetRepo{}
	rules := &recordingRuleRepo{}
	lister := staticTenantLister{ids: []string{"tenant-a", "tenant-b"}}
	if err := EnsureAllTenantPolicyDefaults(context.Background(), lister, ruleSets, rules); err != nil {
		t.Fatalf("backfill tenant defaults: %v", err)
	}
	if len(ruleSets.ensured) != 2 || len(rules.seeded) != 2 {
		t.Fatalf("backfill ensured=%d seeded=%d", len(ruleSets.ensured), len(rules.seeded))
	}
	if rules.seeded[0][0] != "tenant-a" || rules.seeded[1][0] != "tenant-b" {
		t.Fatalf("backfill tenant order=%v", rules.seeded)
	}
}

func TestEnsureAllTenantPolicyDefaultsFailsClosed(t *testing.T) {
	want := errors.New("seed failed")
	ruleSets := &recordingRuleSetRepo{}
	rules := &recordingRuleRepo{err: want}
	err := EnsureAllTenantPolicyDefaults(context.Background(), staticTenantLister{ids: []string{"tenant-a", "tenant-b"}}, ruleSets, rules)
	if !errors.Is(err, want) {
		t.Fatalf("backfill error=%v want seed error", err)
	}
	if len(rules.seeded) != 1 {
		t.Fatalf("backfill continued after failure: %v", rules.seeded)
	}
}
