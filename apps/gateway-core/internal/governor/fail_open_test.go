package governor

import (
	"context"
	"errors"
	"testing"
)

type errProvider struct{}

func (errProvider) GetEnforcementMode(ctx context.Context, ref ScopeRef) string { return "enforce" }
func (errProvider) EffectiveQuota(ctx context.Context, ref ScopeRef) (EffectiveQuotaInput, error) {
	return EffectiveQuotaInput{}, errors.New("simulated db error")
}

type emptySnap struct{}

func (emptySnap) GetMulti(ctx context.Context, ref ScopeRef) (map[string]Snapshot, error) {
	return nil, nil
}

func TestFailClosedOnQuotaError(t *testing.T) {
	d := New(&emptySnap{}, &errProvider{})
	got := d.Decide(context.Background(), ScopeRef{})
	if got.Action != ActionRateLimit || got.AlertOnly || !got.BudgetCutoff {
		t.Errorf("quota storage failure must return a monetary admission fault, got %+v", got)
	}
	if got.TriggeredMetric != "runtime_fault" || got.Reason == "" {
		t.Errorf("expect an explicit runtime fault reason, got %+v", got)
	}
}
