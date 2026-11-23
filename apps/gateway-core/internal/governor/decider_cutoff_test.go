package governor

import (
	"context"
	"errors"
	"testing"
)

type failingScopedQuota struct{ scopedQuotaStub }

func (s *failingScopedQuota) ScopedQuotas(context.Context, ScopeRef) ([]ScopedQuota, error) {
	return nil, errors.New("db down")
}

type erroringSnap struct{}

func (erroringSnap) GetMulti(context.Context, ScopeRef) (map[string]Snapshot, error) {
	return nil, errors.New("redis down")
}

// 断流关闭：配额读取失败仍然 fail-open（与现状一致）。

func TestDecideFailsClosedWhenBudgetCutoffIsOn(t *testing.T) {
	decider := New(erroringSnap{}, &failingScopedQuota{})
	for name, got := range map[string]Decision{
		"realtime":    decider.Decide(context.Background(), ScopeRef{TenantID: "t"}),
		"nonrealtime": decider.DecideNonRealtime(context.Background(), ScopeRef{TenantID: "t"}),
	} {
		if got.Action != ActionRateLimit || got.AlertOnly || !got.BudgetCutoff || got.TriggeredMetric != "runtime_fault" {
			t.Fatalf("%s: cutoff on must fail closed: %+v", name, got)
		}
	}
}

// 断流开启：快照读取失败时，只对“已配金额预算”的用户 fail-closed，没有金额预算的用户不受影响。
func TestDecideSnapshotFailureOnlyClosesScopesWithMoneyBudget(t *testing.T) {
	withMoney := &scopedQuotaStub{quotas: []ScopedQuota{{Scope: "team", ID: "team-1", EnforcementMode: "enforce", Limits: EffectiveQuotaInput{MonthlyBudgetMicros: 100, OverageAction: "rate_limit"}}}}
	noMoney := &scopedQuotaStub{quotas: []ScopedQuota{{Scope: "team", ID: "team-1", EnforcementMode: "soft", Limits: EffectiveQuotaInput{MonthlyTokenLimit: 100}}}}

	closed := New(erroringSnap{}, withMoney)
	if got := closed.Decide(context.Background(), ScopeRef{TenantID: "t", TeamID: "team-1"}); got.Action != ActionRateLimit || !got.BudgetCutoff {
		t.Fatalf("money budget scope must fail closed: %+v", got)
	}
	open := New(erroringSnap{}, noMoney)
	if got := open.Decide(context.Background(), ScopeRef{TenantID: "t", TeamID: "team-1"}); got.Action != ActionAlert || !got.AlertOnly || got.BudgetCutoff {
		t.Fatalf("scope without money budget must stay fail-open: %+v", got)
	}
}
