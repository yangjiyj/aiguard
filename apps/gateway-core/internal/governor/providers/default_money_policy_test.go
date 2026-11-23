package providers

import (
	"context"
	"errors"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/redis/go-redis/v9"
	"testing"
)

func TestMoneyPolicyDefaultRetainsExplicitNotifyAndSoft(t *testing.T) {
	client := atomicAdmissionRedis(t)
	for _, tc := range []struct {
		mode, action string
		blocked      bool
	}{{"enforce", "rate_limit", true}, {"enforce", "notify", false}, {"soft", "rate_limit", false}, {"soft", "notify", false}} {
		a := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{Scope: "tenant", ID: "t", EnforcementMode: tc.mode, Limits: governor.EffectiveQuotaInput{MonthlyBudgetMicros: 100, OverageAction: tc.action}}}})
		lease, err := a.Admit(context.Background(), governor.AdmissionRequest{Ref: governor.ScopeRef{TenantID: "t"}, RequestID: tc.mode + tc.action, EstimatedTokens: 1, EstimatedCostMicros: 101, CostEstimateAvailable: true})
		if (err != nil) != tc.blocked {
			t.Fatalf("%s/%s blocked=%v err=%v", tc.mode, tc.action, tc.blocked, err)
		}
		if tc.blocked {
			var limit *governor.AdmissionLimitError
			if !errors.As(err, &limit) || !limit.BudgetCutoff {
				t.Fatalf("missing monetary refusal details: %v", err)
			}
		} else {
			_ = a.Release(context.Background(), lease, 0, 0)
		}
	}
}

func TestUnpricedAdmissionKeepsRequestAndTokenLimits(t *testing.T) {
	client := atomicAdmissionRedis(t)
	a := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{Scope: "tenant", ID: "t", EnforcementMode: "enforce", Limits: governor.EffectiveQuotaInput{MonthlyBudgetMicros: 1, MonthlyTokenLimit: 5, OverageAction: "rate_limit"}}}})
	lease, err := a.Admit(context.Background(), governor.AdmissionRequest{Ref: governor.ScopeRef{TenantID: "t"}, RequestID: "unpriced-ok", EstimatedTokens: 2, CostEstimateMissingPrice: true})
	if err != nil {
		t.Fatalf("unpriced money bypass: %v", err)
	}
	_ = a.Settle(context.Background(), lease, 2, 0, false)
	_, err = a.Admit(context.Background(), governor.AdmissionRequest{Ref: governor.ScopeRef{TenantID: "t"}, RequestID: "unpriced-token-limit", EstimatedTokens: 4, CostEstimateMissingPrice: true})
	var limit *governor.AdmissionLimitError
	if !errors.As(err, &limit) || limit.Metric != "month_tokens" {
		t.Fatalf("token limit must still enforce: %v", err)
	}
}

func TestNotifyZeroBudgetNeverRejectsOrFailsClosed(t *testing.T) {
	for _, client := range []*redis.Client{atomicAdmissionRedis(t), nil} {
		quota := staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{Scope: "tenant", ID: "notify-zero", EnforcementMode: "enforce", Limits: governor.EffectiveQuotaInput{DailyBudgetBlocked: true, MonthlyBudgetBlocked: true, DailyTokenBlocked: true, MonthlyTokenBlocked: true, OverageAction: "notify"}}}}
		a := NewAtomicAdmission(client, quota)
		lease, err := a.Admit(context.Background(), governor.AdmissionRequest{Ref: governor.ScopeRef{TenantID: "notify-zero"}, RequestID: "notify-zero", EstimatedTokens: 2, EstimatedCostMicros: 5, CostEstimateAvailable: true})
		if err != nil || lease == nil {
			t.Fatalf("notify zero budget refused: %v", err)
		}
		if len(lease.Observations) < 4 {
			t.Fatalf("blocked flags must still be observed: %+v", lease.Observations)
		}
		if client != nil {
			_ = a.Release(context.Background(), lease, 0, 0)
		}
	}
}
