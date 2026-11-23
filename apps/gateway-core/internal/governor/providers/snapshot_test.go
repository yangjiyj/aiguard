package providers

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
)

func TestSnapshotReaderDoesNotConvertRedisFaultOrCorruptUsageToZero(t *testing.T) {
	client := atomicAdmissionRedis(t)
	reader := NewSnapshotReader(client)
	ctx := context.Background()
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	key := BudgetKey("tenant", "tenant-a", time.Now().In(location).Format("2006-01"))
	if err := client.HSet(ctx, key, "tokens", "not-a-number").Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.GetMulti(ctx, governor.ScopeRef{TenantID: "tenant-a"}); err == nil || !strings.Contains(err.Error(), "tokens") {
		t.Fatalf("corrupt snapshot error=%v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.GetMulti(ctx, governor.ScopeRef{TenantID: "tenant-a"}); err == nil {
		t.Fatal("closed Redis must return a runtime fault, not a zero snapshot")
	}
}

func TestSnapshotScopesUseOnlyStableKeyBucket(t *testing.T) {
	scopes := snapshotScopes(governor.ScopeRef{KeyID: "key-id-1"})
	got := map[string]string{}
	for _, scope := range scopes {
		got[scope.scope] = scope.id
	}
	if got["key"] != "key-id-1" {
		t.Fatalf("unexpected key snapshot scopes: %+v", got)
	}
	if _, ok := got["key_legacy"]; ok {
		t.Fatal("prefix compatibility bucket must not be read")
	}
}

// 7.1/7.2 regression against a real Valkey: drive real AtomicAdmission
// Admit/Settle for a Shanghai tenant policy and a New York project policy,
// keep one lease in flight, then read the snapshot. Before the fix the reader
// saw MonthCost=0 (float "cost" is never written), Rpm=0/Concurrency=0 (legacy
// keys are never written) and all-zero project usage (the @hash bucket).
func TestSnapshotReaderReadsAtomicAdmissionKeysAcrossTimezones(t *testing.T) {
	client := atomicAdmissionRedis(t)
	ctx := context.Background()
	quotas := []governor.ScopedQuota{
		{Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce", Limits: governor.EffectiveQuotaInput{
			RPMLimit: 100, ConcurrencyLimit: 10, MonthlyBudgetMicros: 50_000_000, OverageAction: "rate_limit"}},
		{Scope: "project", ID: "project-a", EnforcementMode: "enforce", Limits: governor.EffectiveQuotaInput{
			RPMLimit: 100, ConcurrencyLimit: 10, MonthlyBudgetMicros: 50_000_000, QuotaTimezone: "America/New_York", OverageAction: "rate_limit"}},
	}
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: quotas})
	ref := governor.ScopeRef{TenantID: "tenant-a", ProjectID: "project-a"}
	for i, amount := range []int64{1_234_567, 2_000_000} {
		lease, err := admission.Admit(ctx, governor.AdmissionRequest{
			Ref: ref, RequestID: "ws7-snapshot-" + string(rune('a'+i)), EstimatedTokens: 100,
			EstimatedCostMicros: amount, CostEstimateAvailable: true,
		})
		if err != nil {
			t.Fatalf("admit %d: %v", i, err)
		}
		if err := admission.Settle(ctx, lease, 8, amount, true); err != nil {
			t.Fatalf("settle %d: %v", i, err)
		}
	}
	if _, err := admission.Admit(ctx, governor.AdmissionRequest{
		Ref: ref, RequestID: "ws7-snapshot-inflight", EstimatedTokens: 10, EstimatedCostMicros: 1, CostEstimateAvailable: true,
	}); err != nil {
		t.Fatalf("inflight admit: %v", err)
	}

	got, err := NewSnapshotReader(client).GetScoped(ctx, ref, quotas)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"tenant:tenant-a", "project:project-a"} {
		snap := got[key]
		if snap.MonthCostMicros != 3_234_567 || snap.DayCostMicros != 3_234_567 {
			t.Errorf("%s cost micros: %+v", key, snap)
		}
		if snap.MonthTokens != 16 || snap.DayTokens != 16 {
			t.Errorf("%s tokens: %+v", key, snap)
		}
		if snap.Rpm != 3 {
			t.Errorf("%s rpm=%d want 3 (two settled + one in flight in the current minute)", key, snap.Rpm)
		}
		if snap.Concurrency != 1 {
			t.Errorf("%s concurrency=%d want 1 in-flight lease", key, snap.Concurrency)
		}
	}
}

func TestSnapshotReaderRejectsFloatCostMicros(t *testing.T) {
	client := atomicAdmissionRedis(t)
	ctx := context.Background()
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	key := BudgetKey("tenant", "tenant-a", time.Now().In(location).Format("2006-01"))
	if err := client.HSet(ctx, key, "cost_micros", "1.5").Err(); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSnapshotReader(client).GetMulti(ctx, governor.ScopeRef{TenantID: "tenant-a"}); err == nil || !strings.Contains(err.Error(), "cost_micros") {
		t.Fatalf("non-integer cost_micros must surface, err=%v", err)
	}
}
