package providers

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
)

// captureAdmissionLog redirects the standard logger for the duration of a test.
func captureAdmissionLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}

// 7.9: a reserved counter that would go negative on settle/release means the
// reservation was already subtracted once. The clamp at 0 must not hide it.
func TestAtomicAdmissionFlagsReservedCounterUnderflowInsteadOfSilentlyClamping(t *testing.T) {
	client := atomicAdmissionRedis(t)
	admission := NewAtomicAdmission(client, staticAdmissionQuotaProvider{quotas: []governor.ScopedQuota{{
		Scope: "tenant", ID: "tenant-a", EnforcementMode: "enforce",
		Limits: governor.EffectiveQuotaInput{
			DailyBudgetMicros: 1000, MonthlyBudgetMicros: 2000,
			OverageAction: "rate_limit", QuotaTimezone: "UTC",
		},
	}}})
	ref := governor.ScopeRef{TenantID: "tenant-a"}
	ctx := context.Background()

	clean, err := admission.Admit(ctx, governor.AdmissionRequest{
		Ref: ref, RequestID: "underflow-clean", EstimatedTokens: 5,
		EstimatedCostMicros: 60, CostEstimateAvailable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	logs := captureAdmissionLog(t)
	if err := admission.Settle(ctx, clean, 4, 40, true); err != nil {
		t.Fatal(err)
	}
	if got := admission.ReservationUnderflows(); got != 0 {
		t.Fatalf("clean settle reported %d underflows", got)
	}
	if strings.Contains(logs.String(), "underflow") {
		t.Fatalf("clean settle logged an underflow: %s", logs.String())
	}

	lease, err := admission.Admit(ctx, governor.AdmissionRequest{
		Ref: ref, RequestID: "underflow-dup", EstimatedTokens: 5,
		EstimatedCostMicros: 60, CostEstimateAvailable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	scope := lease.Scopes[0]
	dayCostKey := atomicDayCostReservationKey("tenant-a", scope, scope.DayBucket)
	// Simulate the reservation having been subtracted already (e.g. an expiry
	// reclaim racing this finalize): only 10 of the 60 reserved micros remain.
	if err := client.Set(ctx, dayCostKey, 10, 0).Err(); err != nil {
		t.Fatal(err)
	}
	if err := admission.Settle(ctx, lease, 4, 40, true); err != nil {
		t.Fatal(err)
	}
	if got := client.Get(ctx, dayCostKey).Val(); got != "0" {
		t.Fatalf("day cost reservation=%q, want clamped 0", got)
	}
	if got := admission.ReservationUnderflows(); got != 1 {
		t.Fatalf("underflow metric=%d, want 1", got)
	}
	line := logs.String()
	if !strings.Contains(line, "underflow") || !strings.Contains(line, "deficit=50") || !strings.Contains(line, "request=underflow-dup") {
		t.Fatalf("underflow alert missing or incomplete: %q", line)
	}

	released, err := admission.Admit(ctx, governor.AdmissionRequest{
		Ref: ref, RequestID: "underflow-release", EstimatedTokens: 5,
		EstimatedCostMicros: 30, CostEstimateAvailable: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Set(ctx, dayCostKey, 0, 0).Err(); err != nil {
		t.Fatal(err)
	}
	if err := admission.Release(ctx, released, 0, 0); err != nil {
		t.Fatal(err)
	}
	if got := admission.ReservationUnderflows(); got != 2 {
		t.Fatalf("release underflow metric=%d, want 2", got)
	}
}
