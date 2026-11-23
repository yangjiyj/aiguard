package governor

import (
	"context"
	"testing"
)

type stubQuota struct {
	mode  string
	quota EffectiveQuotaInput
}

func (s *stubQuota) GetEnforcementMode(ctx context.Context, ref ScopeRef) string { return s.mode }
func (s *stubQuota) EffectiveQuota(ctx context.Context, ref ScopeRef) (EffectiveQuotaInput, error) {
	return s.quota, nil
}

type stubSnap struct {
	snap Snapshot
}

func (s *stubSnap) GetMulti(ctx context.Context, ref ScopeRef) (map[string]Snapshot, error) {
	return map[string]Snapshot{"project:x": s.snap}, nil
}

type scopedQuotaStub struct {
	stubQuota
	quotas []ScopedQuota
}

func (s *scopedQuotaStub) ScopedQuotas(context.Context, ScopeRef) ([]ScopedQuota, error) {
	return s.quotas, nil
}

type exactMultiSnap map[string]Snapshot

func (s exactMultiSnap) GetMulti(context.Context, ScopeRef) (map[string]Snapshot, error) {
	return s, nil
}

type ancestorScopedSnap struct{ exactMultiSnap }

func (s ancestorScopedSnap) GetScoped(context.Context, ScopeRef, []ScopedQuota) (map[string]Snapshot, error) {
	return s.exactMultiSnap, nil
}

type stubModelChecker struct{ allowed bool }

func (s *stubModelChecker) IsModelAllowedForTeam(context.Context, string, string) (bool, error) {
	return s.allowed, nil
}

func TestDecideComparesEachLimitWithTheSameScopeUsage(t *testing.T) {
	quota := &scopedQuotaStub{
		stubQuota: stubQuota{mode: "enforce"},
		quotas: []ScopedQuota{
			{Scope: "tenant", ID: "tenant-1", EnforcementMode: "enforce", Limits: EffectiveQuotaInput{MonthlyTokenLimit: 1_000_000, OverageAction: "rate_limit"}},
			{Scope: "user", ID: "user-1", EnforcementMode: "enforce", Limits: EffectiveQuotaInput{MonthlyTokenLimit: 10_000, OverageAction: "rate_limit"}},
		},
	}
	snapshots := exactMultiSnap{
		"tenant:tenant-1": {MonthTokens: 200_000},
		"user:user-1":     {MonthTokens: 100},
	}

	got := New(snapshots, quota).Decide(context.Background(), ScopeRef{TenantID: "tenant-1", UserID: "user-1"})

	if got.Action != ActionNone {
		t.Fatalf("tenant usage must not be compared with the user limit: %+v", got)
	}
}

func TestDecideReportsTheActuallyExhaustedScope(t *testing.T) {
	quota := &scopedQuotaStub{
		stubQuota: stubQuota{mode: "enforce"},
		quotas: []ScopedQuota{
			{Scope: "tenant", ID: "tenant-1", EnforcementMode: "enforce", Limits: EffectiveQuotaInput{MonthlyTokenLimit: 1_000_000, OverageAction: "rate_limit"}},
			{Scope: "user", ID: "user-1", EnforcementMode: "enforce", Limits: EffectiveQuotaInput{MonthlyTokenLimit: 10_000, OverageAction: "rate_limit"}},
		},
	}
	snapshots := exactMultiSnap{
		"tenant:tenant-1": {MonthTokens: 1_000_000},
		"user:user-1":     {MonthTokens: 100},
	}

	got := New(snapshots, quota).Decide(context.Background(), ScopeRef{TenantID: "tenant-1", UserID: "user-1"})

	if got.Action != ActionRateLimit || got.TriggeredScope != "tenant" || got.ScopeID != "tenant-1" {
		t.Fatalf("expected exhausted tenant scope, got %+v", got)
	}
}

func TestDecideDoesNotLetSoftPreAlertHideLaterHardOverage(t *testing.T) {
	quota := &scopedQuotaStub{
		stubQuota: stubQuota{mode: "enforce"},
		quotas: []ScopedQuota{
			{Scope: "tenant", ID: "tenant-1", EnforcementMode: "soft", Limits: EffectiveQuotaInput{MonthlyBudgetMicros: 100, OverageAction: "rate_limit"}},
			{Scope: "user", ID: "user-1", EnforcementMode: "enforce", Limits: EffectiveQuotaInput{MonthlyBudgetMicros: 10, OverageAction: "rate_limit"}},
		},
	}
	snapshots := exactMultiSnap{
		"tenant:tenant-1": {MonthCostMicros: 85},
		"user:user-1":     {MonthCostMicros: 11},
	}

	got := New(snapshots, quota).Decide(context.Background(), ScopeRef{TenantID: "tenant-1", UserID: "user-1"})

	if got.Action != ActionRateLimit || got.TriggeredScope != "user" {
		t.Fatalf("hard user overage must win over an earlier soft alert: %+v", got)
	}
}

func TestDecideScopedBypassSkipsQuotaAndModelPolicy(t *testing.T) {
	quota := &scopedQuotaStub{
		stubQuota: stubQuota{mode: "soft"},
		quotas: []ScopedQuota{{
			Scope: "team", ID: "team-1", EnforcementMode: "bypass",
			Limits: EffectiveQuotaInput{MonthlyBudgetMicros: 1, OverageAction: "rate_limit"},
		}},
	}
	checker := &stubModelChecker{allowed: false}
	decider := New(exactMultiSnap{"team:team-1": {MonthCostMicros: 999}}, quota).WithModelChecker(checker)

	got := decider.Decide(context.Background(), ScopeRef{TeamID: "team-1", ModelID: "model-1"})

	if got.Action != ActionNone {
		t.Fatalf("an explicit all-scope bypass must not enforce quota or model policy: %+v", got)
	}
}

func TestStableKeyQuotaIgnoresLegacyPrefixBucket(t *testing.T) {
	quota := &scopedQuotaStub{quotas: []ScopedQuota{{
		Scope: "key", ID: "key-id-1", EnforcementMode: "enforce",
		Limits: EffectiveQuotaInput{MonthlyTokenLimit: 100, OverageAction: "rate_limit"},
	}}}
	snapshots := exactMultiSnap{
		"key:key-id-1":      {MonthTokens: 60},
		"key_legacy:sk-abc": {MonthTokens: 110},
	}
	got := New(snapshots, quota).Decide(context.Background(), ScopeRef{KeyID: "key-id-1"})
	if got.Action != ActionNone {
		t.Fatalf("legacy prefix usage must not affect stable key quota: %+v", got)
	}
}

func TestDecideRespectsEnforcementMode(t *testing.T) {
	cases := []struct {
		name  string
		mode  string
		usage Snapshot
		quota EffectiveQuotaInput
		want  ActionType
	}{
		{"soft mode alerts but never blocks", "soft",
			Snapshot{MonthCostMicros: 999},
			EffectiveQuotaInput{MonthlyBudgetMicros: 100}, ActionAlert}, // soft: alert-only, never block
		{"enforce + over budget triggers downgrade", "enforce",
			Snapshot{MonthCostMicros: 200},
			EffectiveQuotaInput{MonthlyBudgetMicros: 100, OverageAction: "downgrade_model", DowngradeTo: "gpt-4o-mini"},
			ActionDowngradeMod},
		{"enforce + over RPM triggers rate_limit", "enforce",
			Snapshot{Rpm: 100},
			EffectiveQuotaInput{RPMLimit: 60}, ActionRateLimit},
		{"bypass passes through", "bypass",
			Snapshot{MonthCostMicros: 999},
			EffectiveQuotaInput{MonthlyBudgetMicros: 100}, ActionNone},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := New(&stubSnap{snap: c.usage}, &stubQuota{mode: c.mode, quota: c.quota})
			got := d.Decide(context.Background(), ScopeRef{ProjectID: "x"})
			if got.Action != c.want {
				t.Errorf("want %s got %s", c.want, got.Action)
			}
		})
	}
}

func TestSoftModeAlertOnly(t *testing.T) {
	d := New(
		&stubSnap{snap: Snapshot{MonthCostMicros: 200}},
		&stubQuota{mode: "soft", quota: EffectiveQuotaInput{MonthlyBudgetMicros: 100}},
	)
	got := d.Decide(context.Background(), ScopeRef{ProjectID: "x"})
	if got.Action != ActionAlert {
		t.Errorf("soft overage: want ActionAlert, got %s", got.Action)
	}
	if !got.AlertOnly {
		t.Error("soft overage: want AlertOnly=true")
	}
}

func TestDecidePreAlertAt80Percent(t *testing.T) {
	d := New(
		&stubSnap{snap: Snapshot{MonthCostMicros: 85}},
		&stubQuota{mode: "enforce", quota: EffectiveQuotaInput{MonthlyBudgetMicros: 100}},
	)
	got := d.Decide(context.Background(), ScopeRef{ProjectID: "x"})
	if got.Action != ActionAlert || !got.AlertOnly {
		t.Errorf("expect alert-only, got %+v", got)
	}
}

func TestDecideNonRealtimeDelegatesAllQuotaActionsToAtomicAdmission(t *testing.T) {
	quota := &scopedQuotaStub{quotas: []ScopedQuota{{
		Scope: "project", ID: "project-1", EnforcementMode: "enforce",
		Limits: EffectiveQuotaInput{
			RPMLimit: 1, ConcurrencyLimit: 1, DailyTokenLimit: 10,
			DailyBudgetMicros: 100, OverageAction: "rate_limit",
		},
	}}}
	snap := exactMultiSnap{"project:project-1": {Rpm: 2, Concurrency: 2, DayTokens: 11, DayCostMicros: 50}}
	decision := New(snap, quota).DecideNonRealtime(context.Background(), ScopeRef{ProjectID: "project-1"})
	if decision.Action != ActionNone {
		t.Fatalf("atomic realtime dimensions were evaluated twice: %+v", decision)
	}

	snap["project:project-1"] = Snapshot{DayCostMicros: 100}
	decision = New(snap, quota).DecideNonRealtime(context.Background(), ScopeRef{ProjectID: "project-1"})
	if decision.Action != ActionNone {
		t.Fatalf("cost policy was evaluated outside atomic admission: %+v", decision)
	}

	quota.quotas[0].Limits.DailyBudgetMicros = 0
	quota.quotas[0].Limits.OverageAction = "pause_key"
	snap["project:project-1"] = Snapshot{DayTokens: 10}
	decision = New(snap, quota).DecideNonRealtime(context.Background(), ScopeRef{ProjectID: "project-1"})
	if decision.Action != ActionNone {
		t.Fatalf("legacy token action was evaluated outside atomic admission: %+v", decision)
	}
}

func TestDecideNonRealtimePreservesModelPolicy(t *testing.T) {
	quota := &scopedQuotaStub{quotas: []ScopedQuota{{Scope: "team", ID: "team-1", EnforcementMode: "enforce"}}}
	decision := New(exactMultiSnap{}, quota).
		WithModelChecker(&stubModelChecker{allowed: false}).
		DecideNonRealtime(context.Background(), ScopeRef{TeamID: "team-1", ModelID: "model-1"})
	if decision.Action != ActionRateLimit || decision.Reason != "model not allowed for team" {
		t.Fatalf("model policy was skipped: %+v", decision)
	}
}

func TestDecideNonRealtimeDoesNotReadParentTeamCostSnapshot(t *testing.T) {
	quota := &scopedQuotaStub{quotas: []ScopedQuota{{
		Scope: "team", ID: "team-root", EnforcementMode: "enforce",
		Limits: EffectiveQuotaInput{DailyBudgetMicros: 10, OverageAction: "rate_limit"},
	}}}
	snapshot := ancestorScopedSnap{exactMultiSnap{"team:team-root": {DayCostMicros: 10}}}
	decision := New(snapshot, quota).DecideNonRealtime(context.Background(), ScopeRef{TeamID: "team-child"})
	if decision.Action != ActionNone {
		t.Fatalf("parent team cost was evaluated outside atomic admission: %+v", decision)
	}
}

func TestAccountingTeamScopeDoesNotHardenDefaultModelPolicyMode(t *testing.T) {
	quota := &scopedQuotaStub{quotas: []ScopedQuota{{Scope: "team", ID: "team-child", EnforcementMode: "accounting"}}}
	decision := New(exactMultiSnap{}, quota).
		WithModelChecker(&stubModelChecker{allowed: false}).
		DecideNonRealtime(context.Background(), ScopeRef{TeamID: "team-child", ModelID: "model-1"})
	if decision.Action != ActionAlert || !decision.AlertOnly {
		t.Fatalf("accounting scope hardened model policy: %+v", decision)
	}
}

// 7.4: budget checks compare int64 micros; the 80% pre-alert is exact at the
// boundary instead of depending on float rounding of limit*0.8.
func TestDecideBudgetUsesIntegerMicros(t *testing.T) {
	d := New(nil, nil)
	q := EffectiveQuotaInput{MonthlyBudgetMicros: 1_000_001, OverageAction: "rate_limit"}
	if got := d.decide("enforce", Snapshot{MonthCostMicros: 800_000}, q); got.Action != ActionNone {
		t.Fatalf("800000/1000001 is below 80%%, got %+v", got)
	}
	if got := d.decide("enforce", Snapshot{MonthCostMicros: 800_001}, q); got.Action != ActionAlert || !got.AlertOnly {
		t.Fatalf("800001/1000001 reaches 80%%, got %+v", got)
	}
	if got := d.decide("enforce", Snapshot{MonthCostMicros: 1_000_001}, q); got.Action != ActionRateLimit || got.TriggeredMetric != "mo_cost" {
		t.Fatalf("limit reached must rate limit, got %+v", got)
	}
	day := EffectiveQuotaInput{DailyBudgetMicros: 5, OverageAction: "rate_limit"}
	if got := d.decideNonRealtime("enforce", Snapshot{DayCostMicros: 4}, day); got.Action != ActionNone {
		t.Fatalf("below daily limit, got %+v", got)
	}
	if got := d.decideNonRealtime("enforce", Snapshot{DayCostMicros: 5}, day); got.Action != ActionRateLimit || got.TriggeredMetric != "day_cost" {
		t.Fatalf("daily limit reached, got %+v", got)
	}
}

func TestOwnedKeySkipsOnlyDepartmentModelAdmission(t *testing.T) {
	for _, user := range []string{"user-a", ""} {
		d := New(&stubSnap{}, &stubQuota{mode: "enforce"}).WithModelChecker(&stubModelChecker{allowed: false})
		got := d.Decide(context.Background(), ScopeRef{UserModelAccessEnforced: user != "", TeamID: "dept", ModelID: "extra", UserID: user})
		want := ActionRateLimit
		if user != "" {
			want = ActionNone
		}
		if got.Action != want {
			t.Fatalf("owner=%s action=%s want=%s", user, got.Action, want)
		}
		got = d.DecideNonRealtime(context.Background(), ScopeRef{UserModelAccessEnforced: user != "", TeamID: "dept", ModelID: "extra", UserID: user})
		if got.Action != want {
			t.Fatalf("non-realtime owner=%s action=%s want=%s", user, got.Action, want)
		}
	}
	d := New(&stubSnap{snap: Snapshot{Rpm: 10}}, &stubQuota{mode: "enforce", quota: EffectiveQuotaInput{RPMLimit: 1}}).WithModelChecker(&stubModelChecker{allowed: false})
	if d.Decide(context.Background(), ScopeRef{UserModelAccessEnforced: true, TeamID: "dept", ModelID: "extra", UserID: "user-a"}).Action != ActionRateLimit {
		t.Fatal("owned key skipped quota")
	}
}

func TestAuthenticatedActorDoesNotBypassUnownedKeyDepartmentPolicy(t *testing.T) {
	d := New(&stubSnap{}, &stubQuota{mode: "enforce"}).WithModelChecker(&stubModelChecker{allowed: false})
	ref := ScopeRef{UserID: "authenticated-actor", TeamID: "department", ModelID: "forbidden"}
	if d.Decide(context.Background(), ref).Action != ActionRateLimit || d.DecideNonRealtime(context.Background(), ref).Action != ActionRateLimit {
		t.Fatal("actor identity bypassed the unowned key model policy")
	}
}
