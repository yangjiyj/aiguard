package modelrouter

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelrouting"
	"github.com/jackc/pgx/v5/pgxpool"
)

type fakeModelRouteSource struct {
	routes []ModelRecord
	err    error
}

type fakeSharedHealthSource struct {
	fakeModelRouteSource
	snapshots []SharedRouteHealthSnapshot
	writes    chan SharedRouteHealthSnapshot
	ledger    chan attemptLedgerOperation
}

func (f *fakeSharedHealthSource) WriteSharedRouteHealth(_ context.Context, snapshot SharedRouteHealthSnapshot) error {
	f.writes <- snapshot
	return nil
}

func (f *fakeSharedHealthSource) ListSharedRouteHealth(context.Context) ([]SharedRouteHealthSnapshot, error) {
	return append([]SharedRouteHealthSnapshot(nil), f.snapshots...), nil
}

func (f *fakeSharedHealthSource) StartRouteAttempt(_ context.Context, entry RouteAttemptLedgerEntry) error {
	f.ledger <- attemptLedgerOperation{entry: entry}
	return nil
}

func (f *fakeSharedHealthSource) FinishRouteAttempt(_ context.Context, entry RouteAttemptLedgerEntry) error {
	f.ledger <- attemptLedgerOperation{finish: true, entry: entry}
	return nil
}

func (f fakeModelRouteSource) ResolveLogicalModelName(_ context.Context, _ string, modelRef string) (string, bool, error) {
	if f.err != nil {
		return "", false, f.err
	}
	if len(f.routes) > 0 {
		return f.routes[0].ModelName, true, nil
	}
	return modelRef, true, nil
}

func (f fakeModelRouteSource) listModelRoutesByName(context.Context, string, string) ([]ModelRecord, error) {
	return f.routes, f.err
}

type fakeV2PolicySource struct {
	policy *V2RoutingPolicy
	err    error
}

func (f fakeV2PolicySource) GetV2Policy(context.Context, string, string) (*V2RoutingPolicy, error) {
	return f.policy, f.err
}

func validPriorityPolicy(providerIDs ...string) *V2RoutingPolicy {
	rules := make([]modelrouting.ProviderRule, 0, len(providerIDs))
	for i, id := range providerIDs {
		rules = append(rules, modelrouting.ProviderRule{ProviderID: id, Enabled: true, Priority: i + 1})
	}
	return &V2RoutingPolicy{
		Scope: modelrouting.ScopeDefault,
		Config: modelrouting.Config{
			Strategy:  modelrouting.StrategyPriority,
			CostBasis: modelrouting.CostNone,
			Providers: rules,
		},
	}
}

func validSmartLatencyPolicy(providerIDs ...string) *V2RoutingPolicy {
	policy := validPriorityPolicy(providerIDs...)
	policy.Config.Strategy = modelrouting.StrategySmart
	policy.Config.Objective = modelrouting.ObjectiveLatency
	return policy
}

func TestSharedHealthIsAsyncAndExcludesFreshUnhealthyRoute(t *testing.T) {
	now := time.Now()
	routes := []ModelRecord{{ID: "m1", ModelName: "logical/model", ProviderID: "p1"}, {ID: "m2", ModelName: "logical/model", ProviderID: "p2"}}
	source := &fakeSharedHealthSource{
		fakeModelRouteSource: fakeModelRouteSource{routes: routes},
		snapshots:            []SharedRouteHealthSnapshot{{RouteKey: RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "p1"}, State: "unhealthy", Version: 1, ObservedAt: now, ExpiresAt: now.Add(time.Minute)}},
		writes:               make(chan SharedRouteHealthSnapshot, 1),
		ledger:               make(chan attemptLedgerOperation, 2),
	}
	engine := newModelRouteEngine(source, fakeV2PolicySource{policy: validPriorityPolicy("p1", "p2")})
	deadline := time.Now().Add(time.Second)
	for {
		if _, ok := engine.sharedHealth(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "p1"}); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shared health cache did not refresh")
		}
		time.Sleep(time.Millisecond)
	}
	plan, applied, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model", RequestID: "req"})
	if err != nil || !applied || plan.Primary.ProviderID != "p2" {
		t.Fatalf("plan=%+v applied=%v err=%v", plan, applied, err)
	}
	engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "p2"}, AttemptResult{Success: true})
	select {
	case snapshot := <-source.writes:
		if snapshot.State != "healthy" || snapshot.ProviderID != "p2" {
			t.Fatalf("snapshot=%+v", snapshot)
		}
	case <-time.After(time.Second):
		t.Fatal("shared health write blocked the request path or was lost")
	}
}

func TestAttemptLedgerUsesBoundedAsyncQueue(t *testing.T) {
	source := &fakeSharedHealthSource{
		writes: make(chan SharedRouteHealthSnapshot, 1),
		ledger: make(chan attemptLedgerOperation, 2),
	}
	engine := newModelRouteEngine(source, fakeV2PolicySource{})
	entry := RouteAttemptLedgerEntry{AttemptID: "attempt-1"}
	_ = engine.StartRouteAttempt(context.Background(), entry)
	_ = engine.FinishRouteAttempt(context.Background(), entry)
	for index, wantFinish := range []bool{false, true} {
		select {
		case operation := <-source.ledger:
			if operation.finish != wantFinish || operation.entry.AttemptID != entry.AttemptID {
				t.Fatalf("operation %d=%+v", index, operation)
			}
		case <-time.After(time.Second):
			t.Fatalf("operation %d was not persisted", index)
		}
	}
}

func TestEngineDirectsOnlyHealthyRouteEvenWhenPolicyOmitsIt(t *testing.T) {
	routes := []ModelRecord{{ID: "m1", ModelName: "logical/model", ProviderID: "p1", ProviderName: "故障线"}, {ID: "m2", ModelName: "logical/model", ProviderID: "p2", ProviderName: "健康线"}}
	engine := newModelRouteEngine(fakeModelRouteSource{routes: routes}, fakeV2PolicySource{policy: validPriorityPolicy("p1")})
	for i := 0; i < 3; i++ {
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "p1"}, AttemptResult{Retryable: true, StatusCode: 503})
	}
	plan, applied, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model", RequestID: "req"})
	if err != nil || !applied || plan.Primary.ProviderID != "p2" || len(plan.Fallbacks) != 0 {
		t.Fatalf("direct plan=%+v applied=%v err=%v", plan, applied, err)
	}
	if plan.Decision.ModelRouteV2.FallbackReason != "" {
		t.Fatalf("unexpected unavailable decision: %+v", plan.Decision.ModelRouteV2)
	}
	if len(plan.Decision.ModelRouteV2.Candidates) != 2 || plan.Decision.ModelRouteV2.Candidates[0].ExclusionReason != "circuit_open" || plan.Decision.ModelRouteV2.Candidates[1].ExclusionReason != "selected_primary" {
		t.Fatalf("incomplete explanations: %+v", plan.Decision.ModelRouteV2.Candidates)
	}
}

func TestEnginePolicyWithNoHealthyIntersectionEmitsStableUnavailable(t *testing.T) {
	routes := []ModelRecord{{ID: "m1", ModelName: "logical/model", ProviderID: "p1", ProviderName: "线路甲"}, {ID: "m2", ModelName: "logical/model", ProviderID: "p2", ProviderName: "线路乙"}}
	writer := &recordingAlertWriter{}
	sink := NewAlertSink(writer, time.Minute)
	defer sink.Close(context.Background())
	engine := newModelRouteEngineWithAlertSink(fakeModelRouteSource{routes: routes}, fakeV2PolicySource{policy: validPriorityPolicy("p3")}, sink, time.Now)
	plan, applied, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model", RequestID: "req"})
	if err == nil || !applied || plan.Decision == nil || plan.Decision.ModelRouteV2.FallbackReason != "policy_has_no_eligible_route" {
		t.Fatalf("plan=%+v applied=%v err=%v", plan, applied, err)
	}
	if len(plan.Decision.ModelRouteV2.Candidates) != 2 || plan.Decision.ModelRouteV2.Candidates[0].ExclusionReason != "not_in_policy" || plan.Decision.ModelRouteV2.Candidates[1].ExclusionReason != "not_in_policy" {
		t.Fatalf("explanations=%+v", plan.Decision.ModelRouteV2.Candidates)
	}
	if flushErr := sink.flush(context.Background()); flushErr != nil {
		t.Fatal(flushErr)
	}
	if len(writer.alerts) != 1 || writer.alerts[0].Type != AlertRouteUnavailable {
		t.Fatalf("alerts=%+v", writer.alerts)
	}
}

// 请求的模型名根本不在目录里（客户端写错了名字）不是线路故障：不能产生
// 「模型无可用线路」高危告警，否则每个写错名字的客户端都会刷一条误报。
type unknownModelRouteSource struct{ fakeModelRouteSource }

func (unknownModelRouteSource) ResolveLogicalModelName(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}

func TestEngineUnknownModelNameDoesNotRaiseRouteUnavailableAlert(t *testing.T) {
	writer := &recordingAlertWriter{}
	sink := NewAlertSink(writer, time.Minute)
	defer sink.Close(context.Background())
	engine := newModelRouteEngineWithAlertSink(unknownModelRouteSource{}, fakeV2PolicySource{policy: validPriorityPolicy("p1")}, sink, time.Now)
	plan, applied, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "claude-x", RequestID: "req"})
	if err == nil || !applied || plan.Decision == nil || plan.Decision.ModelRouteV2.FallbackReason != "no_enabled_route" {
		t.Fatalf("plan=%+v applied=%v err=%v", plan, applied, err)
	}
	if flushErr := sink.flush(context.Background()); flushErr != nil {
		t.Fatal(flushErr)
	}
	if len(writer.alerts) != 0 {
		t.Fatalf("unknown model name must not alert: %+v", writer.alerts)
	}
}

func TestEngineAuditRouteRefsRemainStableAfterWeightedAndSmartReorder(t *testing.T) {
	for _, strategy := range []modelrouting.Strategy{modelrouting.StrategyWeighted, modelrouting.StrategySmart} {
		t.Run(string(strategy), func(t *testing.T) {
			routes := []ModelRecord{{ID: "m1", ModelName: "logical/model", ProviderID: "p1", ProviderName: "同名供应商"}, {ID: "m2", ModelName: "logical/model", ProviderID: "p2", ProviderName: "同名供应商"}}
			policy := validPriorityPolicy("p1", "p2")
			policy.Config.Strategy = strategy
			if strategy == modelrouting.StrategyWeighted {
				policy.Config.Providers[0].Weight = 1
				policy.Config.Providers[1].Weight = 100
			}
			if strategy == modelrouting.StrategySmart {
				policy.Config.Objective = modelrouting.ObjectiveLatency
			}
			engine := newModelRouteEngine(fakeModelRouteSource{routes: routes}, fakeV2PolicySource{policy: policy})
			if strategy == modelrouting.StrategySmart {
				for i := 0; i < 20; i++ {
					engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "p1"}, AttemptResult{Success: true, Latency: time.Second})
					engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "p2"}, AttemptResult{Success: true, Latency: time.Millisecond})
				}
			}
			var plan RoutePlan
			for i := 0; i < 200; i++ {
				candidate, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model", RequestID: fmt.Sprintf("req-%d", i)})
				if err != nil {
					t.Fatal(err)
				}
				if candidate.Primary.ProviderID == "p2" {
					plan = candidate
					break
				}
			}
			if plan.Primary.ProviderID != "p2" {
				t.Fatal("test did not produce reordered p2 primary")
			}
			if plan.RouteIdentities["p1"].RouteRef != "线路 1" || plan.RouteIdentities["p2"].RouteRef != "线路 2" || plan.Decision.ModelRouteV2.PlannedRoute.RouteRef != "线路 2" {
				t.Fatalf("unstable identity map: plan=%#v decision=%#v", plan.RouteIdentities, plan.Decision.ModelRouteV2)
			}
			refs := map[string]bool{}
			for _, c := range plan.Decision.ModelRouteV2.Candidates {
				refs[c.RouteRef] = true
			}
			if !refs["线路 1"] || !refs["线路 2"] {
				t.Fatalf("candidate refs changed after reorder: %#v", plan.Decision.ModelRouteV2.Candidates)
			}
		})
	}
}

func TestEngineUsesRealLogicalModelMetricsAndPreferenceDamping(t *testing.T) {
	now := time.Now()
	routes := []ModelRecord{{ID: "upstream-row-a", ModelName: "logical/model", ProviderID: "p1"}, {ID: "upstream-row-b", ModelName: "logical/model", ProviderID: "p2"}}
	engine := newModelRouteEngineWithClock(fakeModelRouteSource{routes: routes}, fakeV2PolicySource{policy: validSmartLatencyPolicy("p1", "p2")}, func() time.Time { return now })
	initial, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	if err != nil || initial.Primary.ProviderID != "p1" {
		t.Fatalf("cold-start plan = %+v err=%v", initial, err)
	}
	for i := 0; i < 20; i++ {
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "p1"}, AttemptResult{Success: true, Latency: time.Second})
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "p2"}, AttemptResult{Success: true, Latency: 100 * time.Millisecond})
	}
	for cycle := 1; cycle <= 3; cycle++ {
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "p2"}, AttemptResult{Success: true, Latency: 100 * time.Millisecond})
		plan, _, planErr := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
		if planErr != nil {
			t.Fatal(planErr)
		}
		want := "p1"
		if cycle == 3 {
			want = "p2"
		}
		if plan.Primary.ProviderID != want {
			t.Fatalf("cycle %d primary=%s want %s", cycle, plan.Primary.ProviderID, want)
		}
	}
}

func TestEnginePrunesAndBoundsFlappingSwitchState(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	engine := newModelRouteEngineWithClock(fakeModelRouteSource{}, fakeV2PolicySource{}, func() time.Time { return now })
	oldKey := RoutePreferenceKey{TenantID: "old-tenant", ModelName: "logical/model"}
	engine.recordPreferenceSwitch(oldKey, "provider-a")
	now = now.Add(healthStateTTL + time.Second)
	engine.recordPreferenceSwitch(RoutePreferenceKey{TenantID: "new-tenant", ModelName: "logical/model"}, "provider-b")
	engine.switchMu.Lock()
	_, oldStillPresent := engine.switches[oldKey]
	engine.switchMu.Unlock()
	if oldStillPresent {
		t.Fatal("expired flapping key was not pruned")
	}
	for i := 0; i < maxHealthStateKeys+2; i++ {
		engine.recordPreferenceSwitch(RoutePreferenceKey{TenantID: fmt.Sprintf("tenant-%d", i), ModelName: "logical/model"}, "provider")
	}
	engine.switchMu.Lock()
	count := len(engine.switches)
	engine.switchMu.Unlock()
	if count > maxHealthStateKeys {
		t.Fatalf("flapping state keys=%d limit=%d", count, maxHealthStateKeys)
	}
}

func TestEngineCircuitImmediatelyExcludesFailedPreferredRoute(t *testing.T) {
	routes := []ModelRecord{{ID: "a", ModelName: "logical/model", ProviderID: "p1"}, {ID: "b", ModelName: "logical/model", ProviderID: "p2"}}
	engine := newModelRouteEngine(fakeModelRouteSource{routes: routes}, fakeV2PolicySource{policy: validSmartLatencyPolicy("p1", "p2")})
	_, _, _ = engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	key := RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "p1"}
	for i := 0; i < 3; i++ {
		engine.RecordAttempt(key, AttemptResult{Retryable: true, StatusCode: 503})
	}
	plan, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	if err != nil || plan.Primary.ProviderID != "p2" {
		t.Fatalf("circuit failover plan=%+v err=%v", plan, err)
	}
}

func TestEnginePreferenceKeepsHealthyFourthRankedPrimaryUntilThirdLead(t *testing.T) {
	routes := []ModelRecord{
		{ID: "old", ModelName: "logical/model", ProviderID: "old"},
		{ID: "a", ModelName: "logical/model", ProviderID: "a"},
		{ID: "b", ModelName: "logical/model", ProviderID: "b"},
		{ID: "c", ModelName: "logical/model", ProviderID: "c"},
	}
	engine := newModelRouteEngine(fakeModelRouteSource{routes: routes}, fakeV2PolicySource{policy: validSmartLatencyPolicy("old", "a", "b", "c")})
	initial, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	if err != nil || initial.Primary.ProviderID != "old" {
		t.Fatalf("initial=%+v err=%v", initial, err)
	}
	latencies := map[string]time.Duration{"a": 100 * time.Millisecond, "b": 200 * time.Millisecond, "c": 300 * time.Millisecond, "old": time.Second}
	for providerID, latency := range latencies {
		for i := 0; i < 20; i++ {
			engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: providerID}, AttemptResult{Success: true, Latency: latency})
		}
	}
	for cycle := 1; cycle <= 3; cycle++ {
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "a"}, AttemptResult{Success: true, Latency: 100 * time.Millisecond})
		plan, _, planErr := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
		if planErr != nil {
			t.Fatal(planErr)
		}
		want := "old"
		if cycle == 3 {
			want = "a"
		}
		if plan.Primary.ProviderID != want {
			t.Fatalf("cycle %d primary=%s want=%s fallbacks=%v", cycle, plan.Primary.ProviderID, want, providerIDs(plan.Fallbacks))
		}
		if len(plan.Fallbacks) > 2 {
			t.Fatalf("attempt limit exceeded: %+v", plan)
		}
	}
}

func TestEngineCustomPreferenceUsesLatencyFirstInsteadOfStability(t *testing.T) {
	routes := []ModelRecord{{ID: "stable", ModelName: "logical/model", ProviderID: "stable"}, {ID: "fast", ModelName: "logical/model", ProviderID: "fast"}}
	policy := validPriorityPolicy("stable", "fast")
	policy.Config.Strategy = modelrouting.StrategySmart
	policy.Config.Objective = modelrouting.ObjectiveCustom
	policy.Config.CustomOrder = []modelrouting.Objective{modelrouting.ObjectiveLatency, modelrouting.ObjectiveStability, modelrouting.ObjectiveCost}
	engine := newModelRouteEngine(fakeModelRouteSource{routes: routes}, fakeV2PolicySource{policy: policy})
	_, _, _ = engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	for i := 0; i < 20; i++ {
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "stable"}, AttemptResult{Success: true, Latency: time.Second})
		fast := AttemptResult{Success: true, Latency: 100 * time.Millisecond}
		if i%5 == 0 {
			fast = AttemptResult{Retryable: true, StatusCode: 503, Latency: 100 * time.Millisecond}
		}
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "fast"}, fast)
	}
	for cycle := 1; cycle <= 3; cycle++ {
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "fast"}, AttemptResult{Success: true, Latency: 100 * time.Millisecond})
		plan, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
		if err != nil {
			t.Fatal(err)
		}
		want := "stable"
		if cycle == 3 {
			want = "fast"
		}
		if plan.Primary.ProviderID != want {
			t.Fatalf("cycle %d primary=%s want=%s", cycle, plan.Primary.ProviderID, want)
		}
	}
}

func TestEngineCustomPreferenceSkipsUnavailableFirstDimension(t *testing.T) {
	routes := []ModelRecord{{ID: "old", ModelName: "logical/model", ProviderID: "old"}, {ID: "better", ModelName: "logical/model", ProviderID: "better"}}
	policy := validPriorityPolicy("old", "better")
	policy.Config.Strategy = modelrouting.StrategySmart
	policy.Config.Objective = modelrouting.ObjectiveCustom
	policy.Config.CustomOrder = []modelrouting.Objective{modelrouting.ObjectiveCost, modelrouting.ObjectiveLatency, modelrouting.ObjectiveStability}
	policy.Config.CostBasis = modelrouting.CostRelative
	policy.Config.Providers[1].RelativeCost = modelrouting.CostLow // partial cost: whole cost dimension unavailable
	engine := newModelRouteEngine(fakeModelRouteSource{routes: routes}, fakeV2PolicySource{policy: policy})
	_, _, _ = engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	for i := 0; i < 20; i++ {
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "old"}, AttemptResult{Success: true, Latency: time.Second})
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "better"}, AttemptResult{Success: true, Latency: 100 * time.Millisecond})
	}
	for cycle := 1; cycle <= 3; cycle++ {
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "better"}, AttemptResult{Success: true, Latency: 100 * time.Millisecond})
		plan, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
		if err != nil {
			t.Fatal(err)
		}
		if cycle == 3 && plan.Primary.ProviderID != "better" {
			t.Fatalf("unavailable cost dimension was not skipped: %+v", plan)
		}
	}
}

func TestEngineColdFallbackImmediatelyUsesCurrentAdministratorPriority(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	routes := []ModelRecord{{ID: "priority", ModelName: "logical/model", ProviderID: "priority"}, {ID: "dynamic", ModelName: "logical/model", ProviderID: "dynamic"}}
	engine := newModelRouteEngineWithClock(fakeModelRouteSource{routes: routes}, fakeV2PolicySource{policy: validSmartLatencyPolicy("priority", "dynamic")}, func() time.Time { return now })
	_, _, _ = engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	recordLatencySamples(engine, "t", "logical/model", "priority", time.Second, 20)
	recordLatencySamples(engine, "t", "logical/model", "dynamic", 100*time.Millisecond, 20)
	for i := 0; i < 3; i++ {
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "dynamic"}, AttemptResult{Success: true, Latency: 100 * time.Millisecond})
		_, _, _ = engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	}
	if engine.preferences.Current(RoutePreferenceKey{TenantID: "t", ModelName: "logical/model"}) != "dynamic" {
		t.Fatal("test setup did not establish dynamic preference")
	}

	now = now.Add(16 * time.Minute)
	plan, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Primary.ProviderID != "priority" {
		t.Fatalf("cold fallback retained stale dynamic preference: %+v", plan)
	}
}

func TestEngineColdFallbackClearsPendingDynamicSwitchCycles(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	routes := []ModelRecord{{ID: "priority", ModelName: "logical/model", ProviderID: "priority"}, {ID: "dynamic", ModelName: "logical/model", ProviderID: "dynamic"}}
	engine := newModelRouteEngineWithClock(fakeModelRouteSource{routes: routes}, fakeV2PolicySource{policy: validSmartLatencyPolicy("priority", "dynamic")}, func() time.Time { return now })
	_, _, _ = engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	recordLatencySamples(engine, "t", "logical/model", "priority", time.Second, 20)
	recordLatencySamples(engine, "t", "logical/model", "dynamic", 100*time.Millisecond, 20)
	for i := 0; i < 2; i++ {
		engine.RecordAttempt(RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "dynamic"}, AttemptResult{Success: true, Latency: 100 * time.Millisecond})
		plan, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
		if err != nil || plan.Primary.ProviderID != "priority" {
			t.Fatalf("pending cycle %d plan=%+v err=%v", i+1, plan, err)
		}
	}

	now = now.Add(16 * time.Minute)
	cold, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	if err != nil || cold.Primary.ProviderID != "priority" {
		t.Fatalf("cold plan=%+v err=%v", cold, err)
	}
	recordLatencySamples(engine, "t", "logical/model", "priority", time.Second, 20)
	recordLatencySamples(engine, "t", "logical/model", "dynamic", 100*time.Millisecond, 20)
	recovered, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
	if err != nil {
		t.Fatal(err)
	}
	if recovered.Primary.ProviderID != "priority" {
		t.Fatalf("warm recovery inherited pre-cold pending cycles: %+v", recovered)
	}
}

func recordLatencySamples(engine *modelRouteEngine, tenantID, modelName, providerID string, latency time.Duration, count int) {
	for i := 0; i < count; i++ {
		engine.RecordAttempt(RouteKey{TenantID: tenantID, ModelName: modelName, ProviderID: providerID}, AttemptResult{Success: true, Latency: latency})
	}
}

func TestEngineRepeatedPlansDoNotClaimHalfOpenProbe(t *testing.T) {
	now := time.Now()
	route := ModelRecord{ID: "m", ModelName: "logical/model", ProviderID: "p"}
	engine := newModelRouteEngineWithClock(fakeModelRouteSource{routes: []ModelRecord{route}}, fakeV2PolicySource{policy: validPriorityPolicy("p")}, func() time.Time { return now })
	key := RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: "p"}
	for i := 0; i < 3; i++ {
		engine.RecordAttempt(key, AttemptResult{Retryable: true})
	}
	now = now.Add(30 * time.Second)
	for i := 0; i < 5; i++ {
		plan, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model"})
		if err != nil || plan.Primary.ProviderID != "p" {
			t.Fatalf("plan %d=%+v err=%v", i, plan, err)
		}
	}
	if !engine.health.Allow(key) {
		t.Fatal("Plan consumed the half-open probe lease")
	}
	if engine.health.Allow(key) {
		t.Fatal("probe claim itself was not exclusive")
	}
}

func TestCustomPreferenceSkipsEqualFirstDimensionForNextDifference(t *testing.T) {
	config := modelrouting.Config{Objective: modelrouting.ObjectiveCustom, CustomOrder: []modelrouting.Objective{modelrouting.ObjectiveStability, modelrouting.ObjectiveLatency, modelrouting.ObjectiveCost}}
	selection := routeSelection{Explanations: []routeExplanation{
		{ProviderID: "a", Scores: map[string]float64{"stability": 1, "latency": .2}, DimensionState: map[string]string{"stability": "used", "latency": "used"}},
		{ProviderID: "b", Scores: map[string]float64{"stability": 1, "latency": .9}, DimensionState: map[string]string{"stability": "used", "latency": "used"}},
	}}
	current, candidate, ok := preferenceScores(config, selection, "a", "b")
	if !ok || current != .2 || candidate != .9 {
		t.Fatalf("equal first dimension blocked next custom dimension: current=%v candidate=%v ok=%v", current, candidate, ok)
	}
}

func TestEngineSingleCandidateBypassesScoring(t *testing.T) {
	route := ModelRecord{ID: "m1", ModelName: "gpt-4o", ProviderID: "p1", UpstreamModelID: "vendor-gpt-4o"}
	engine := newModelRouteEngine(fakeModelRouteSource{routes: []ModelRecord{route}}, fakeV2PolicySource{policy: validPriorityPolicy("p1")})

	plan, applied, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t1", Model: "gpt-4o"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !applied {
		t.Fatal("expected v2 policy to be applied")
	}
	if plan.Primary.ProviderID != "p1" || len(plan.Fallbacks) != 0 {
		t.Fatalf("unexpected single-route plan: %+v", plan)
	}
	if plan.Decision == nil || plan.Decision.ProviderLayer == nil || plan.Decision.ProviderLayer.Reason["selection"] != "single_candidate" {
		t.Fatalf("expected explicit single-candidate decision, got %+v", plan.Decision)
	}
}

func TestEngineNoCandidateNeverChangesToAnotherModel(t *testing.T) {
	engine := newModelRouteEngine(fakeModelRouteSource{}, fakeV2PolicySource{policy: validPriorityPolicy("p1")})

	plan, applied, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t1", Model: "requested/model"})
	if err == nil || !strings.Contains(err.Error(), "no valid route") {
		t.Fatalf("expected unavailable-route error, got %v", err)
	}
	if !applied {
		t.Fatal("expected matching v2 policy to own the unavailable result")
	}
	if plan.Primary.ModelName != "" || plan.Primary.UpstreamModelID != "" {
		t.Fatalf("engine substituted a model: %+v", plan.Primary)
	}
}

func TestEngineWithoutV2PolicyReturnsAppliedFalse(t *testing.T) {
	route := ModelRecord{ID: "m1", ModelName: "gpt-4o", ProviderID: "p1"}
	engine := newModelRouteEngine(fakeModelRouteSource{routes: []ModelRecord{route}}, fakeV2PolicySource{})

	plan, applied, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t1", Model: "gpt-4o"})
	if err != nil || applied {
		t.Fatalf("expected clean legacy fallthrough, plan=%+v applied=%v err=%v", plan, applied, err)
	}
}

func TestListModelRoutesReturnsOnlySameLogicalModelAndValidCredentials(t *testing.T) {
	pool, tenantID, otherTenantID := setupModelRouteDB(t)
	ctx := context.Background()
	insertRouteFixture(t, pool, tenantID, otherTenantID)

	router := NewModelRouter(pool)
	routes, err := router.ListModelRoutes(ctx, tenantID, "model-ref-a")
	if err != nil {
		t.Fatalf("ListModelRoutes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected two valid same-model routes, got %d: %+v", len(routes), routes)
	}
	byProvider := map[string]ModelRecord{}
	for _, route := range routes {
		if route.ModelName != "acme/chat/v1" {
			t.Fatalf("different logical model leaked into candidates: %+v", route)
		}
		byProvider[route.ProviderID] = route
	}
	if byProvider["provider-a"].UpstreamModelID != "upstream-a" || byProvider["provider-b"].UpstreamModelID != "upstream-b" {
		t.Fatalf("provider-specific upstream mapping lost: %+v", byProvider)
	}
	if byProvider["provider-a"].ProviderName != "供应商 A" || byProvider["provider-a"].ProviderBaseURL != "https://provider-a.example/v1" || byProvider["provider-a"].ProviderAuthMode != "bearer" {
		t.Fatalf("complete provider route not preserved: %+v", byProvider["provider-a"])
	}

	byName, err := router.ListModelRoutes(ctx, tenantID, "acme/chat/v1")
	if err != nil || len(byName) != 2 {
		t.Fatalf("slash model-name resolution failed: routes=%+v err=%v", byName, err)
	}
	foreign, err := router.ListModelRoutes(ctx, otherTenantID, "model-ref-a")
	if err != nil || len(foreign) != 0 {
		t.Fatalf("cross-tenant model reference leaked candidates: routes=%+v err=%v", foreign, err)
	}
}

func TestListModelRoutesPrefersExactLogicalNameWhenRefAlsoMatchesAnotherModelID(t *testing.T) {
	pool, tenantID, otherTenantID := setupModelRouteDB(t)
	ctx := context.Background()
	insertRouteFixture(t, pool, tenantID, otherTenantID)
	if _, err := pool.Exec(ctx, `INSERT INTO models (id, provider_id, model_name, upstream_model_id, status) VALUES ('acme/chat/v1','provider-a','different-model','must-not-be-selected','active')`); err != nil {
		t.Fatalf("insert ambiguous model reference: %v", err)
	}

	routes, err := NewModelRouter(pool).ListModelRoutes(ctx, tenantID, "acme/chat/v1")
	if err != nil {
		t.Fatalf("ListModelRoutes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected exact logical-name candidates, got %+v", routes)
	}
	for _, route := range routes {
		if route.ModelName != "acme/chat/v1" || route.UpstreamModelID == "must-not-be-selected" {
			t.Fatalf("model ID collision silently changed logical model: %+v", route)
		}
	}
}

func TestEngineModelIDWithNoCredentialStillAppliesModelOverride(t *testing.T) {
	pool, tenantID, _ := setupModelRouteDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO providers (id, tenant_id, name, provider_type, status) VALUES ('credentialless-provider',$1,'无凭证供应商','openai','active')`, tenantID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO models (id, provider_id, model_name, upstream_model_id, status) VALUES ('credentialless-id','credentialless-provider','protected/model','upstream-protected','active')`); err != nil {
		t.Fatalf("insert model: %v", err)
	}
	config := `{"strategy":"priority","cost_basis":"none","providers":[{"provider_id":"credentialless-provider","enabled":true,"priority":1,"weight":0}]}`
	if _, err := pool.Exec(ctx, `INSERT INTO routing_policies (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, schema_version, config_version) VALUES ('credentialless-override',$1,'model','protected/model','provider','priority',$2::jsonb,true,2,1)`, tenantID, config); err != nil {
		t.Fatalf("insert override: %v", err)
	}

	engine := NewModelRouteEngine(NewModelRouter(pool), NewPolicyCache(pool, time.Minute))
	plan, applied, err := engine.Plan(ctx, RequestEnvelope{TenantID: tenantID, Model: "credentialless-id"})
	if err == nil || !strings.Contains(err.Error(), "no valid route") {
		t.Fatalf("expected explicit unavailable error, got plan=%+v applied=%v err=%v", plan, applied, err)
	}
	if !applied {
		t.Fatal("model override was lost when the resolved model had zero credentialed candidates")
	}
	if plan.Primary.ModelName != "" {
		t.Fatalf("engine substituted a model: %+v", plan.Primary)
	}
}

func TestEngineUsesOverrideBeforeDefault(t *testing.T) {
	pool, tenantID, _ := setupModelRouteDB(t)
	ctx := context.Background()
	for _, row := range []struct {
		id, scopeType, scopeRef, providerID string
	}{
		{"default-policy", "tenant", tenantID, "provider-a"},
		{"override-policy", "model", "acme/chat/v1", "provider-b"},
	} {
		config := fmt.Sprintf(`{"strategy":"priority","cost_basis":"none","providers":[{"provider_id":%q,"enabled":true,"priority":1,"weight":0}]}`, row.providerID)
		if _, err := pool.Exec(ctx, `INSERT INTO routing_policies (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, schema_version, config_version) VALUES ($1,$2,$3,$4,'provider','priority',$5::jsonb,true,2,1)`, row.id, tenantID, row.scopeType, row.scopeRef, config); err != nil {
			t.Fatalf("insert v2 policy: %v", err)
		}
	}

	cache := NewPolicyCache(pool, time.Minute)
	engine := newModelRouteEngine(fakeModelRouteSource{routes: []ModelRecord{
		{ID: "model-a", ModelName: "acme/chat/v1", ProviderID: "provider-a"},
		{ID: "model-b", ModelName: "acme/chat/v1", ProviderID: "provider-b"},
	}}, cache)
	plan, applied, err := engine.Plan(ctx, RequestEnvelope{TenantID: tenantID, Model: "acme/chat/v1"})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !applied || plan.Primary.ProviderID != "provider-b" || plan.Decision.ProviderLayer.Strategy != "priority" {
		t.Fatalf("override did not win over default: applied=%v plan=%+v", applied, plan)
	}
}

func TestV2PolicyCacheIgnoresLegacyRows(t *testing.T) {
	pool, tenantID, _ := setupModelRouteDB(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO routing_policies (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, schema_version) VALUES ('legacy-policy',$1,'model','acme/chat/v1','provider','fallback','{}'::jsonb,true,1)`, tenantID); err != nil {
		t.Fatalf("insert legacy policy: %v", err)
	}
	cache := NewPolicyCache(pool, time.Minute)
	policy, err := cache.GetV2Policy(ctx, tenantID, "acme/chat/v1")
	if err != nil || policy != nil {
		t.Fatalf("legacy row entered v2 cache: policy=%+v err=%v", policy, err)
	}
}

func TestV2PolicyReadsReflectControlPlaneChangesImmediately(t *testing.T) {
	pool, tenantID, otherTenantID := setupModelRouteDB(t)
	ctx := context.Background()
	configFor := func(providerID string) string {
		return fmt.Sprintf(`{"strategy":"priority","cost_basis":"none","providers":[{"provider_id":%q,"enabled":true,"priority":1,"weight":0}]}`, providerID)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO routing_policies (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, schema_version, config_version) VALUES ('live-default',$1,'tenant',$1,'provider','priority',$2::jsonb,true,2,1)`, tenantID, configFor("provider-a")); err != nil {
		t.Fatalf("insert default: %v", err)
	}
	cache := NewPolicyCache(pool, time.Minute)

	policy, err := cache.GetV2Policy(ctx, tenantID, "model-update")
	if err != nil || policy == nil || policy.Config.Providers[0].ProviderID != "provider-a" {
		t.Fatalf("read initial default: policy=%+v err=%v", policy, err)
	}
	if _, err := pool.Exec(ctx, `UPDATE routing_policies SET config_json=$2::jsonb, config_version=config_version+1 WHERE id='live-default' AND tenant_id=$1`, tenantID, configFor("provider-b")); err != nil {
		t.Fatalf("update default: %v", err)
	}
	policy, err = cache.GetV2Policy(ctx, tenantID, "model-update")
	if err != nil || policy == nil || policy.Config.Providers[0].ProviderID != "provider-b" {
		t.Fatalf("stale default survived update: policy=%+v err=%v", policy, err)
	}

	if _, err := pool.Exec(ctx, `INSERT INTO routing_policies (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, schema_version, config_version) VALUES ('live-override',$1,'model','model-delete','provider','priority',$2::jsonb,true,2,1)`, tenantID, configFor("provider-a")); err != nil {
		t.Fatalf("insert override: %v", err)
	}
	policy, err = cache.GetV2Policy(ctx, tenantID, "model-delete")
	if err != nil || policy == nil || policy.Scope != modelrouting.ScopeOverride {
		t.Fatalf("read override: policy=%+v err=%v", policy, err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM routing_policies WHERE id='live-override' AND tenant_id=$1`, tenantID); err != nil {
		t.Fatalf("delete override: %v", err)
	}
	policy, err = cache.GetV2Policy(ctx, tenantID, "model-delete")
	if err != nil || policy == nil || policy.Scope != modelrouting.ScopeDefault || policy.Config.Providers[0].ProviderID != "provider-b" {
		t.Fatalf("deleted override remained visible: policy=%+v err=%v", policy, err)
	}

	policy, err = cache.GetV2Policy(ctx, tenantID, "model-created")
	if err != nil || policy == nil || policy.Scope != modelrouting.ScopeDefault {
		t.Fatalf("expected tenant default before override create: policy=%+v err=%v", policy, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO routing_policies (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, schema_version, config_version) VALUES ('new-override',$1,'model','model-created','provider','priority',$2::jsonb,true,2,1)`, tenantID, configFor("provider-a")); err != nil {
		t.Fatalf("insert new override: %v", err)
	}
	policy, err = cache.GetV2Policy(ctx, tenantID, "model-created")
	if err != nil || policy == nil || policy.Scope != modelrouting.ScopeOverride {
		t.Fatalf("new override hidden by cached default: policy=%+v err=%v", policy, err)
	}

	policy, err = cache.GetV2Policy(ctx, otherTenantID, "model-after-miss")
	if err != nil || policy != nil {
		t.Fatalf("expected initial miss: policy=%+v err=%v", policy, err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO routing_policies (id, tenant_id, scope_type, scope_ref, layer, strategy, config_json, enabled, schema_version, config_version) VALUES ('after-miss',$1,'model','model-after-miss','provider','priority',$2::jsonb,true,2,1)`, otherTenantID, configFor("provider-a")); err != nil {
		t.Fatalf("insert after miss: %v", err)
	}
	policy, err = cache.GetV2Policy(ctx, otherTenantID, "model-after-miss")
	if err != nil || policy == nil || policy.Scope != modelrouting.ScopeOverride {
		t.Fatalf("new policy hidden by cached miss: policy=%+v err=%v", policy, err)
	}
}

func setupModelRouteDB(t *testing.T) (*pgxpool.Pool, string, string) {
	t.Helper()
	dbURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	t.Cleanup(pool.Close)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID, otherTenantID := "route-tenant-"+suffix, "route-other-"+suffix
	for _, id := range []string{tenantID, otherTenantID} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name) VALUES ($1,$1)`, id); err != nil {
			t.Fatalf("insert tenant: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM routing_policies WHERE tenant_id IN ($1,$2)`, tenantID, otherTenantID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM provider_credentials WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id IN ($1,$2))`, tenantID, otherTenantID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id IN ($1,$2))`, tenantID, otherTenantID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM providers WHERE tenant_id IN ($1,$2)`, tenantID, otherTenantID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM tenants WHERE id IN ($1,$2)`, tenantID, otherTenantID)
	})
	return pool, tenantID, otherTenantID
}

func insertRouteFixture(t *testing.T, pool *pgxpool.Pool, tenantID, otherTenantID string) {
	t.Helper()
	ctx := context.Background()
	providers := []struct{ id, tenant, name, status string }{
		{"provider-a", tenantID, "供应商 A", "active"},
		{"provider-b", tenantID, "供应商 B", "active"},
		{"provider-disabled", tenantID, "禁用供应商", "disabled"},
		{"provider-no-credential", tenantID, "无凭证供应商", "active"},
		{"provider-other", otherTenantID, "其他租户", "active"},
	}
	for _, p := range providers {
		if _, err := pool.Exec(ctx, `INSERT INTO providers (id, tenant_id, name, provider_type, base_url, auth_mode, status) VALUES ($1,$2,$3,'openai',$4,'bearer',$5)`, p.id, p.tenant, p.name, "https://"+p.id+".example/v1", p.status); err != nil {
			t.Fatalf("insert provider %s: %v", p.id, err)
		}
	}
	models := []struct{ id, provider, name, upstream, status string }{
		{"model-ref-a", "provider-a", "acme/chat/v1", "upstream-a", "active"},
		{"model-ref-b", "provider-b", "acme/chat/v1", "upstream-b", "active"},
		{"model-wrong", "provider-a", "different-model", "wrong", "active"},
		{"model-disabled", "provider-b", "acme/chat/v1", "disabled", "disabled"},
		{"model-provider-disabled", "provider-disabled", "acme/chat/v1", "provider-disabled", "active"},
		{"model-no-credential", "provider-no-credential", "acme/chat/v1", "no-credential", "active"},
		{"model-other", "provider-other", "acme/chat/v1", "other", "active"},
	}
	for _, m := range models {
		if _, err := pool.Exec(ctx, `INSERT INTO models (id, provider_id, model_name, upstream_model_id, pricing_json, status) VALUES ($1,$2,$3,$4,'{"input":1,"output":2}'::jsonb,$5)`, m.id, m.provider, m.name, m.upstream, m.status); err != nil {
			t.Fatalf("insert model %s: %v", m.id, err)
		}
	}
	for _, providerID := range []string{"provider-a", "provider-b", "provider-disabled", "provider-other"} {
		if _, err := pool.Exec(ctx, `INSERT INTO provider_credentials (id, provider_id, secret_ciphertext, status) VALUES ($1,$2,'test-secret','active')`, "cred-"+providerID, providerID); err != nil {
			t.Fatalf("insert credential: %v", err)
		}
	}
}

// 目录同步探测写入的 unhealthy 只调整顺序，不剔除线路；网关真实流量熔断写入的仍然剔除。
func TestProbeSourcedUnhealthyOnlyDeprioritisesRoutes(t *testing.T) {
	now := time.Now()
	routes := []ModelRecord{{ID: "m1", ModelName: "logical/model", ProviderID: "p1"}, {ID: "m2", ModelName: "logical/model", ProviderID: "p2"}}
	probe := func(provider string) SharedRouteHealthSnapshot {
		return SharedRouteHealthSnapshot{RouteKey: RouteKey{TenantID: "t", ModelName: "logical/model", ProviderID: provider}, State: "unhealthy", Version: 1, ObservedAt: now, ExpiresAt: now.Add(time.Minute), SourceInstance: "catalog-sync:lease"}
	}
	plan := func(snapshots ...SharedRouteHealthSnapshot) (RoutePlan, error) {
		source := &fakeSharedHealthSource{fakeModelRouteSource: fakeModelRouteSource{routes: routes}, snapshots: snapshots, writes: make(chan SharedRouteHealthSnapshot, 4), ledger: make(chan attemptLedgerOperation, 4)}
		engine := newModelRouteEngine(source, fakeV2PolicySource{policy: validPriorityPolicy("p1", "p2")})
		deadline := time.Now().Add(time.Second)
		for {
			if _, ok := engine.sharedHealth(snapshots[0].RouteKey); ok {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("shared health cache did not refresh")
			}
			time.Sleep(time.Millisecond)
		}
		got, _, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "t", Model: "logical/model", RequestID: "req"})
		return got, err
	}
	got, err := plan(probe("p1"), probe("p2"))
	if err != nil || got.Primary.ProviderID == "" {
		t.Fatalf("all probe-unhealthy routes must still be tried: plan=%+v err=%v", got, err)
	}
	got, err = plan(probe("p1"))
	if err != nil || got.Primary.ProviderID != "p2" || len(got.Fallbacks) != 1 || got.Fallbacks[0].ProviderID != "p1" {
		t.Fatalf("probe-unhealthy route should move behind healthy one: plan=%+v err=%v", got, err)
	}
}
