package modelrouter

import (
	"context"
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelrouting"
)

func selectorRoute(providerID string) ModelRecord {
	return ModelRecord{ID: "model-" + providerID, ProviderID: providerID, ModelName: "acme/chat/v1"}
}

func selectorRule(providerID string, priority, weight int) modelrouting.ProviderRule {
	return modelrouting.ProviderRule{ProviderID: providerID, Enabled: true, Priority: priority, Weight: weight}
}

func selectorInput(config modelrouting.Config, streaming bool, metrics map[string]RouteMetricsSnapshot) routeSelectionInput {
	return routeSelectionInput{
		TenantID:  "tenant-a",
		ModelName: "acme/chat/v1",
		RequestID: "request-a",
		Streaming: streaming,
		Routes: []ModelRecord{
			selectorRoute("provider-a"), selectorRoute("provider-b"), selectorRoute("provider-c"), selectorRoute("provider-d"),
		},
		Config:  config,
		Metrics: metrics,
	}
}

func providerIDs(routes []ModelRecord) []string {
	ids := make([]string, 0, len(routes))
	for _, route := range routes {
		ids = append(ids, route.ProviderID)
	}
	return ids
}

func TestPrioritySelectorOrdersPrimaryAndBackups(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategyPriority, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-c", 3, 0), selectorRule("provider-a", 1, 0), selectorRule("provider-b", 2, 0), selectorRule("provider-d", 4, 0),
	}}
	selection, err := selectRoutesV2(selectorInput(config, false, nil), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("selectRoutesV2: %v", err)
	}
	if got, want := providerIDs(selection.Routes), []string{"provider-a", "provider-b", "provider-c"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("routes=%v want=%v", got, want)
	}
	if selection.Explanations[0].Reason != "selected_primary" || selection.Explanations[3].Reason != "attempt_limit_exceeded" {
		t.Fatalf("missing deterministic explanations: %+v", selection.Explanations)
	}
}

func TestWeightedSelectorIsDeterministicForSameRequest(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategyWeighted, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 1, 10), selectorRule("provider-b", 2, 90),
		{ProviderID: "provider-c", Enabled: false, Priority: 3, Weight: 1000},
		selectorRule("provider-d", 4, 0),
	}}
	input := selectorInput(config, false, nil)
	first, err := selectRoutesV2(input, modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("first select: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := selectRoutesV2(input, modelrouting.ScopeDefault)
		if err != nil || !reflect.DeepEqual(first, again) {
			t.Fatalf("same request was re-drawn or re-explained: first=%+v again=%+v err=%v", first, again, err)
		}
	}
	for _, id := range providerIDs(first.Routes) {
		if id == "provider-c" || id == "provider-d" {
			t.Fatalf("disabled or zero-weight provider participated: %v", providerIDs(first.Routes))
		}
	}
}

func TestWeightedSelectorHashIncludesTenantAndResolvedModel(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategyWeighted, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 1, 1), selectorRule("provider-b", 2, 1), selectorRule("provider-c", 3, 1),
	}}
	seen := map[string]struct{}{}
	for i := 0; i < 64; i++ {
		input := selectorInput(config, false, nil)
		input.TenantID = []string{"tenant-a", "tenant-b"}[i%2]
		input.ModelName = []string{"acme/chat/v1", "acme/embed/v1"}[(i/2)%2]
		for routeIndex := range input.Routes {
			input.Routes[routeIndex].ModelName = input.ModelName
		}
		input.RequestID = "request-" + string(rune('A'+i))
		selection, err := selectRoutesV2(input, modelrouting.ScopeDefault)
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		seen[selection.Routes[0].ProviderID] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatalf("stable hash did not distribute across weighted candidates: %v", seen)
	}
}

func TestWeightedSelectorSticksToSessionWhenSessionIDPresent(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategyWeighted, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 1, 1), selectorRule("provider-b", 2, 1), selectorRule("provider-c", 3, 1),
	}}

	// Same session, many different request IDs: primary route must not change.
	first := routeSelection{}
	for i := 0; i < 16; i++ {
		input := selectorInput(config, false, nil)
		input.SessionID = "session-alpha"
		input.RequestID = "req-" + string(rune('a'+i))
		selection, err := selectRoutesV2(input, modelrouting.ScopeDefault)
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if selection.Mode != "weighted_session_sticky" {
			t.Fatalf("session input must report sticky mode, got %q", selection.Mode)
		}
		if i == 0 {
			first = selection
			continue
		}
		if selection.Routes[0].ProviderID != first.Routes[0].ProviderID {
			t.Fatalf("same session re-routed: first=%s now=%s", first.Routes[0].ProviderID, selection.Routes[0].ProviderID)
		}
	}

	// Different sessions must distribute across weighted routes over time.
	seen := map[string]struct{}{}
	for i := 0; i < 48; i++ {
		input := selectorInput(config, false, nil)
		input.SessionID = "session-" + string(rune('A'+i))
		input.RequestID = "shared-request-id"
		selection, err := selectRoutesV2(input, modelrouting.ScopeDefault)
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		seen[selection.Routes[0].ProviderID] = struct{}{}
	}
	if len(seen) < 2 {
		t.Fatalf("session hash did not distribute across weighted candidates: %v", seen)
	}

	// No session identifier: per-request distribution, plain weighted mode.
	input := selectorInput(config, false, nil)
	selection, err := selectRoutesV2(input, modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selection.Mode != "weighted" {
		t.Fatalf("request-only input must keep plain weighted mode, got %q", selection.Mode)
	}
}


func warm(success float64, latency, ttft time.Duration) RouteMetricsSnapshot {
	return RouteMetricsSnapshot{SampleCount: 20, SuccessRate: success, P95Latency: latency, P95TTFT: ttft}
}

func TestSmartSelectorFallsBackToPriorityWhenSamplesAreCold(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveStability, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 1, 0), selectorRule("provider-b", 2, 0),
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": {SampleCount: 19, SuccessRate: .1, P95Latency: 9 * time.Second},
		"provider-b": warm(.999, 10*time.Millisecond, 5*time.Millisecond),
	}
	selection, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selection.Routes[0].ProviderID != "provider-a" || selection.Mode != "priority_cold_start" {
		t.Fatalf("cold samples must use administrator priority: %+v", selection)
	}
}

func TestSmartStabilityPrefersHigherSuccessRateThenLowerP95Latency(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveStability, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 1, 0), selectorRule("provider-b", 2, 0), selectorRule("provider-c", 3, 0),
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(.98, 100*time.Millisecond, 20*time.Millisecond),
		"provider-b": warm(.99, 300*time.Millisecond, 30*time.Millisecond),
		"provider-c": warm(.99, 200*time.Millisecond, 40*time.Millisecond),
	}
	selection, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if got, want := providerIDs(selection.Routes), []string{"provider-c", "provider-b", "provider-a"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("stability order=%v want=%v", got, want)
	}
}

func TestSmartLatencyUsesTTFTForStreamingAndTotalLatencyOtherwise(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveLatency, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 1, 0), selectorRule("provider-b", 2, 0),
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(.99, 100*time.Millisecond, 900*time.Millisecond),
		"provider-b": warm(.99, 900*time.Millisecond, 100*time.Millisecond),
	}
	streaming, err := selectRoutesV2(selectorInput(config, true, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("streaming select: %v", err)
	}
	nonStreaming, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("non-streaming select: %v", err)
	}
	if streaming.Routes[0].ProviderID != "provider-b" || nonStreaming.Routes[0].ProviderID != "provider-a" {
		t.Fatalf("wrong latency metric: streaming=%v non-streaming=%v", providerIDs(streaming.Routes), providerIDs(nonStreaming.Routes))
	}
}

func TestSmartCostIgnoresRoutesWithoutCostInsteadOfAssumingZero(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveCost, CostBasis: modelrouting.CostRelative, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 1, 0),
		{ProviderID: "provider-b", Enabled: true, Priority: 2, RelativeCost: modelrouting.CostLow},
		{ProviderID: "provider-c", Enabled: true, Priority: 3, RelativeCost: modelrouting.CostHigh},
	}}
	selection, err := selectRoutesV2(selectorInput(config, false, map[string]RouteMetricsSnapshot{
		"provider-a": warm(.99, time.Second, time.Second), "provider-b": warm(.99, time.Second, time.Second), "provider-c": warm(.99, time.Second, time.Second),
	}), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selection.Routes[0].ProviderID != "provider-b" {
		t.Fatalf("missing cost was treated as free: %v", providerIDs(selection.Routes))
	}
	encoded, err := json.Marshal(selection.Explanations)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "input_per_million") || strings.Contains(string(encoded), "output_per_million") {
		t.Fatalf("decision leaked purchase amount: %s", encoded)
	}
}

func TestSmartCostWithNoComparableCostFallsBackToPriority(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveCost, CostBasis: modelrouting.CostActual, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-b", 2, 0), selectorRule("provider-a", 1, 0),
	}}
	selection, err := selectRoutesV2(selectorInput(config, false, map[string]RouteMetricsSnapshot{
		"provider-a": warm(.99, time.Second, time.Second), "provider-b": warm(.99, time.Second, time.Second),
	}), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selection.Routes[0].ProviderID != "provider-a" || selection.Mode != "priority_cost_unavailable" {
		t.Fatalf("expected safe priority fallback, got %+v", selection)
	}
}

func TestSmartBalancedUsesConfiguredDimensionsOnly(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveBalanced, CostBasis: modelrouting.CostRelative, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 1, 0),
		{ProviderID: "provider-b", Enabled: true, Priority: 2, RelativeCost: modelrouting.CostLow},
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(1, 10*time.Millisecond, 10*time.Millisecond),
		"provider-b": warm(.90, time.Second, time.Second),
	}
	selection, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selection.Routes[0].ProviderID != "provider-a" {
		t.Fatalf("missing cost should re-normalize available dimensions, got %v", providerIDs(selection.Routes))
	}
	for _, explanation := range selection.Explanations {
		if _, hasCostScore := explanation.Scores["cost"]; hasCostScore {
			t.Fatalf("partially configured cost must be ignored for every candidate: %+v", selection.Explanations)
		}
		for _, score := range explanation.Scores {
			if score < 0 || score > 1 {
				t.Fatalf("score not normalized: %+v", explanation)
			}
		}
	}
}

func TestSmartActualCostDoesNotLeakPurchaseAmounts(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveBalanced, CostBasis: modelrouting.CostActual, Providers: []modelrouting.ProviderRule{
		{ProviderID: "provider-a", Enabled: true, Priority: 1, ActualCost: &modelrouting.TokenPrice{Currency: "CNY", InputPerMillion: 123.456789, OutputPerMillion: 987.654321}},
		{ProviderID: "provider-b", Enabled: true, Priority: 2, ActualCost: &modelrouting.TokenPrice{Currency: "CNY", InputPerMillion: 321.654987, OutputPerMillion: 789.456123}},
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(.99, 100*time.Millisecond, 50*time.Millisecond),
		"provider-b": warm(.98, 200*time.Millisecond, 80*time.Millisecond),
	}
	selection, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	encoded, err := json.Marshal(selection.Explanations)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"123.456789", "987.654321", "321.654987", "789.456123", "input_per_million", "output_per_million"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("decision leaked actual purchase price %q: %s", secret, encoded)
		}
	}
}

func TestSmartSelectorNeverEmitsNaNOrInfinity(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveBalanced, CostBasis: modelrouting.CostActual, Providers: []modelrouting.ProviderRule{
		{ProviderID: "provider-a", Enabled: true, Priority: 1, ActualCost: &modelrouting.TokenPrice{Currency: "CNY", InputPerMillion: math.NaN(), OutputPerMillion: 1}},
		{ProviderID: "provider-b", Enabled: true, Priority: 2, ActualCost: &modelrouting.TokenPrice{Currency: "CNY", InputPerMillion: 1, OutputPerMillion: 1}},
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(math.NaN(), 100*time.Millisecond, 50*time.Millisecond),
		"provider-b": warm(.99, 200*time.Millisecond, 80*time.Millisecond),
	}
	selection, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	for _, explanation := range selection.Explanations {
		for name, score := range explanation.Scores {
			if math.IsNaN(score) || math.IsInf(score, 0) {
				t.Fatalf("%s emitted invalid %s score: %v", explanation.ProviderID, name, score)
			}
		}
	}
	if _, err := json.Marshal(selection.Explanations); err != nil {
		t.Fatalf("explanation is not JSON safe: %v", err)
	}
}

func TestCustomObjectiveOnlyChangesDimensionOrder(t *testing.T) {
	rules := []modelrouting.ProviderRule{
		{ProviderID: "provider-a", Enabled: true, Priority: 1, RelativeCost: modelrouting.CostHigh},
		{ProviderID: "provider-b", Enabled: true, Priority: 2, RelativeCost: modelrouting.CostLow},
	}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(1, time.Second, time.Second),
		"provider-b": warm(.95, 10*time.Millisecond, 10*time.Millisecond),
	}
	latencyFirst := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveCustom, CustomOrder: []modelrouting.Objective{modelrouting.ObjectiveLatency, modelrouting.ObjectiveStability, modelrouting.ObjectiveCost}, CostBasis: modelrouting.CostRelative, Providers: rules}
	stabilityFirst := latencyFirst
	stabilityFirst.CustomOrder = []modelrouting.Objective{modelrouting.ObjectiveStability, modelrouting.ObjectiveLatency, modelrouting.ObjectiveCost}
	fast, err := selectRoutesV2(selectorInput(latencyFirst, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("latency-first: %v", err)
	}
	stable, err := selectRoutesV2(selectorInput(stabilityFirst, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("stability-first: %v", err)
	}
	if fast.Routes[0].ProviderID != "provider-b" || stable.Routes[0].ProviderID != "provider-a" {
		t.Fatalf("custom order did more/less than reorder dimensions: fast=%v stable=%v", providerIDs(fast.Routes), providerIDs(stable.Routes))
	}
}

func TestCustomStabilityKeepsSuccessThenP95LatencySemantics(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveCustom, CustomOrder: []modelrouting.Objective{modelrouting.ObjectiveStability, modelrouting.ObjectiveCost, modelrouting.ObjectiveLatency}, CostBasis: modelrouting.CostRelative, Providers: []modelrouting.ProviderRule{
		{ProviderID: "provider-a", Enabled: true, Priority: 1, RelativeCost: modelrouting.CostHigh},
		{ProviderID: "provider-b", Enabled: true, Priority: 2, RelativeCost: modelrouting.CostLow},
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(.99, 100*time.Millisecond, 100*time.Millisecond),
		"provider-b": warm(.99, 900*time.Millisecond, 10*time.Millisecond),
	}
	selection, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selection.Routes[0].ProviderID != "provider-a" {
		t.Fatalf("custom stability skipped its P95 latency tie-breaker: %v", providerIDs(selection.Routes))
	}
}

func TestCustomObjectiveIgnoresMixedActualCostCurrenciesForWholeGroup(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveCustom, CustomOrder: []modelrouting.Objective{modelrouting.ObjectiveCost, modelrouting.ObjectiveStability, modelrouting.ObjectiveLatency}, CostBasis: modelrouting.CostActual, Providers: []modelrouting.ProviderRule{
		{ProviderID: "provider-a", Enabled: true, Priority: 1, ActualCost: &modelrouting.TokenPrice{Currency: "CNY", InputPerMillion: 700.123456, OutputPerMillion: 300.654321}},
		{ProviderID: "provider-b", Enabled: true, Priority: 2, ActualCost: &modelrouting.TokenPrice{Currency: "USD", InputPerMillion: 1.234567, OutputPerMillion: 1.765432}},
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(.99, 100*time.Millisecond, 50*time.Millisecond),
		"provider-b": warm(.90, 10*time.Millisecond, 5*time.Millisecond),
	}
	selection, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selection.Routes[0].ProviderID != "provider-a" || selection.Mode != "smart_custom_cost_ignored" {
		t.Fatalf("mixed currencies affected custom routing: %+v", selection)
	}
	assertCustomCostIgnored(t, selection, "ignored_mixed_currency")
}

func TestCustomObjectiveIgnoresPartialCostsForWholeGroup(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveCustom, CustomOrder: []modelrouting.Objective{modelrouting.ObjectiveCost, modelrouting.ObjectiveStability, modelrouting.ObjectiveLatency}, CostBasis: modelrouting.CostRelative, Providers: []modelrouting.ProviderRule{
		{ProviderID: "provider-a", Enabled: true, Priority: 2},
		{ProviderID: "provider-b", Enabled: true, Priority: 1, RelativeCost: modelrouting.CostLow},
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(.99, 100*time.Millisecond, 50*time.Millisecond),
		"provider-b": warm(.90, 10*time.Millisecond, 5*time.Millisecond),
	}
	selection, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selection.Routes[0].ProviderID != "provider-a" || selection.Mode != "smart_custom_cost_ignored" {
		t.Fatalf("partial costs affected custom routing: %+v", selection)
	}
	assertCustomCostIgnored(t, selection, "ignored_incomplete")
}

func TestCustomCostFirstWithIncomparableCostsFallsBackToAdministratorPriority(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveCustom, CustomOrder: []modelrouting.Objective{modelrouting.ObjectiveCost, modelrouting.ObjectiveStability, modelrouting.ObjectiveLatency}, CostBasis: modelrouting.CostActual, Providers: []modelrouting.ProviderRule{
		{ProviderID: "provider-a", Enabled: true, Priority: 1, ActualCost: &modelrouting.TokenPrice{Currency: "CNY", InputPerMillion: 100, OutputPerMillion: 100}},
		{ProviderID: "provider-b", Enabled: true, Priority: 2, ActualCost: &modelrouting.TokenPrice{Currency: "USD", InputPerMillion: 1, OutputPerMillion: 1}},
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(.99, 100*time.Millisecond, 50*time.Millisecond),
		"provider-b": warm(.99, 100*time.Millisecond, 50*time.Millisecond),
	}
	selection, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if got := providerIDs(selection.Routes); !reflect.DeepEqual(got, []string{"provider-a", "provider-b"}) {
		t.Fatalf("incomparable cost-only decision did not use administrator priority: %v", got)
	}
	assertCustomCostIgnored(t, selection, "ignored_mixed_currency")
}

func TestCustomObjectiveSkipsLatencyForWholeGroupWhenAnyP95IsMissing(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveCustom, CustomOrder: []modelrouting.Objective{modelrouting.ObjectiveLatency, modelrouting.ObjectiveStability, modelrouting.ObjectiveCost}, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 2, 0), selectorRule("provider-b", 1, 0),
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(.99, 0, 0),
		"provider-b": warm(.90, 10*time.Millisecond, 5*time.Millisecond),
	}
	selection, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selection.Routes[0].ProviderID != "provider-a" {
		t.Fatalf("partial latency affected custom routing: %+v", selection)
	}
	for _, explanation := range selection.Explanations[:2] {
		if _, ok := explanation.Scores["latency"]; ok || explanation.DimensionState["latency"] != "ignored_incomplete" {
			t.Fatalf("latency was not uniformly ignored: %+v", explanation)
		}
	}
}

func TestSmartBalancedSkipsLatencyForWholeGroupWhenAnyP95IsMissing(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveBalanced, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 2, 0), selectorRule("provider-b", 1, 0),
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(.99, 0, 0),
		"provider-b": warm(.90, 10*time.Millisecond, 5*time.Millisecond),
	}
	input := selectorInput(config, false, metrics)
	first, err := selectRoutesV2(input, modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if first.Routes[0].ProviderID != "provider-a" {
		t.Fatalf("unknown latency outranked stability: %+v", first)
	}
	for _, explanation := range first.Explanations[:2] {
		if _, ok := explanation.Scores["latency"]; ok || explanation.DimensionState["latency"] != "ignored_incomplete" {
			t.Fatalf("balanced latency was not uniformly ignored: %+v", explanation)
		}
	}
	for i := 0; i < 20; i++ {
		again, err := selectRoutesV2(input, modelrouting.ScopeDefault)
		if err != nil || !reflect.DeepEqual(first, again) {
			t.Fatalf("balanced partial-metric order was not deterministic: first=%+v again=%+v err=%v", first, again, err)
		}
	}
}

func TestSmartBalancedFallsBackToPriorityWhenAllDimensionsAreUnavailable(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategySmart, Objective: modelrouting.ObjectiveBalanced, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 2, 0), selectorRule("provider-b", 1, 0),
	}}
	metrics := map[string]RouteMetricsSnapshot{
		"provider-a": warm(math.NaN(), 0, 0),
		"provider-b": warm(math.NaN(), 0, 0),
	}
	selection, err := selectRoutesV2(selectorInput(config, false, metrics), modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if selection.Routes[0].ProviderID != "provider-b" || selection.Mode != "priority_dynamic_dimensions_unavailable" {
		t.Fatalf("all-unavailable balanced routing did not fall back to priority: %+v", selection)
	}
}

func assertCustomCostIgnored(t *testing.T, selection routeSelection, wantCostState string) {
	t.Helper()
	for _, explanation := range selection.Explanations[:2] {
		if _, ok := explanation.Scores["cost"]; ok {
			t.Fatalf("ignored custom cost emitted a score: %+v", explanation)
		}
		if explanation.CostState != wantCostState {
			t.Fatalf("cost state=%q want=%q: %+v", explanation.CostState, wantCostState, explanation)
		}
	}
	encoded, err := json.Marshal(selection.Explanations)
	if err != nil {
		t.Fatalf("marshal explanations: %v", err)
	}
	for _, amount := range []string{"700.123456", "300.654321", "1.234567", "1.765432"} {
		if strings.Contains(string(encoded), amount) {
			t.Fatalf("ignored custom cost leaked purchase amount %q: %s", amount, encoded)
		}
	}
}

func TestFixedSelectorOnlyAllowsValidatedModelOverride(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategyFixed, FixedProviderID: "provider-b", CostBasis: modelrouting.CostNone}
	selection, err := selectRoutesV2(selectorInput(config, false, nil), modelrouting.ScopeOverride)
	if err != nil || !reflect.DeepEqual(providerIDs(selection.Routes), []string{"provider-b"}) {
		t.Fatalf("valid fixed override failed: selection=%+v err=%v", selection, err)
	}
	if len(selection.Explanations) != 4 {
		t.Fatalf("fixed strategy did not explain every candidate: %+v", selection.Explanations)
	}
	for _, explanation := range selection.Explanations {
		if explanation.ProviderID == "provider-b" {
			if explanation.Reason != "selected_primary" || explanation.Scores["fixed"] != 1 {
				t.Fatalf("fixed provider explanation=%+v", explanation)
			}
			continue
		}
		if explanation.Reason != "excluded_by_fixed_strategy" || explanation.Scores["fixed"] != 0 || explanation.CostState != "not_used" {
			t.Fatalf("excluded fixed candidate lacks explanation: %+v", explanation)
		}
	}
	if _, err := selectRoutesV2(selectorInput(config, false, nil), modelrouting.ScopeDefault); err == nil {
		t.Fatal("fixed default bypassed shared validation")
	}
}

func TestSelectorNeverCrossesResolvedLogicalModel(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategyPriority, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 1, 0), selectorRule("provider-b", 2, 0),
	}}
	input := selectorInput(config, false, nil)
	input.Routes[0].ModelName = "different/model"
	selection, err := selectRoutesV2(input, modelrouting.ScopeDefault)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if got := providerIDs(selection.Routes); !reflect.DeepEqual(got, []string{"provider-b"}) {
		t.Fatalf("cross-model route participated: %v", got)
	}
}

func TestEngineDecisionIncludesAllCandidateExplanationsButOnlyThreeAttempts(t *testing.T) {
	config := modelrouting.Config{Strategy: modelrouting.StrategyPriority, CostBasis: modelrouting.CostNone, Providers: []modelrouting.ProviderRule{
		selectorRule("provider-a", 1, 0), selectorRule("provider-b", 2, 0), selectorRule("provider-c", 3, 0), selectorRule("provider-d", 4, 0),
	}}
	policy := &V2RoutingPolicy{Scope: modelrouting.ScopeDefault, Config: config}
	engine := newModelRouteEngine(fakeModelRouteSource{routes: selectorInput(config, false, nil).Routes}, fakeV2PolicySource{policy: policy})
	plan, applied, err := engine.Plan(context.Background(), RequestEnvelope{TenantID: "tenant-a", Model: "acme/chat/v1", RequestID: "request-a"})
	if err != nil || !applied {
		t.Fatalf("Plan: applied=%v err=%v", applied, err)
	}
	if plan.Primary.ProviderID != "provider-a" || len(plan.Fallbacks) != 2 {
		t.Fatalf("expected one primary plus two fallbacks: %+v", plan)
	}
	explanations, ok := plan.Decision.ProviderLayer.Reason["candidates"].([]routeExplanation)
	if !ok || len(explanations) != 4 || explanations[3].Reason != "attempt_limit_exceeded" {
		t.Fatalf("decision did not explain all candidates: %#v", plan.Decision.ProviderLayer.Reason)
	}
}
