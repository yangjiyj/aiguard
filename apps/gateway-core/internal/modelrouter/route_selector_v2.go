package modelrouter

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelrouting"
)

const (
	minimumSmartSamples  = 20
	maximumRouteAttempts = 3
)

// RouteMetricsSnapshot is an immutable selector input. Task 7 is responsible
// for producing snapshots; the selector never reads or mutates live state.
type RouteMetricsSnapshot struct {
	SampleCount int
	SuccessRate float64
	P95Latency  time.Duration
	P95TTFT     time.Duration
	Version     uint64
	EvaluatedAt time.Time
}

type routeSelectionInput struct {
	TenantID  string
	ModelName string
	RequestID string
	// SessionID sticks weighted routing to one route for the whole conversation
	// when the client supplies a session identifier; empty falls back to
	// per-request distribution keyed by RequestID.
	SessionID string
	Streaming bool
	Routes    []ModelRecord
	Config    modelrouting.Config
	Metrics   map[string]RouteMetricsSnapshot
}

type routeExplanation struct {
	ProviderID     string             `json:"provider_id"`
	SampleState    string             `json:"sample_state"`
	Scores         map[string]float64 `json:"normalized_scores,omitempty"`
	DimensionState map[string]string  `json:"dimension_state,omitempty"`
	CostState      string             `json:"cost_state,omitempty"`
	Reason         string             `json:"reason"`
}

type routeSelection struct {
	Routes            []ModelRecord
	OrderedRoutes     []ModelRecord
	Mode              string
	Explanations      []routeExplanation
	EvaluationVersion uint64
}

type selectionCandidate struct {
	route          ModelRecord
	rule           modelrouting.ProviderRule
	configIndex    int
	metrics        RouteMetricsSnapshot
	cost           float64
	hasCost        bool
	costState      string
	scores         map[string]float64
	dimensionState map[string]string
}

func selectRoutesV2(input routeSelectionInput, scope modelrouting.Scope) (routeSelection, error) {
	if input.Config.Strategy == modelrouting.StrategyFixed {
		if err := input.Config.Validate(scope); err != nil {
			return routeSelection{}, err
		}
		return selectFixedRoute(input)
	}

	candidates := configuredCandidates(input)
	if len(candidates) == 0 {
		return routeSelection{}, fmt.Errorf("no valid route for requested model")
	}

	var mode string
	switch input.Config.Strategy {
	case modelrouting.StrategyPriority:
		mode = "priority"
		sortAndScorePriority(candidates)
	case modelrouting.StrategyWeighted:
		mode = "weighted"
		if input.SessionID != "" {
			mode = "weighted_session_sticky"
		}
		var err error
		candidates, err = orderWeighted(input, candidates)
		if err != nil {
			return routeSelection{}, err
		}
	case modelrouting.StrategySmart:
		candidates, mode = orderSmart(input, candidates)
	default:
		return routeSelection{}, fmt.Errorf("unsupported model routing strategy %q", input.Config.Strategy)
	}

	return finishSelection(input, candidates, mode), nil
}

func configuredCandidates(input routeSelectionInput) []selectionCandidate {
	candidates := make([]selectionCandidate, 0, len(input.Config.Providers))
	seen := make(map[string]struct{}, len(input.Config.Providers))
	for index, rule := range input.Config.Providers {
		if !rule.Enabled {
			continue
		}
		if _, duplicate := seen[rule.ProviderID]; duplicate {
			continue
		}
		seen[rule.ProviderID] = struct{}{}
		for _, route := range input.Routes {
			if route.ProviderID != rule.ProviderID || route.ModelName != input.ModelName {
				continue
			}
			candidate := selectionCandidate{
				route: route, rule: rule, configIndex: index,
				metrics:        input.Metrics[rule.ProviderID],
				scores:         make(map[string]float64),
				dimensionState: make(map[string]string),
			}
			candidate.cost, candidate.hasCost, candidate.costState = configuredCost(rule, input.Config.CostBasis)
			candidates = append(candidates, candidate)
			break
		}
	}
	return candidates
}

func selectFixedRoute(input routeSelectionInput) (routeSelection, error) {
	selectedIndex := -1
	for index, route := range input.Routes {
		if route.ProviderID != input.Config.FixedProviderID || route.ModelName != input.ModelName {
			continue
		}
		selectedIndex = index
		break
	}
	if selectedIndex < 0 {
		return routeSelection{}, fmt.Errorf("no valid route for requested model")
	}

	explanations := make([]routeExplanation, 0, len(input.Routes))
	for index, route := range input.Routes {
		explanation := routeExplanation{
			ProviderID:     route.ProviderID,
			SampleState:    sampleState(input.Metrics[route.ProviderID]),
			Scores:         map[string]float64{"fixed": 0},
			DimensionState: map[string]string{"fixed": "used"},
			CostState:      "not_used",
			Reason:         "excluded_by_fixed_strategy",
		}
		if route.ModelName != input.ModelName {
			explanation.Reason = "different_logical_model"
		}
		if index == selectedIndex {
			explanation.Scores["fixed"] = 1
			explanation.Reason = "selected_primary"
		}
		explanations = append(explanations, explanation)
	}
	return routeSelection{
		Routes:        []ModelRecord{input.Routes[selectedIndex]},
		OrderedRoutes: []ModelRecord{input.Routes[selectedIndex]},
		Mode:          "fixed",
		Explanations:  explanations,
	}, nil
}

func orderWeighted(input routeSelectionInput, candidates []selectionCandidate) ([]selectionCandidate, error) {
	participants := make([]selectionCandidate, 0, len(candidates))
	var total uint64
	for _, candidate := range candidates {
		if candidate.rule.Weight <= 0 {
			continue
		}
		weight := uint64(candidate.rule.Weight)
		if math.MaxUint64-total < weight {
			return nil, fmt.Errorf("model routing weight total overflow")
		}
		total += weight
		participants = append(participants, candidate)
	}
	if len(participants) == 0 || total == 0 {
		return nil, fmt.Errorf("no positive-weight route for requested model")
	}

	// Weighted distribution is deterministic per seed so retries of the same
	// request stay on the same route. When the client provides a session
	// identifier, the whole conversation sticks to one route (new sessions
	// re-roll the weighted dice); otherwise each request is its own seed.
	hashSeed := input.RequestID
	if input.SessionID != "" {
		hashSeed = input.SessionID
	}
	hash := sha256.Sum256([]byte(input.TenantID + "\x00" + input.ModelName + "\x00" + hashSeed))
	bucket := binary.BigEndian.Uint64(hash[:8]) % total
	selected := 0
	var cumulative uint64
	for index, candidate := range participants {
		participants[index].scores["weight"] = clamp01(float64(candidate.rule.Weight) / float64(total))
		cumulative += uint64(candidate.rule.Weight)
		if bucket < cumulative {
			selected = index
			break
		}
	}
	primary := participants[selected]
	rest := append([]selectionCandidate(nil), participants[:selected]...)
	rest = append(rest, participants[selected+1:]...)
	sortByPriority(rest)
	return append([]selectionCandidate{primary}, rest...), nil
}

func orderSmart(input routeSelectionInput, candidates []selectionCandidate) ([]selectionCandidate, string) {
	for _, candidate := range candidates {
		if candidate.metrics.SampleCount < minimumSmartSamples {
			sortAndScorePriority(candidates)
			return candidates, "priority_cold_start"
		}
	}

	switch input.Config.Objective {
	case modelrouting.ObjectiveStability:
		setDimensionState(candidates, modelrouting.ObjectiveStability, "used")
		scoreStability(candidates)
		sort.SliceStable(candidates, func(i, j int) bool {
			leftSuccess := finiteRate(candidates[i].metrics.SuccessRate)
			rightSuccess := finiteRate(candidates[j].metrics.SuccessRate)
			if leftSuccess != rightSuccess {
				return leftSuccess > rightSuccess
			}
			if candidates[i].metrics.P95Latency != candidates[j].metrics.P95Latency {
				return positiveDuration(candidates[i].metrics.P95Latency) < positiveDuration(candidates[j].metrics.P95Latency)
			}
			return priorityLess(candidates[i], candidates[j])
		})
		return candidates, "smart_stability"
	case modelrouting.ObjectiveLatency:
		if !scoreLatency(candidates, input.Streaming) {
			setDimensionState(candidates, modelrouting.ObjectiveLatency, "ignored_incomplete")
			sortAndScorePriority(candidates)
			return candidates, "priority_latency_unavailable"
		}
		for index := range candidates {
			if _, ok := selectedLatency(candidates[index].metrics, input.Streaming); ok {
				candidates[index].dimensionState[string(modelrouting.ObjectiveLatency)] = "used"
			} else {
				candidates[index].dimensionState[string(modelrouting.ObjectiveLatency)] = "unavailable"
			}
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			left, leftOK := selectedLatency(candidates[i].metrics, input.Streaming)
			right, rightOK := selectedLatency(candidates[j].metrics, input.Streaming)
			if leftOK != rightOK {
				return leftOK
			}
			if leftOK && left != right {
				return left < right
			}
			return priorityLess(candidates[i], candidates[j])
		})
		return candidates, "smart_latency"
	case modelrouting.ObjectiveCost:
		if !costsComparable(candidates, input.Config.CostBasis) {
			setDimensionState(candidates, modelrouting.ObjectiveCost, costDimensionState(candidates, input.Config.CostBasis))
			sortAndScorePriority(candidates)
			return candidates, "priority_cost_unavailable"
		}
		scoreCost(candidates)
		for index := range candidates {
			if candidates[index].hasCost {
				candidates[index].dimensionState[string(modelrouting.ObjectiveCost)] = "used"
			} else {
				candidates[index].dimensionState[string(modelrouting.ObjectiveCost)] = "unavailable"
			}
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			if candidates[i].hasCost != candidates[j].hasCost {
				return candidates[i].hasCost
			}
			if candidates[i].hasCost && candidates[i].cost != candidates[j].cost {
				return candidates[i].cost < candidates[j].cost
			}
			return priorityLess(candidates[i], candidates[j])
		})
		return candidates, "smart_cost"
	case modelrouting.ObjectiveBalanced:
		stabilityEnabled := allStabilityComparable(candidates)
		latencyEnabled := allLatencyComparable(candidates, input.Streaming)
		costEnabled := allCostsComparable(candidates, input.Config.CostBasis)
		setGroupedDimensionStates(candidates, stabilityEnabled, latencyEnabled, costEnabled, input.Config.CostBasis)
		if !stabilityEnabled && !latencyEnabled && !costEnabled {
			sortAndScorePriority(candidates)
			return candidates, "priority_dynamic_dimensions_unavailable"
		}
		scoreBalanced(candidates, input.Streaming, stabilityEnabled, latencyEnabled, costEnabled)
		sort.SliceStable(candidates, func(i, j int) bool {
			if candidates[i].scores["balanced"] != candidates[j].scores["balanced"] {
				return candidates[i].scores["balanced"] > candidates[j].scores["balanced"]
			}
			return priorityLess(candidates[i], candidates[j])
		})
		return candidates, "smart_balanced"
	case modelrouting.ObjectiveCustom:
		if !validCustomOrder(input.Config.CustomOrder) {
			sortAndScorePriority(candidates)
			return candidates, "priority_custom_invalid"
		}
		stabilityEnabled := allStabilityComparable(candidates)
		latencyEnabled := allLatencyComparable(candidates, input.Streaming)
		costEnabled := allCostsComparable(candidates, input.Config.CostBasis)
		setGroupedDimensionStates(candidates, stabilityEnabled, latencyEnabled, costEnabled, input.Config.CostBasis)
		if stabilityEnabled {
			scoreStability(candidates)
		}
		if latencyEnabled {
			scoreLatency(candidates, input.Streaming)
		}
		if costEnabled {
			scoreCost(candidates)
		}
		if !stabilityEnabled && !latencyEnabled && !costEnabled {
			sortAndScorePriority(candidates)
			return candidates, "priority_custom_dimensions_unavailable"
		}
		sort.SliceStable(candidates, func(i, j int) bool {
			for _, dimension := range input.Config.CustomOrder {
				if !customDimensionEnabled(dimension, stabilityEnabled, latencyEnabled, costEnabled) {
					continue
				}
				if comparison := compareDimension(candidates[i], candidates[j], dimension, input.Streaming); comparison != 0 {
					return comparison > 0
				}
			}
			return priorityLess(candidates[i], candidates[j])
		})
		if !costEnabled && input.Config.CostBasis != modelrouting.CostNone && input.Config.CostBasis != "" {
			return candidates, "smart_custom_cost_ignored"
		}
		return candidates, "smart_custom"
	default:
		sortAndScorePriority(candidates)
		return candidates, "priority_objective_invalid"
	}
}

func finishSelection(input routeSelectionInput, ordered []selectionCandidate, mode string) routeSelection {
	selectedCount := len(ordered)
	if selectedCount > maximumRouteAttempts {
		selectedCount = maximumRouteAttempts
	}
	routes := make([]ModelRecord, 0, selectedCount)
	orderedRoutes := make([]ModelRecord, 0, len(ordered))
	reasons := make(map[string]string, len(ordered))
	scores := make(map[string]map[string]float64, len(ordered))
	costStates := make(map[string]string, len(ordered))
	dimensionStates := make(map[string]map[string]string, len(ordered))
	for index, candidate := range ordered {
		orderedRoutes = append(orderedRoutes, candidate.route)
		scores[candidate.route.ProviderID] = candidate.scores
		costStates[candidate.route.ProviderID] = candidate.costState
		dimensionStates[candidate.route.ProviderID] = candidate.dimensionState
		if index >= selectedCount {
			reasons[candidate.route.ProviderID] = "attempt_limit_exceeded"
			continue
		}
		routes = append(routes, candidate.route)
		if index == 0 {
			reasons[candidate.route.ProviderID] = "selected_primary"
		} else {
			reasons[candidate.route.ProviderID] = fmt.Sprintf("selected_fallback_%d", index)
		}
	}

	explanations := make([]routeExplanation, 0, len(input.Routes))
	for _, route := range input.Routes {
		explanation := routeExplanation{ProviderID: route.ProviderID, SampleState: sampleState(input.Metrics[route.ProviderID])}
		explanation.Scores = scores[route.ProviderID]
		explanation.DimensionState = dimensionStates[route.ProviderID]
		explanation.CostState = costStates[route.ProviderID]
		explanation.Reason = reasons[route.ProviderID]
		if explanation.Reason == "" {
			explanation.Reason = exclusionReason(input, route)
		}
		explanations = append(explanations, explanation)
	}
	return routeSelection{Routes: routes, OrderedRoutes: orderedRoutes, Mode: mode, Explanations: explanations, EvaluationVersion: metricsEvaluationVersion(input, ordered)}
}

func metricsEvaluationVersion(input routeSelectionInput, ordered []selectionCandidate) uint64 {
	version := uint64(1469598103934665603)
	for _, candidate := range ordered {
		for _, b := range []byte(candidate.route.ProviderID) {
			version ^= uint64(b)
			version *= 1099511628211
		}
		version ^= input.Metrics[candidate.route.ProviderID].Version
		version *= 1099511628211
	}
	return version
}

func exclusionReason(input routeSelectionInput, route ModelRecord) string {
	if route.ModelName != input.ModelName {
		return "different_logical_model"
	}
	for _, rule := range input.Config.Providers {
		if rule.ProviderID != route.ProviderID {
			continue
		}
		if !rule.Enabled {
			return "disabled_by_policy"
		}
		if input.Config.Strategy == modelrouting.StrategyWeighted && rule.Weight <= 0 {
			return "non_positive_weight"
		}
		return "duplicate_or_unavailable"
	}
	return "not_in_policy"
}

func sortByPriority(candidates []selectionCandidate) {
	sort.SliceStable(candidates, func(i, j int) bool { return priorityLess(candidates[i], candidates[j]) })
}

func sortAndScorePriority(candidates []selectionCandidate) {
	sortByPriority(candidates)
	if len(candidates) == 1 {
		candidates[0].scores["priority"] = 1
		return
	}
	for index := range candidates {
		candidates[index].scores["priority"] = clamp01(1 - float64(index)/float64(len(candidates)-1))
	}
}

func priorityLess(left, right selectionCandidate) bool {
	if left.rule.Priority != right.rule.Priority {
		if left.rule.Priority <= 0 {
			return false
		}
		if right.rule.Priority <= 0 {
			return true
		}
		return left.rule.Priority < right.rule.Priority
	}
	if left.configIndex != right.configIndex {
		return left.configIndex < right.configIndex
	}
	return left.route.ProviderID < right.route.ProviderID
}

func sampleState(metrics RouteMetricsSnapshot) string {
	if metrics.SampleCount <= 0 {
		return "missing"
	}
	if metrics.SampleCount < minimumSmartSamples {
		return "cold"
	}
	return "warm"
}

func scoreStability(candidates []selectionCandidate) {
	values := make([]float64, len(candidates))
	for index := range candidates {
		values[index] = finiteRate(candidates[index].metrics.SuccessRate)
	}
	for index, value := range normalizeHigher(values) {
		candidates[index].scores["stability"] = value
	}
}

func scoreLatency(candidates []selectionCandidate, streaming bool) bool {
	values := make([]float64, len(candidates))
	available := make([]bool, len(candidates))
	count := 0
	for index := range candidates {
		latency, ok := selectedLatency(candidates[index].metrics, streaming)
		if ok {
			values[index] = float64(latency)
			available[index] = true
			count++
		}
	}
	if count == 0 {
		return false
	}
	normalized := normalizeLowerAvailable(values, available)
	for index := range candidates {
		if available[index] {
			candidates[index].scores["latency"] = normalized[index]
		}
	}
	return true
}

func scoreCost(candidates []selectionCandidate) {
	values := make([]float64, len(candidates))
	available := make([]bool, len(candidates))
	for index := range candidates {
		values[index] = candidates[index].cost
		available[index] = candidates[index].hasCost
	}
	normalized := normalizeLowerAvailable(values, available)
	for index := range candidates {
		if available[index] {
			candidates[index].scores["cost"] = normalized[index]
		}
	}
}

func scoreBalanced(candidates []selectionCandidate, streaming bool, stabilityEnabled, latencyEnabled, costEnabled bool) {
	if stabilityEnabled {
		scoreStability(candidates)
	}
	if latencyEnabled {
		scoreLatency(candidates, streaming)
	}
	if costEnabled {
		scoreCost(candidates)
	}
	dimensions := []struct {
		name   string
		weight float64
	}{
		{name: "stability", weight: .5},
		{name: "latency", weight: .3},
		{name: "cost", weight: .2},
	}
	weights := 0.0
	if stabilityEnabled {
		weights += .5
	}
	if latencyEnabled {
		weights += .3
	}
	if costEnabled {
		weights += .2
	}
	for index := range candidates {
		weighted := 0.0
		for _, dimension := range dimensions {
			value, ok := candidates[index].scores[dimension.name]
			if !ok {
				continue
			}
			weighted += value * dimension.weight
		}
		if weights > 0 {
			candidates[index].scores["balanced"] = clamp01(weighted / weights)
		}
	}
}

func allStabilityComparable(candidates []selectionCandidate) bool {
	if len(candidates) == 0 {
		return false
	}
	for _, candidate := range candidates {
		if !validSuccessRate(candidate.metrics.SuccessRate) {
			return false
		}
	}
	return true
}

func allLatencyComparable(candidates []selectionCandidate, streaming bool) bool {
	if len(candidates) == 0 {
		return false
	}
	for _, candidate := range candidates {
		if _, ok := selectedLatency(candidate.metrics, streaming); !ok {
			return false
		}
	}
	return true
}

func setGroupedDimensionStates(candidates []selectionCandidate, stabilityEnabled, latencyEnabled, costEnabled bool, basis modelrouting.CostBasis) {
	stabilityState := "ignored_incomplete"
	if stabilityEnabled {
		stabilityState = "used"
	}
	latencyState := "ignored_incomplete"
	if latencyEnabled {
		latencyState = "used"
	}
	costState := costDimensionState(candidates, basis)
	if costEnabled {
		costState = "used"
	}
	for index := range candidates {
		candidates[index].dimensionState[string(modelrouting.ObjectiveStability)] = stabilityState
		candidates[index].dimensionState[string(modelrouting.ObjectiveLatency)] = latencyState
		candidates[index].dimensionState[string(modelrouting.ObjectiveCost)] = costState
		if !costEnabled {
			candidates[index].costState = costState
		}
	}
}

func setDimensionState(candidates []selectionCandidate, dimension modelrouting.Objective, state string) {
	for index := range candidates {
		candidates[index].dimensionState[string(dimension)] = state
	}
}

func customDimensionEnabled(dimension modelrouting.Objective, stabilityEnabled, latencyEnabled, costEnabled bool) bool {
	switch dimension {
	case modelrouting.ObjectiveStability:
		return stabilityEnabled
	case modelrouting.ObjectiveLatency:
		return latencyEnabled
	case modelrouting.ObjectiveCost:
		return costEnabled
	default:
		return false
	}
}

func configuredCost(rule modelrouting.ProviderRule, basis modelrouting.CostBasis) (float64, bool, string) {
	switch basis {
	case modelrouting.CostRelative:
		switch rule.RelativeCost {
		case modelrouting.CostLow:
			return 1, true, "relative_low"
		case modelrouting.CostMedium:
			return 2, true, "relative_medium"
		case modelrouting.CostHigh:
			return 3, true, "relative_high"
		default:
			return 0, false, "missing"
		}
	case modelrouting.CostActual:
		if rule.ActualCost == nil || rule.ActualCost.Currency == "" || !finiteNonNegative(rule.ActualCost.InputPerMillion) || !finiteNonNegative(rule.ActualCost.OutputPerMillion) {
			return 0, false, "missing"
		}
		total := rule.ActualCost.InputPerMillion + rule.ActualCost.OutputPerMillion
		if !finiteNonNegative(total) {
			return 0, false, "missing"
		}
		return total, true, "actual_configured"
	default:
		return 0, false, "not_used"
	}
}

func costsComparable(candidates []selectionCandidate, basis modelrouting.CostBasis) bool {
	count := 0
	currency := ""
	for _, candidate := range candidates {
		if !candidate.hasCost {
			continue
		}
		count++
		if basis == modelrouting.CostActual {
			candidateCurrency := candidate.rule.ActualCost.Currency
			if currency == "" {
				currency = candidateCurrency
			} else if currency != candidateCurrency {
				return false
			}
		}
	}
	return count > 0
}

func allCostsComparable(candidates []selectionCandidate, basis modelrouting.CostBasis) bool {
	if len(candidates) == 0 || basis == modelrouting.CostNone || basis == "" {
		return false
	}
	currency := ""
	for _, candidate := range candidates {
		if !candidate.hasCost {
			return false
		}
		if basis != modelrouting.CostActual {
			continue
		}
		candidateCurrency := candidate.rule.ActualCost.Currency
		if currency == "" {
			currency = candidateCurrency
		} else if currency != candidateCurrency {
			return false
		}
	}
	return true
}

func costDimensionState(candidates []selectionCandidate, basis modelrouting.CostBasis) string {
	if basis == modelrouting.CostNone || basis == "" {
		return "not_used"
	}
	currency := ""
	for _, candidate := range candidates {
		if !candidate.hasCost {
			return "ignored_incomplete"
		}
		if basis != modelrouting.CostActual {
			continue
		}
		candidateCurrency := candidate.rule.ActualCost.Currency
		if currency == "" {
			currency = candidateCurrency
		} else if currency != candidateCurrency {
			return "ignored_mixed_currency"
		}
	}
	return "used"
}

func compareDimension(left, right selectionCandidate, dimension modelrouting.Objective, streaming bool) int {
	switch dimension {
	case modelrouting.ObjectiveStability:
		leftSuccess, rightSuccess := finiteRate(left.metrics.SuccessRate), finiteRate(right.metrics.SuccessRate)
		if leftSuccess > rightSuccess {
			return 1
		}
		if leftSuccess < rightSuccess {
			return -1
		}
		leftLatency, rightLatency := positiveDuration(left.metrics.P95Latency), positiveDuration(right.metrics.P95Latency)
		if leftLatency < rightLatency {
			return 1
		}
		if leftLatency > rightLatency {
			return -1
		}
	case modelrouting.ObjectiveLatency:
		leftLatency, leftOK := selectedLatency(left.metrics, streaming)
		rightLatency, rightOK := selectedLatency(right.metrics, streaming)
		if !leftOK || !rightOK {
			return 0
		}
		if leftLatency < rightLatency {
			return 1
		}
		if leftLatency > rightLatency {
			return -1
		}
	case modelrouting.ObjectiveCost:
		if !left.hasCost || !right.hasCost {
			return 0
		}
		if left.cost < right.cost {
			return 1
		}
		if left.cost > right.cost {
			return -1
		}
	}
	return 0
}

func validCustomOrder(order []modelrouting.Objective) bool {
	if len(order) != 3 {
		return false
	}
	seen := make(map[modelrouting.Objective]struct{}, 3)
	for _, dimension := range order {
		if dimension != modelrouting.ObjectiveStability && dimension != modelrouting.ObjectiveLatency && dimension != modelrouting.ObjectiveCost {
			return false
		}
		if _, duplicate := seen[dimension]; duplicate {
			return false
		}
		seen[dimension] = struct{}{}
	}
	return true
}

func selectedLatency(metrics RouteMetricsSnapshot, streaming bool) (time.Duration, bool) {
	latency := metrics.P95Latency
	if streaming {
		latency = metrics.P95TTFT
	}
	return latency, latency > 0
}

func finiteRate(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
		return 0
	}
	if value > 1 {
		return 1
	}
	return value
}

func validSuccessRate(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0 && value <= 1
}

func finiteNonNegative(value float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= 0
}

func positiveDuration(value time.Duration) time.Duration {
	if value <= 0 {
		return time.Duration(math.MaxInt64)
	}
	return value
}

func normalizeHigher(values []float64) []float64 {
	available := make([]bool, len(values))
	for index := range available {
		available[index] = true
	}
	return normalize(values, available, true)
}

func normalizeLowerAvailable(values []float64, available []bool) []float64 {
	return normalize(values, available, false)
}

func normalize(values []float64, available []bool, higherIsBetter bool) []float64 {
	result := make([]float64, len(values))
	minimum, maximum := math.Inf(1), math.Inf(-1)
	for index, value := range values {
		if !available[index] || math.IsNaN(value) || math.IsInf(value, 0) {
			continue
		}
		minimum = math.Min(minimum, value)
		maximum = math.Max(maximum, value)
	}
	if math.IsInf(minimum, 1) {
		return result
	}
	for index, value := range values {
		if !available[index] {
			continue
		}
		if maximum == minimum {
			result[index] = 1
			continue
		}
		if higherIsBetter {
			result[index] = clamp01((value - minimum) / (maximum - minimum))
		} else {
			result[index] = clamp01((maximum - value) / (maximum - minimum))
		}
	}
	return result
}

func clamp01(value float64) float64 {
	if math.IsNaN(value) || value < 0 {
		return 0
	}
	if value > 1 || math.IsInf(value, 1) {
		return 1
	}
	return value
}
