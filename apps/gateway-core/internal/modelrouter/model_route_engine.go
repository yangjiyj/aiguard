package modelrouter

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/modelrouting"
)

type modelRouteSource interface {
	ResolveLogicalModelName(ctx context.Context, tenantID, modelRef string) (string, bool, error)
	listModelRoutesByName(ctx context.Context, tenantID, modelName string) ([]ModelRecord, error)
}

type attemptLedgerOperation struct {
	finish bool
	entry  RouteAttemptLedgerEntry
}

func (e *modelRouteEngine) StartRouteAttempt(_ context.Context, entry RouteAttemptLedgerEntry) error {
	if e.ledgerQueue != nil {
		select {
		case e.ledgerQueue <- attemptLedgerOperation{entry: entry}:
		default:
		}
	}
	return nil
}

func (e *modelRouteEngine) FinishRouteAttempt(_ context.Context, entry RouteAttemptLedgerEntry) error {
	if e.ledgerQueue != nil {
		select {
		case e.ledgerQueue <- attemptLedgerOperation{finish: true, entry: entry}:
		default:
		}
	}
	return nil
}

type v2PolicySource interface {
	GetV2Policy(ctx context.Context, tenantID, modelName string) (*V2RoutingPolicy, error)
}

type modelRouteEngine struct {
	routes      modelRouteSource
	policies    v2PolicySource
	metrics     *RouteMetricsStore
	health      *RouteHealth
	preferences *PreferenceSwitch
	alerts      *AlertSink
	now         func() time.Time
	switchMu    sync.Mutex
	switches    map[RoutePreferenceKey][]time.Time
	sharedStore SharedRouteHealthStore
	sharedQueue chan SharedRouteHealthSnapshot
	sharedMu    sync.RWMutex
	shared      map[RouteKey]SharedRouteHealthSnapshot
	ledgerStore AttemptLedgerRecorder
	ledgerQueue chan attemptLedgerOperation
}

func NewModelRouteEngine(router *ModelRouter, cache *PolicyCache) Engine {
	return newModelRouteEngineWithAlertSink(router, cache, nil, time.Now)
}

func NewModelRouteEngineWithAlertSink(router *ModelRouter, cache *PolicyCache, alerts *AlertSink) Engine {
	return newModelRouteEngineWithAlertSink(router, cache, alerts, time.Now)
}

func newModelRouteEngine(routes modelRouteSource, policies v2PolicySource) *modelRouteEngine {
	return newModelRouteEngineWithClock(routes, policies, time.Now)
}

func newModelRouteEngineWithClock(routes modelRouteSource, policies v2PolicySource, clock func() time.Time) *modelRouteEngine {
	return newModelRouteEngineWithAlertSink(routes, policies, nil, clock)
}

func newModelRouteEngineWithAlertSink(routes modelRouteSource, policies v2PolicySource, alerts *AlertSink, clock func() time.Time) *modelRouteEngine {
	if clock == nil {
		clock = time.Now
	}
	engine := &modelRouteEngine{routes: routes, policies: policies, metrics: NewRouteMetricsStore(clock), health: NewRouteHealth(clock), preferences: NewPreferenceSwitch(clock), alerts: alerts, now: clock, switches: make(map[RoutePreferenceKey][]time.Time), shared: make(map[RouteKey]SharedRouteHealthSnapshot)}
	if store, ok := routes.(SharedRouteHealthStore); ok {
		engine.sharedStore = store
		engine.sharedQueue = make(chan SharedRouteHealthSnapshot, 1024)
		go engine.runSharedHealthLoop()
	}
	if store, ok := routes.(AttemptLedgerRecorder); ok {
		engine.ledgerStore = store
		engine.ledgerQueue = make(chan attemptLedgerOperation, 2048)
		go engine.runAttemptLedgerLoop()
	}
	return engine
}

func (e *modelRouteEngine) runAttemptLedgerLoop() {
	for operation := range e.ledgerQueue {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		if operation.finish {
			_ = e.ledgerStore.FinishRouteAttempt(ctx, operation.entry)
		} else {
			_ = e.ledgerStore.StartRouteAttempt(ctx, operation.entry)
		}
		cancel()
	}
}

func (e *modelRouteEngine) HasV2Policy(ctx context.Context, tenantID, modelRef string) (bool, error) {
	modelName, found, err := e.routes.ResolveLogicalModelName(ctx, tenantID, modelRef)
	if err != nil {
		return false, err
	}
	if !found {
		modelName = modelRef
	}
	policy, err := e.policies.GetV2Policy(ctx, tenantID, modelName)
	return policy != nil, err
}

func (e *modelRouteEngine) Plan(ctx context.Context, env RequestEnvelope) (RoutePlan, bool, error) {
	modelRef := env.Model
	if modelRef == "" {
		modelRef = env.ModelID
	}
	modelName, found, err := e.routes.ResolveLogicalModelName(ctx, env.TenantID, modelRef)
	if err != nil {
		return RoutePlan{}, false, err
	}
	if !found {
		modelName = modelRef
	}
	policy, err := e.policies.GetV2Policy(ctx, env.TenantID, modelName)
	if err != nil {
		return RoutePlan{}, false, err
	}
	if policy == nil {
		return RoutePlan{}, false, nil
	}
	var routeIdentities map[string]RouteIdentity
	var candidateExplanations []routeExplanation
	zeroDecision := func(reason string) RoutePlan {
		return RoutePlan{Decision: &RoutingDecision{ModelRouteV2: &ModelRouteDecisionV2{SchemaVersion: 2, RequestedModel: modelName, PolicySource: string(policy.Scope), PolicyVersion: policy.ConfigVersion, Strategy: string(policy.Config.Strategy), FallbackReason: reason, Candidates: auditRouteCandidates(candidateExplanations, routeIdentities)}}, RouteIdentities: routeIdentities}
	}
	if !found {
		// 模型名不在租户目录里（客户端写错名字），不是线路故障：只返回错误，
		// 不发「模型无可用线路」告警。入口层会先把它判成 404 model_not_found。
		return zeroDecision("no_enabled_route"), true, fmt.Errorf("no valid route for requested model")
	}
	routes, err := e.routes.listModelRoutesByName(ctx, env.TenantID, modelName)
	if err != nil {
		return zeroDecision("route_inventory_error"), true, err
	}
	if len(routes) == 0 {
		e.emit(RouteAlert{TenantID: env.TenantID, ModelName: modelName, ProviderRef: "all", Type: AlertRouteUnavailable, Reason: "请求模型没有具备有效凭证的上游线路"})
		return zeroDecision("no_credentialed_route"), true, fmt.Errorf("no valid route for requested model")
	}
	allRoutes := routes
	routeIdentities = buildAuditRouteIdentities(allRoutes)
	providerIDs := make([]string, 0, len(routes))
	healthy := make([]ModelRecord, 0, len(routes))
	probeDegraded := make([]ModelRecord, 0, len(routes))
	healthExplanations := make([]routeExplanation, 0, len(routes))
	preferenceKey := RoutePreferenceKey{TenantID: env.TenantID, ModelName: modelName}
	previousPreference := e.preferences.Current(preferenceKey)
	previousHealthy := false
	for _, route := range routes {
		key := RouteKey{TenantID: env.TenantID, ModelName: modelName, ProviderID: route.ProviderID}
		if snapshot, ok := e.sharedHealth(key); ok && snapshot.State == "unhealthy" {
			// 目录同步探测给出的异常只是建议：排到正常线路之后，不剔除。
			// 网关真实流量熔断共享出来的异常仍然剔除。
			if strings.HasPrefix(snapshot.SourceInstance, "catalog-sync") {
				if e.health.Available(key) {
					probeDegraded = append(probeDegraded, route)
					providerIDs = append(providerIDs, route.ProviderID)
				}
				continue
			}
			healthExplanations = append(healthExplanations, routeExplanation{ProviderID: route.ProviderID, Reason: "shared_health_unhealthy"})
			continue
		}
		if !e.health.Available(key) {
			reason := "health_gate"
			if e.health.Opened(key) {
				reason = "circuit_open"
			}
			healthExplanations = append(healthExplanations, routeExplanation{ProviderID: route.ProviderID, SampleState: sampleState(e.metrics.Snapshot(key)), Reason: reason})
			continue
		}
		healthy = append(healthy, route)
		providerIDs = append(providerIDs, route.ProviderID)
		if route.ProviderID == previousPreference {
			previousHealthy = true
		}
	}
	routes = append(healthy, probeDegraded...)
	if len(routes) == 0 {
		candidateExplanations = mergeRouteExplanations(allRoutes, healthExplanations)
		e.emit(RouteAlert{TenantID: env.TenantID, ModelName: modelName, ProviderRef: "all", Type: AlertRouteUnavailable, Reason: "请求模型的全部上游线路均不可用"})
		return zeroDecision("no_healthy_route"), true, fmt.Errorf("no healthy route for requested model")
	}
	if len(routes) == 1 {
		e.emit(RouteAlert{TenantID: env.TenantID, ModelName: modelName, ProviderRef: routes[0].ProviderID, Type: AlertRouteDegraded, Reason: "请求模型仅剩一条健康线路"})
		directExplanation := routeExplanation{ProviderID: routes[0].ProviderID, SampleState: sampleState(e.metrics.Snapshot(RouteKey{TenantID: env.TenantID, ModelName: modelName, ProviderID: routes[0].ProviderID})), Reason: "selected_primary"}
		candidateExplanations = mergeRouteExplanations(allRoutes, append(healthExplanations, directExplanation))
		identity := routeIdentities[routes[0].ProviderID]
		decision := &RoutingDecision{ProviderLayer: &ProviderDecision{ProviderID: routes[0].ProviderID, Strategy: "direct_single_healthy", Reason: map[string]any{"selection": "single_candidate", "model_name": modelName, "candidates": candidateExplanations, "max_attempts": 1}}, ModelRouteV2: &ModelRouteDecisionV2{SchemaVersion: 2, RequestedModel: modelName, PolicySource: string(policy.Scope), PolicyVersion: policy.ConfigVersion, Strategy: string(policy.Config.Strategy), Candidates: auditRouteCandidates(candidateExplanations, routeIdentities), PlannedRoute: identity}}
		return RoutePlan{Primary: routes[0], Decision: decision, RouteIdentities: routeIdentities}, true, nil
	}

	metrics := e.metrics.Snapshots(env.TenantID, modelName, providerIDs)
	selection, err := selectRoutesV2(routeSelectionInput{TenantID: env.TenantID, ModelName: modelName, RequestID: env.RequestID, SessionID: env.SessionID, Routes: routes, Config: policy.Config, Streaming: env.Streaming, Metrics: metrics}, policy.Scope)
	if err != nil {
		policyExplanations := append([]routeExplanation(nil), healthExplanations...)
		input := routeSelectionInput{ModelName: modelName, Config: policy.Config}
		for _, route := range routes {
			policyExplanations = append(policyExplanations, routeExplanation{ProviderID: route.ProviderID, SampleState: sampleState(metrics[route.ProviderID]), Reason: exclusionReason(input, route)})
		}
		candidateExplanations = mergeRouteExplanations(allRoutes, policyExplanations)
		e.emit(RouteAlert{TenantID: env.TenantID, ModelName: modelName, ProviderRef: "all", Type: AlertRouteUnavailable, Reason: "路由策略未包含任何当前健康线路"})
		return zeroDecision("policy_has_no_eligible_route"), true, err
	}
	if policy.Config.Strategy == modelrouting.StrategySmart && len(selection.Routes) > 0 {
		selection.Routes = e.stabilizePreference(preferenceKey, previousPreference, previousHealthy, selection, policy.Config)
	}
	selection.Routes = demoteRoutes(selection.Routes, probeDegraded)
	// Task 7 planning only peeks at half-open eligibility. The retry executor in
	// Task 8 must atomically claim a probe immediately before the actual call.
	filtered := selection.Routes[:1]
	for _, route := range selection.Routes[1:] {
		if e.health.Closed(RouteKey{TenantID: env.TenantID, ModelName: modelName, ProviderID: route.ProviderID}) {
			filtered = append(filtered, route)
		}
	}
	selection.Routes = filtered
	selection.Explanations = applyFinalSelectionReasons(selection.Explanations, selection.Routes)
	selection.Explanations = mergeRouteExplanations(allRoutes, append(healthExplanations, selection.Explanations...))
	selectionMode := selection.Mode
	if len(selection.Routes) == 1 {
		selectionMode = "single_candidate"
	}
	fallbackIDs := make([]string, 0, len(selection.Routes)-1)
	for _, route := range selection.Routes[1:] {
		fallbackIDs = append(fallbackIDs, route.ProviderID)
	}
	decision := &RoutingDecision{
		ProviderLayer: &ProviderDecision{
			ProviderID:    selection.Routes[0].ProviderID,
			Strategy:      string(policy.Config.Strategy),
			FallbackChain: fallbackIDs,
			Reason: map[string]any{
				"selection":    selectionMode,
				"model_name":   modelName,
				"candidates":   selection.Explanations,
				"max_attempts": len(selection.Routes),
			},
		},
		ModelRouteV2: &ModelRouteDecisionV2{
			SchemaVersion:  2,
			RequestedModel: modelName,
			PolicySource:   string(policy.Scope),
			PolicyVersion:  policy.ConfigVersion,
			Strategy:       string(policy.Config.Strategy),
			Candidates:     auditRouteCandidates(selection.Explanations, routeIdentities),
			PlannedRoute:   routeIdentities[selection.Routes[0].ProviderID],
		},
	}
	return RoutePlan{Primary: selection.Routes[0], Fallbacks: selection.Routes[1:], Decision: decision, RouteIdentities: routeIdentities}, true, nil
}

func buildAuditRouteIdentities(routes []ModelRecord) map[string]RouteIdentity {
	identities := make(map[string]RouteIdentity, len(routes))
	for index, route := range routes {
		name := strings.TrimSpace(route.ProviderName)
		if name == "" {
			name = "上游线路"
		}
		identities[route.ProviderID] = RouteIdentity{ProviderName: name, RouteRef: fmt.Sprintf("线路 %d", index+1)}
	}
	return identities
}

func mergeRouteExplanations(routes []ModelRecord, explanations []routeExplanation) []routeExplanation {
	byProvider := make(map[string]routeExplanation, len(explanations))
	for _, explanation := range explanations {
		byProvider[explanation.ProviderID] = explanation
	}
	out := make([]routeExplanation, 0, len(routes))
	for _, route := range routes {
		explanation, ok := byProvider[route.ProviderID]
		if !ok {
			explanation = routeExplanation{ProviderID: route.ProviderID, Reason: "not_eligible"}
		}
		out = append(out, explanation)
	}
	return out
}

func auditRouteCandidates(explanations []routeExplanation, identities map[string]RouteIdentity) []RouteCandidateDecision {
	out := make([]RouteCandidateDecision, 0, len(explanations))
	for _, explanation := range explanations {
		identity := identities[explanation.ProviderID]
		out = append(out, RouteCandidateDecision{ProviderName: identity.ProviderName, RouteRef: identity.RouteRef, SampleState: explanation.SampleState, NormalizedScores: explanation.Scores, DimensionState: explanation.DimensionState, ExclusionReason: explanation.Reason})
	}
	return out
}

func (e *modelRouteEngine) RecordAttempt(key RouteKey, result AttemptResult) {
	e.metrics.Record(key, result)
	wasOpen := e.health.Opened(key)
	e.health.Record(key, result)
	isOpen := e.health.Opened(key)
	if !wasOpen && isOpen {
		e.emit(RouteAlert{TenantID: key.TenantID, ModelName: key.ModelName, ProviderRef: key.ProviderID, Type: AlertCircuitOpened, Reason: "线路连续发生可重试的上游故障，系统已临时熔断"})
	} else if wasOpen && !isOpen && result.Success {
		e.emit(RouteAlert{TenantID: key.TenantID, ModelName: key.ModelName, ProviderRef: key.ProviderID, Type: AlertRouteRecovered, Reason: "线路探测成功，已恢复参与模型路由"})
	}
	e.publishSharedHealth(key, result, isOpen)
}

func (e *modelRouteEngine) publishSharedHealth(key RouteKey, result AttemptResult, open bool) {
	if e.sharedQueue == nil {
		return
	}
	now := e.now()
	state := "degraded"
	if result.Success {
		state = "healthy"
	} else if open {
		state = "unhealthy"
	}
	snapshot := SharedRouteHealthSnapshot{RouteKey: key, State: state, Version: now.UnixNano(), ObservedAt: now, ExpiresAt: now.Add(30 * time.Second), SourceInstance: "gateway"}
	e.sharedMu.Lock()
	e.shared[key] = snapshot
	e.sharedMu.Unlock()
	select {
	case e.sharedQueue <- snapshot:
	default:
	}
}

func (e *modelRouteEngine) sharedHealth(key RouteKey) (SharedRouteHealthSnapshot, bool) {
	e.sharedMu.RLock()
	snapshot, ok := e.shared[key]
	e.sharedMu.RUnlock()
	if !ok || !e.now().Before(snapshot.ExpiresAt) {
		return SharedRouteHealthSnapshot{}, false
	}
	return snapshot, true
}

func (e *modelRouteEngine) runSharedHealthLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	refresh := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		snapshots, err := e.sharedStore.ListSharedRouteHealth(ctx)
		if err != nil {
			return
		}
		next := make(map[RouteKey]SharedRouteHealthSnapshot, len(snapshots))
		now := e.now()
		for _, snapshot := range snapshots {
			if !snapshot.ObservedAt.After(now.Add(5*time.Minute)) && now.Before(snapshot.ExpiresAt) {
				next[snapshot.RouteKey] = snapshot
			}
		}
		e.sharedMu.Lock()
		e.shared = next
		e.sharedMu.Unlock()
	}
	refresh()
	for {
		select {
		case snapshot := <-e.sharedQueue:
			ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
			_ = e.sharedStore.WriteSharedRouteHealth(ctx, snapshot)
			cancel()
		case <-ticker.C:
			refresh()
		}
	}
}

func (e *modelRouteEngine) RecordFallback(ctx context.Context, key RouteKey) {
	if e == nil {
		return
	}
	e.emitContext(ctx, RouteAlert{TenantID: key.TenantID, ModelName: key.ModelName, ProviderRef: key.ProviderID, Type: AlertRouteFallback, Reason: "主线路调用失败，请求已由备用线路成功处理"})
}

func (e *modelRouteEngine) AllowAttempt(key RouteKey) bool {
	return e.health.Allow(key)
}

func (e *modelRouteEngine) ReleaseAttempt(key RouteKey) {
	e.health.Release(key)
}

func (e *modelRouteEngine) stabilizePreference(key RoutePreferenceKey, previous string, previousHealthy bool, selection routeSelection, config modelrouting.Config) []ModelRecord {
	ordered := selection.OrderedRoutes
	if len(ordered) == 0 {
		ordered = selection.Routes
	}
	top := ordered[0].ProviderID
	if strings.HasPrefix(selection.Mode, "priority_") {
		e.preferences.SetBaseline(key, top)
		return chooseAttempts(ordered, top)
	}
	if previous == "" {
		e.preferences.Choose(key, top, 0, "", 0, false)
		return chooseAttempts(ordered, top)
	}
	previousCandidate := false
	for _, route := range ordered {
		if route.ProviderID == previous {
			previousCandidate = true
			break
		}
	}
	if !previousHealthy || !previousCandidate {
		chosen := e.preferences.Choose(key, previous, 0, top, 0, true)
		if previous != "" && chosen != previous {
			e.recordPreferenceSwitch(key, chosen)
		}
		return chooseAttempts(ordered, top)
	}
	currentScore, candidateScore, comparable := preferenceScores(config, selection, previous, top)
	if !comparable {
		return chooseAttempts(ordered, previous)
	}
	chosen := e.preferences.ChooseVersioned(key, previous, currentScore, top, candidateScore, false, selection.EvaluationVersion)
	if previous != "" && chosen != previous {
		e.recordPreferenceSwitch(key, chosen)
	}
	return chooseAttempts(ordered, chosen)
}

func (e *modelRouteEngine) recordPreferenceSwitch(key RoutePreferenceKey, providerRef string) {
	now := e.now()
	cutoff := now.Add(-10 * time.Minute)
	e.switchMu.Lock()
	e.pruneSwitchesLocked(now)
	if _, exists := e.switches[key]; !exists && len(e.switches) >= maxHealthStateKeys {
		e.evictOldestSwitchLocked()
	}
	history := e.switches[key]
	kept := history[:0]
	for _, at := range history {
		if !at.Before(cutoff) {
			kept = append(kept, at)
		}
	}
	kept = append(kept, now)
	e.switches[key] = kept
	frequent := len(kept) >= 3
	e.switchMu.Unlock()
	if frequent {
		e.emit(RouteAlert{TenantID: key.TenantID, ModelName: key.ModelName, ProviderRef: providerRef, Type: AlertRouteFlapping, Reason: "模型首选线路在十分钟内已切换至少三次"})
	}
}

func (e *modelRouteEngine) pruneSwitchesLocked(now time.Time) {
	cutoff := now.Add(-healthStateTTL)
	for key, history := range e.switches {
		if len(history) == 0 || history[len(history)-1].Before(cutoff) {
			delete(e.switches, key)
		}
	}
}

func (e *modelRouteEngine) evictOldestSwitchLocked() {
	var oldestKey RoutePreferenceKey
	var oldest time.Time
	found := false
	for key, history := range e.switches {
		if len(history) == 0 {
			delete(e.switches, key)
			continue
		}
		last := history[len(history)-1]
		if !found || last.Before(oldest) {
			oldestKey, oldest, found = key, last, true
		}
	}
	if found {
		delete(e.switches, oldestKey)
	}
}

func (e *modelRouteEngine) emit(alert RouteAlert) {
	e.emitContext(context.Background(), alert)
}

func (e *modelRouteEngine) emitContext(ctx context.Context, alert RouteAlert) {
	if e == nil || e.alerts == nil {
		return
	}
	if alert.OccurredAt.IsZero() {
		alert.OccurredAt = e.now()
	}
	e.alerts.Emit(ctx, alert)
}

func chooseAttempts(ordered []ModelRecord, primary string) []ModelRecord {
	result := make([]ModelRecord, 0, maximumRouteAttempts)
	for _, route := range ordered {
		if route.ProviderID == primary {
			result = append(result, route)
			break
		}
	}
	for _, route := range ordered {
		if len(result) >= maximumRouteAttempts {
			break
		}
		if route.ProviderID != primary {
			result = append(result, route)
		}
	}
	return result
}

func preferenceScores(config modelrouting.Config, selection routeSelection, current, candidate string) (float64, float64, bool) {
	currentExplanation, currentOK := explanationFor(selection.Explanations, current)
	candidateExplanation, candidateOK := explanationFor(selection.Explanations, candidate)
	if !currentOK || !candidateOK {
		return 0, 0, false
	}
	dimensions := []modelrouting.Objective{config.Objective}
	if config.Objective == modelrouting.ObjectiveCustom {
		dimensions = config.CustomOrder
	}
	for _, dimension := range dimensions {
		name := string(dimension)
		if dimension == modelrouting.ObjectiveBalanced {
			name = "balanced"
		}
		if currentExplanation.DimensionState[name] != "used" || candidateExplanation.DimensionState[name] != "used" {
			continue
		}
		currentScore, currentHas := currentExplanation.Scores[name]
		candidateScore, candidateHas := candidateExplanation.Scores[name]
		if currentHas && candidateHas {
			if currentScore == candidateScore {
				continue
			}
			return currentScore, candidateScore, true
		}
	}
	return 0, 0, false
}

func explanationFor(explanations []routeExplanation, providerID string) (routeExplanation, bool) {
	for _, explanation := range explanations {
		if explanation.ProviderID == providerID {
			return explanation, true
		}
	}
	return routeExplanation{}, false
}

func applyFinalSelectionReasons(explanations []routeExplanation, routes []ModelRecord) []routeExplanation {
	positions := make(map[string]int, len(routes))
	for index, route := range routes {
		positions[route.ProviderID] = index
	}
	for index := range explanations {
		position, selected := positions[explanations[index].ProviderID]
		if selected {
			if position == 0 {
				explanations[index].Reason = "selected_primary"
			} else {
				explanations[index].Reason = fmt.Sprintf("selected_fallback_%d", position)
			}
		} else if explanations[index].Reason == "selected_primary" || strings.HasPrefix(explanations[index].Reason, "selected_fallback_") {
			explanations[index].Reason = "attempt_limit_exceeded"
		}
	}
	return explanations
}

// demoteRoutes 保持策略给出的相对顺序，把探测判为异常的线路整体移到最后。
func demoteRoutes(routes, demoted []ModelRecord) []ModelRecord {
	if len(demoted) == 0 {
		return routes
	}
	isDemoted := make(map[string]bool, len(demoted))
	for _, route := range demoted {
		isDemoted[route.ProviderID] = true
	}
	front := make([]ModelRecord, 0, len(routes))
	back := make([]ModelRecord, 0, len(demoted))
	for _, route := range routes {
		if isDemoted[route.ProviderID] {
			back = append(back, route)
		} else {
			front = append(front, route)
		}
	}
	return append(front, back...)
}
