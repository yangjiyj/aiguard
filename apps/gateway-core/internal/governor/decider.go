package governor

import (
	"context"
	"log"
	"time"
)

// SnapshotProvider returns live usage snapshots for all scopes of a request.
type SnapshotProvider interface {
	GetMulti(ctx context.Context, ref ScopeRef) (map[string]Snapshot, error)
}

type scopedSnapshotProvider interface {
	GetScoped(ctx context.Context, ref ScopeRef, quotas []ScopedQuota) (map[string]Snapshot, error)
}

// QuotaProvider returns the effective quota and enforcement mode for a request.
type QuotaProvider interface {
	EffectiveQuota(ctx context.Context, ref ScopeRef) (EffectiveQuotaInput, error)
	GetEnforcementMode(ctx context.Context, ref ScopeRef) string
}

// ScopedQuotaProvider is the production quota contract. The legacy aggregate
// methods above remain during the compatibility window for injected callers.
type ScopedQuotaProvider interface {
	ScopedQuotas(ctx context.Context, ref ScopeRef) ([]ScopedQuota, error)
}

// Decider is the hot-path governor decision engine.
type Decider struct {
	snapshot  SnapshotProvider
	quota     QuotaProvider
	checker   ModelChecker // optional: nil = no whitelist check
	timeoutMs int
}

// failOpenOrClosed 在断流关闭时保持 fail-open；开启且 closeNow 为真时改为拒绝。
// closeNow 表示“已知或无法排除该用户配置了金额预算”。
func (d *Decider) failOpenOrClosed(reason string, closeNow bool) Decision {
	if closeNow {
		log.Printf("[governor.fail_closed] %s", reason)
		return Decision{
			Action: ActionRateLimit, TriggeredMetric: "runtime_fault", BudgetCutoff: true,
			Reason: "fail-closed: " + reason,
		}
	}
	return failOpen(reason)
}

func hasMoneyBudget(quotas []ScopedQuota) bool {
	for _, quota := range quotas {
		if quota.EnforcementMode != "enforce" || quota.Limits.OverageAction == "notify" {
			continue
		}
		limits := quota.Limits
		if limits.MonthlyBudgetMicros > 0 || limits.DailyBudgetMicros > 0 || limits.MonthlyBudgetBlocked || limits.DailyBudgetBlocked {
			return true
		}
	}
	return false
}

// New creates a Decider with a 50 ms default decision timeout.
func New(snap SnapshotProvider, quota QuotaProvider) *Decider {
	return &Decider{snapshot: snap, quota: quota, timeoutMs: 50}
}

// WithModelChecker sets an optional model whitelist checker.
func (d *Decider) WithModelChecker(c ModelChecker) *Decider {
	d.checker = c
	return d
}

// SetTimeoutMs overrides the per-request decision timeout.
func (d *Decider) SetTimeoutMs(ms int) { d.timeoutMs = ms }

// Decide evaluates the 5-level quota hierarchy and returns the governing action.
// On any internal error the function fail-opens (ActionNone) to preserve availability.
func (d *Decider) Decide(ctx context.Context, ref ScopeRef) Decision {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.timeoutMs)*time.Millisecond)
	defer cancel()

	if scoped, ok := d.quota.(ScopedQuotaProvider); ok {
		return d.decideScoped(ctx, ref, scoped)
	}

	mode := d.quota.GetEnforcementMode(ctx, ref)
	if mode == "bypass" {
		return Decision{Action: ActionNone}
	}

	quota, err := d.quota.EffectiveQuota(ctx, ref)
	if err != nil {
		return d.failOpenOrClosed("quota error: "+err.Error(), true)
	}

	snaps, err := d.snapshot.GetMulti(ctx, ref)
	if err != nil {
		return d.failOpenOrClosed("snapshot error: "+err.Error(), mode == "enforce" && quota.OverageAction != "notify" && (quota.MonthlyBudgetMicros > 0 || quota.DailyBudgetMicros > 0))
	}

	if ctx.Err() != nil {
		return d.failOpenOrClosed("timeout", mode == "enforce" && quota.OverageAction != "notify" && (quota.MonthlyBudgetMicros > 0 || quota.DailyBudgetMicros > 0))
	}

	merged := mergeUsage(snaps)
	decision := d.decide(mode, merged, quota)
	if decision.Action != ActionNone {
		return decision
	}

	// Model whitelist check: if team has no entry for this model, block (zero-trust).
	// Fall back (allow) if TeamID or ModelID is empty, or no checker configured.
	if !ref.UserModelAccessEnforced && d.checker != nil && ref.TeamID != "" && ref.ModelID != "" {
		allowed, _ := d.checker.IsModelAllowedForTeam(ctx, ref.TeamID, ref.ModelID)
		if !allowed {
			if mode == "soft" {
				return Decision{Action: ActionAlert, AlertOnly: true, Reason: "model not allowed for team"}
			}
			return Decision{Action: ActionRateLimit, Reason: "model not allowed for team"}
		}
	}

	return decision
}

// DecideNonRealtime leaves every quota dimension and legacy overage action to
// AtomicAdmission. It only preserves model-policy evaluation, so cost and token
// usage cannot be checked twice through different Redis representations.
func (d *Decider) DecideNonRealtime(ctx context.Context, ref ScopeRef) Decision {
	ctx, cancel := context.WithTimeout(ctx, time.Duration(d.timeoutMs)*time.Millisecond)
	defer cancel()

	if scoped, ok := d.quota.(ScopedQuotaProvider); ok {
		return d.decideScopedNonRealtime(ctx, ref, scoped)
	}
	mode := d.quota.GetEnforcementMode(ctx, ref)
	if mode == "bypass" {
		return Decision{Action: ActionNone}
	}
	quota, err := d.quota.EffectiveQuota(ctx, ref)
	if err != nil {
		return d.failOpenOrClosed("quota error: "+err.Error(), true)
	}
	snaps, err := d.snapshot.GetMulti(ctx, ref)
	if err != nil {
		return d.failOpenOrClosed("snapshot error: "+err.Error(), mode == "enforce" && quota.OverageAction != "notify" && (quota.MonthlyBudgetMicros > 0 || quota.DailyBudgetMicros > 0))
	}
	if ctx.Err() != nil {
		return d.failOpenOrClosed("timeout", mode == "enforce" && quota.OverageAction != "notify" && (quota.MonthlyBudgetMicros > 0 || quota.DailyBudgetMicros > 0))
	}
	decision := d.decideNonRealtime(mode, mergeUsage(snaps), quota)
	if decision.Action != ActionNone {
		return decision
	}
	return d.checkModelPolicy(ctx, ref, mode)
}

func (d *Decider) scopedSnapshots(ctx context.Context, ref ScopeRef, quotas []ScopedQuota) (map[string]Snapshot, error) {
	if provider, ok := d.snapshot.(scopedSnapshotProvider); ok {
		return provider.GetScoped(ctx, ref, quotas)
	}
	return d.snapshot.GetMulti(ctx, ref)
}

func (d *Decider) decideScoped(ctx context.Context, ref ScopeRef, provider ScopedQuotaProvider) Decision {
	quotas, err := provider.ScopedQuotas(ctx, ref)
	if err != nil {
		return d.failOpenOrClosed("quota error: "+err.Error(), true)
	}
	snaps, err := d.scopedSnapshots(ctx, ref, quotas)
	if err != nil {
		return d.failOpenOrClosed("snapshot error: "+err.Error(), hasMoneyBudget(quotas))
	}
	if ctx.Err() != nil {
		return d.failOpenOrClosed("timeout", hasMoneyBudget(quotas))
	}

	best := Decision{Action: ActionNone}
	modelMode := "soft"
	hasPolicyMode := false
	for _, scopedQuota := range quotas {
		mode := scopedQuota.EnforcementMode
		if mode == "" {
			mode = "soft"
		}
		if mode != "accounting" && (!hasPolicyMode || modeRank(mode) > modeRank(modelMode)) {
			modelMode = mode
			hasPolicyMode = true
		}
		if mode == "bypass" || scopedQuota.Scope == "" || scopedQuota.ID == "" {
			continue
		}
		limits := scopedQuota.Limits
		limits.TriggeredScope = scopedQuota.Scope
		usage := snaps[scopedQuota.Key()]
		candidate := d.decide(mode, usage, limits)
		candidate.ScopeID = scopedQuota.ID
		if decisionRank(candidate.Action) > decisionRank(best.Action) {
			best = candidate
		}
	}
	if best.Action != ActionNone {
		return best
	}

	return d.checkModelPolicy(ctx, ref, modelMode)
}

func (d *Decider) decideScopedNonRealtime(ctx context.Context, ref ScopeRef, provider ScopedQuotaProvider) Decision {
	quotas, err := provider.ScopedQuotas(ctx, ref)
	if err != nil {
		return d.failOpenOrClosed("quota error: "+err.Error(), true)
	}
	if ctx.Err() != nil {
		return d.failOpenOrClosed("timeout", hasMoneyBudget(quotas))
	}

	modelMode := "soft"
	hasPolicyMode := false
	for _, scopedQuota := range quotas {
		mode := scopedQuota.EnforcementMode
		if mode == "" {
			mode = "soft"
		}
		if mode != "accounting" && (!hasPolicyMode || modeRank(mode) > modeRank(modelMode)) {
			modelMode = mode
			hasPolicyMode = true
		}
	}
	return d.checkModelPolicy(ctx, ref, modelMode)
}

func decisionRank(action ActionType) int {
	switch action {
	case ActionRateLimit, ActionPauseKey, ActionDowngradeMod:
		return 2
	case ActionAlert:
		return 1
	default:
		return 0
	}
}

func modeRank(mode string) int {
	switch mode {
	case "enforce":
		return 2
	case "soft":
		return 1
	default:
		return 0
	}
}

func (d *Decider) checkModelPolicy(ctx context.Context, ref ScopeRef, mode string) Decision {
	if ref.UserModelAccessEnforced || mode == "bypass" || d.checker == nil || ref.TeamID == "" || ref.ModelID == "" {
		return Decision{Action: ActionNone}
	}
	allowed, _ := d.checker.IsModelAllowedForTeam(ctx, ref.TeamID, ref.ModelID)
	if allowed {
		return Decision{Action: ActionNone}
	}
	if mode == "soft" {
		return Decision{Action: ActionAlert, AlertOnly: true, Reason: "model not allowed for team"}
	}
	return Decision{Action: ActionRateLimit, Reason: "model not allowed for team"}
}

// decide applies the enforcement rules against the merged usage snapshot.
// Soft mode: monitoring-only — never blocks or alerts, all checks return ActionNone.
// Enforce mode: applies overage_action per dimension.
// Bypass mode: already handled in Decide() above.
func (d *Decider) decide(mode string, u Snapshot, q EffectiveQuotaInput) Decision {
	// RPM check
	if q.RPMLimit > 0 && u.Rpm >= q.RPMLimit {
		if mode == "soft" {
			return Decision{Action: ActionAlert, AlertOnly: true, TriggeredMetric: "rpm", TriggeredScope: q.TriggeredScope, Reason: "soft mode overage: rpm"}
		}
		return Decision{Action: ActionRateLimit, TriggeredMetric: "rpm", TriggeredScope: q.TriggeredScope}
	}

	// Concurrency check
	if q.ConcurrencyLimit > 0 && u.Concurrency >= q.ConcurrencyLimit {
		if mode == "soft" {
			return Decision{Action: ActionAlert, AlertOnly: true, TriggeredMetric: "concurrency", TriggeredScope: q.TriggeredScope, Reason: "soft mode overage: concurrency"}
		}
		return Decision{Action: ActionRateLimit, TriggeredMetric: "concurrency", TriggeredScope: q.TriggeredScope}
	}

	// Monthly budget — check overage first
	if q.MonthlyBudgetMicros > 0 && u.MonthCostMicros >= q.MonthlyBudgetMicros {
		return overageDecision(mode, q, "mo_cost")
	}

	// Monthly tokens
	if q.MonthlyTokenLimit > 0 && u.MonthTokens >= q.MonthlyTokenLimit {
		return overageDecision(mode, q, "mo_tokens")
	}

	// Daily budget
	if q.DailyBudgetMicros > 0 && u.DayCostMicros >= q.DailyBudgetMicros {
		return overageDecision(mode, q, "day_cost")
	}

	// Daily tokens
	if q.DailyTokenLimit > 0 && u.DayTokens >= q.DailyTokenLimit {
		return overageDecision(mode, q, "day_tokens")
	}

	// 80 % pre-alert on monthly budget
	if q.MonthlyBudgetMicros > 0 && budgetPreAlertReached(u.MonthCostMicros, q.MonthlyBudgetMicros) {
		return Decision{
			Action:          ActionAlert,
			AlertOnly:       true,
			TriggeredMetric: "mo_cost",
			TriggeredScope:  q.TriggeredScope,
		}
	}

	return Decision{Action: ActionNone}
}

func (d *Decider) decideNonRealtime(mode string, u Snapshot, q EffectiveQuotaInput) Decision {
	if q.MonthlyBudgetMicros > 0 && u.MonthCostMicros >= q.MonthlyBudgetMicros {
		return overageDecision(mode, q, "mo_cost")
	}
	if q.MonthlyTokenLimit > 0 && u.MonthTokens >= q.MonthlyTokenLimit && q.OverageAction != "rate_limit" {
		return overageDecision(mode, q, "mo_tokens")
	}
	if q.DailyBudgetMicros > 0 && u.DayCostMicros >= q.DailyBudgetMicros {
		return overageDecision(mode, q, "day_cost")
	}
	if q.DailyTokenLimit > 0 && u.DayTokens >= q.DailyTokenLimit && q.OverageAction != "rate_limit" {
		return overageDecision(mode, q, "day_tokens")
	}
	if q.MonthlyBudgetMicros > 0 && budgetPreAlertReached(u.MonthCostMicros, q.MonthlyBudgetMicros) {
		return Decision{Action: ActionAlert, AlertOnly: true, TriggeredMetric: "mo_cost", TriggeredScope: q.TriggeredScope}
	}
	return Decision{Action: ActionNone}
}

// overageDecision maps overage_action to an ActionType.
// Soft mode: emit alert (AlertOnly=true) so alert_inbox is written, but never blocks.
// Enforce mode: applies the configured overage_action.
func overageDecision(mode string, q EffectiveQuotaInput, metric string) Decision {
	if mode == "soft" {
		// Soft mode: observational alert — writes alert_inbox but never blocks the request
		return Decision{
			Action:          ActionAlert,
			AlertOnly:       true,
			TriggeredMetric: metric,
			TriggeredScope:  q.TriggeredScope,
			Reason:          "soft mode overage: " + metric,
		}
	}
	action := ActionAlert
	switch q.OverageAction {
	case "rate_limit":
		action = ActionRateLimit
	case "pause_key":
		action = ActionPauseKey
	case "downgrade_model":
		if q.DowngradeTo != "" {
			action = ActionDowngradeMod
		} else {
			action = ActionAlert
		}
	}
	return Decision{
		Action:          action,
		TriggeredScope:  q.TriggeredScope,
		TriggeredMetric: metric,
		DowngradeTo:     q.DowngradeTo,
	}
}

// mergeUsage selects the maximum usage value across all scope snapshots.
// This is the conservative "highest-water-mark" strategy: any scope that
// is over quota will trigger enforcement.
func mergeUsage(snaps map[string]Snapshot) Snapshot {
	var out Snapshot
	for _, u := range snaps {
		if u.MonthTokens > out.MonthTokens {
			out.MonthTokens = u.MonthTokens
		}
		if u.MonthCostMicros > out.MonthCostMicros {
			out.MonthCostMicros = u.MonthCostMicros
		}
		if u.DayTokens > out.DayTokens {
			out.DayTokens = u.DayTokens
		}
		if u.DayCostMicros > out.DayCostMicros {
			out.DayCostMicros = u.DayCostMicros
		}
		if u.Rpm > out.Rpm {
			out.Rpm = u.Rpm
		}
		if u.Concurrency > out.Concurrency {
			out.Concurrency = u.Concurrency
		}
	}
	return out
}

// budgetPreAlertReached reports used >= 80% of limit using integer micros only.
// used*5 >= limit*4 is exact; operands are bounded by MaxQuotaBudgetMicros (2^53),
// so the products cannot overflow int64.
func budgetPreAlertReached(used, limit int64) bool {
	if limit <= 0 {
		return false
	}
	return used*5 >= limit*4
}
