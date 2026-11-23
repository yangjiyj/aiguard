package handler

import (
	"sort"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

const (
	runtimeStatusUnavailable                = "unavailable"
	runtimeStatusPending                    = "pending"
	runtimeStatusPartiallyApplied           = "partially_applied"
	runtimeStatusApplied                    = "applied"
	runtimeStatusAppliedWithStaleNodes      = "applied_with_stale_nodes"
	runtimeStatusAppliedDegraded            = "applied_degraded"
	runtimeStatusCountUnavailable           = "runtime_count_unavailable"
	runtimeStatusCountInconsistent          = "runtime_count_inconsistent"
	runtimeCompileUnavailableCode           = "runtime_compile_unavailable"
	runtimeCompileDegradedCode              = "runtime_compile_degraded"
	runtimeExecutionDegradedCode            = "runtime_execution_degraded"
	runtimeWarningTenantIndustryUnavailable = "tenant_industry_unavailable"
	runtimeWarningExceptionsUnavailable     = "content_exceptions_unavailable"
	runtimeWarningActiveCountBelowCompiled  = "runtime_active_count_below_compiled"
	runtimeWarningStaleNodes                = "stale_runtime_nodes"
	runtimeWarningPackDegraded              = "runtime_pack_degraded"
)

type runtimeRuleSummary struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	RuleType string `json:"rule_type"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Action   string `json:"action"`
}

type runtimePendingRule struct {
	RuleID     string `json:"rule_id"`
	PolicyCode string `json:"policy_code,omitempty"`
	RuleName   string `json:"rule_name"`
	RuleType   string `json:"rule_type"`
	Action     string `json:"action,omitempty"`
	Reason     string `json:"reason"`
}

// ruleRuntimeStatus keeps desired control-plane state separate from runtime
// proof. ActiveRuntimeCount is nil until at least one fresh node reports that it
// actually holds DesiredVersion.
type ruleRuntimeStatus struct {
	DesiredVersion       string               `json:"desired_version"`
	CatalogCount         int                  `json:"catalog_count"`
	CompiledCount        int                  `json:"compiled_count"`
	CompiledMatcherCount int                  `json:"compiled_matcher_count"`
	CompiledPolicyCount  int                  `json:"compiled_policy_count"`
	CompiledRuleIDs      []string             `json:"compiled_rule_ids"`
	CompiledRules        []runtimeRuleSummary `json:"compiled_rules"`
	SkippedCount         int                  `json:"skipped_count"`
	PendingCount         int                  `json:"pending_count"`
	PendingRules         []runtimePendingRule `json:"pending_rules"`
	Reasons              map[string]int       `json:"reasons"`
	RuntimeVerified      bool                 `json:"runtime_verified"`
	ActiveRuntimeCount   *int                 `json:"active_runtime_count"`
	ActualSkippedCount   *int                 `json:"actual_skipped_count"`
	ActualPolicyCount    *int                 `json:"actual_policy_count"`
	FreshCount           int                  `json:"fresh_count"`
	FreshConvergedCount  int                  `json:"fresh_converged_count"`
	StaleCount           int                  `json:"stale_count"`
	AllConverged         bool                 `json:"all_converged"`
	Status               string               `json:"status"`
	LastError            string               `json:"last_error"`
	Warnings             []string             `json:"warnings,omitempty"`
	Degraded             bool                 `json:"degraded"`
	AttestationMode      string               `json:"attestation_mode"`
}

func unavailableRuleRuntimeStatus() ruleRuntimeStatus {
	return ruleRuntimeStatus{
		CompiledRuleIDs: []string{},
		CompiledRules:   []runtimeRuleSummary{},
		PendingRules:    []runtimePendingRule{},
		Reasons:         map[string]int{},
		Status:          runtimeStatusUnavailable,
		LastError:       runtimeCompileUnavailableCode,
		AttestationMode: rulePackAttestationModeTenantToken,
	}
}

func stableCompiledRuleIDs(pack *rules.RulePack) []string {
	ids := make([]string, len(pack.Rules))
	for index, rule := range pack.Rules {
		ids[index] = rule.RuleID
	}
	sort.Strings(ids)
	return ids
}

func stableRuntimeRuleDetails(pack *rules.RulePack) []runtimeRuleSummary {
	details := make([]runtimeRuleSummary, 0, len(pack.Rules))
	for _, rule := range pack.Rules {
		details = append(details, runtimeRuleSummary{RuleID: rule.RuleID, RuleName: rule.RuleName, RuleType: rule.RuleType, Category: rule.Category, Severity: rule.Severity, Action: rule.Action})
	}
	sort.Slice(details, func(i, j int) bool { return details[i].RuleID < details[j].RuleID })
	return details
}

func stablePendingRuleDetails(pack *rules.RulePack) []runtimePendingRule {
	details := make([]runtimePendingRule, 0, pack.Diagnostics.PendingCount)
	for _, rule := range pack.Skipped {
		if !rule.ConfiguredMatcher &&
			!(rule.Enabled && rule.PolicyCode != "" && rule.Reason == "unsupported_policy_action") {
			continue
		}
		details = append(details, runtimePendingRule{
			RuleID: rule.RuleID, PolicyCode: rule.PolicyCode, RuleName: rule.RuleName,
			RuleType: rule.RuleType, Action: rule.Action, Reason: rule.Reason,
		})
	}
	sort.Slice(details, func(i, j int) bool { return details[i].RuleID < details[j].RuleID })
	return details
}

func ruleRuntimeStatusFromPack(pack *rules.RulePack, conv rulePackConvergence) ruleRuntimeStatus {
	reasons := pack.Diagnostics.SkipReasons
	if reasons == nil {
		reasons = map[string]int{}
	}
	status := ruleRuntimeStatus{
		DesiredVersion:       pack.Version,
		CatalogCount:         pack.Diagnostics.CatalogCount,
		CompiledCount:        pack.Diagnostics.CompiledCount,
		CompiledMatcherCount: len(pack.Rules),
		CompiledPolicyCount:  len(pack.Policies),
		CompiledRuleIDs:      stableCompiledRuleIDs(pack),
		CompiledRules:        stableRuntimeRuleDetails(pack),
		SkippedCount:         pack.Diagnostics.SkippedCount,
		PendingCount:         pack.Diagnostics.PendingCount,
		PendingRules:         stablePendingRuleDetails(pack),
		Reasons:              reasons,
		FreshCount:           conv.FreshCount,
		FreshConvergedCount:  conv.FreshConvergedCount,
		StaleCount:           conv.StaleCount,
		AllConverged:         conv.AllConverged,
		Status:               runtimeStatusPending,
		Warnings:             append([]string(nil), pack.Warnings...),
		Degraded:             pack.Degraded,
		AttestationMode:      rulePackAttestationModeTenantToken,
	}
	if pack.Degraded {
		status.LastError = runtimeCompileDegradedCode
		status.Warnings = appendRuntimeWarning(status.Warnings, runtimeWarningPackDegraded)
	}
	if conv.StaleCount > 0 {
		status.Warnings = appendRuntimeWarning(status.Warnings, runtimeWarningStaleNodes)
	}
	if conv.FreshCount == 0 {
		return status
	}
	if conv.FreshConvergedCount != conv.FreshCount {
		if conv.FreshConvergedCount > 0 {
			status.Status = runtimeStatusPartiallyApplied
		}
		return status
	}
	if conv.RuntimeCountReported != conv.FreshCount || conv.PolicyCountReported != conv.FreshCount ||
		conv.ActualActiveCount == nil || conv.ActualSkippedCount == nil || conv.ActualPolicyCount == nil {
		status.Status = runtimeStatusCountUnavailable
		status.LastError = runtimeStatusCountUnavailable
		return status
	}
	activeCount := *conv.ActualActiveCount
	skippedCount := *conv.ActualSkippedCount
	policyRuntimeCount := *conv.ActualPolicyCount
	matcherCount := len(pack.Rules)
	policyCount := len(pack.Policies)
	if !conv.RuntimeCountsConsistent || activeCount < 0 || skippedCount < 0 || policyRuntimeCount < 0 ||
		activeCount > matcherCount || skippedCount > matcherCount || activeCount != matcherCount-skippedCount || policyRuntimeCount != policyCount {
		status.Status = runtimeStatusCountInconsistent
		status.LastError = runtimeStatusCountInconsistent
		return status
	}
	status.RuntimeVerified = true
	status.ActiveRuntimeCount = copyOptionalCount(conv.ActualActiveCount)
	status.ActualSkippedCount = copyOptionalCount(conv.ActualSkippedCount)
	status.ActualPolicyCount = copyOptionalCount(conv.ActualPolicyCount)
	if *conv.ActualActiveCount < matcherCount || *conv.ActualSkippedCount > 0 {
		status.Status = runtimeStatusAppliedDegraded
		status.Degraded = true
		status.LastError = runtimeExecutionDegradedCode
		status.Warnings = appendRuntimeWarning(status.Warnings, runtimeWarningActiveCountBelowCompiled)
	} else if pack.Degraded {
		status.Status = runtimeStatusAppliedDegraded
	} else if conv.StaleCount > 0 {
		status.Status = runtimeStatusAppliedWithStaleNodes
	} else {
		status.Status = runtimeStatusApplied
	}
	return status
}

func appendRuntimeWarning(values []string, warning string) []string {
	for _, value := range values {
		if value == warning {
			return values
		}
	}
	return append(values, warning)
}
