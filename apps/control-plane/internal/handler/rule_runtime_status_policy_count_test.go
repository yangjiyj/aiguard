package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/rules"
)

func runtimeCount(value int) *int { return &value }

func policyCountPack() *rules.RulePack {
	pack := &rules.RulePack{
		Rules:       make([]rules.CompiledRule, 5),
		Policies:    make([]rules.CompiledPolicy, 41),
		Diagnostics: rules.RuleDiagnostics{CompiledCount: 41},
	}
	return pack
}

func convergedPolicyCounts(policyCount int) rulePackConvergence {
	return rulePackConvergence{
		FreshCount:              1,
		FreshConvergedCount:     1,
		RuntimeCountReported:    1,
		PolicyCountReported:     1,
		ActualActiveCount:       runtimeCount(5),
		ActualSkippedCount:      runtimeCount(0),
		ActualPolicyCount:       runtimeCount(policyCount),
		RuntimeCountsConsistent: true,
		AllConverged:            true,
	}
}

func TestRuleRuntimeStatusVerifiesMatcherAndPolicyReceiptsSeparately(t *testing.T) {
	status := ruleRuntimeStatusFromPack(policyCountPack(), convergedPolicyCounts(41))
	if !status.RuntimeVerified || status.Status != runtimeStatusApplied {
		t.Fatalf("matching policy receipt was not verified: %+v", status)
	}
	if status.ActiveRuntimeCount == nil || *status.ActiveRuntimeCount != 5 {
		t.Fatalf("matcher count=%v want 5", status.ActiveRuntimeCount)
	}
	if status.ActualPolicyCount == nil || *status.ActualPolicyCount != 41 {
		t.Fatalf("policy count=%v want 41", status.ActualPolicyCount)
	}
}

func TestRuleRuntimeStatusRejectsMissingPolicyReceipt(t *testing.T) {
	convergence := convergedPolicyCounts(41)
	convergence.PolicyCountReported = 0
	convergence.ActualPolicyCount = nil

	status := ruleRuntimeStatusFromPack(policyCountPack(), convergence)
	if status.RuntimeVerified || status.Status != runtimeStatusCountUnavailable {
		t.Fatalf("missing policy receipt was accepted: %+v", status)
	}
}

func TestRuleRuntimeStatusRejectsWrongPolicyReceipt(t *testing.T) {
	status := ruleRuntimeStatusFromPack(policyCountPack(), convergedPolicyCounts(40))
	if status.RuntimeVerified || status.Status != runtimeStatusCountInconsistent {
		t.Fatalf("wrong policy receipt was accepted: %+v", status)
	}
}

func TestRuleRuntimeStatusUsesMatcherCountNotPolicyCompiledCount(t *testing.T) {
	status := ruleRuntimeStatusFromPack(policyCountPack(), convergedPolicyCounts(41))
	if status.Degraded || status.ActualSkippedCount == nil || *status.ActualSkippedCount != 0 {
		t.Fatalf("five healthy matchers for 41 policies were marked degraded: %+v", status)
	}
}
