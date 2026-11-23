package repository

import (
	"testing"
	"time"
)

func TestHardeningFExceptionRequiresConcreteRuleIDBeforeSave(t *testing.T) {
	for _, ruleID := range []string{"", " \t "} {
		t.Run(ruleID, func(t *testing.T) {
			exception := &AgentGuardException{TenantID: "tenant-test", ScopeType: "tenant", RuleID: ruleID, Reason: "approved restricted exception", Decision: AgentGuardActionAudit, ExpiresAt: time.Now().Add(time.Hour)}
			if err := ValidateAgentGuardException(exception); err == nil {
				t.Fatalf("empty rule id must be rejected before persistence: %+v", exception)
			}
		})
	}
}
