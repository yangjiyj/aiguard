package handler

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// W5 5.7 (D4): "仅记录" is record-and-forward (audit), never an explicit allow.
func TestWS5PolicyCenterRecordMapsToAuditNotAllow(t *testing.T) {
	cases := map[string]string{
		policyCenterAgentBehaviorRecord:     repository.AgentGuardActionAudit,
		policyCenterAgentBehaviorAlertAllow: repository.AgentGuardActionAudit,
		policyCenterAgentBehaviorBlock:      repository.AgentGuardActionBlock,
	}
	for console, want := range cases {
		if got := policyCenterAgentGuardAction(console); got != want {
			t.Errorf("policyCenterAgentGuardAction(%q)=%q want %q", console, got, want)
		}
	}
}

// The console choice reads back as saved even though record and alert_allow
// share the enforced action.
func TestWS5PolicyCenterRuleActionReadsBackConsoleChoice(t *testing.T) {
	definition, _ := policyCenterAgentBehaviorDefinitionByKey(policyCenterAgentBehaviorSystem)
	for _, choice := range []string{policyCenterAgentBehaviorRecord, policyCenterAgentBehaviorAlertAllow, policyCenterAgentBehaviorBlock} {
		policy := &repository.AgentGuardPolicy{RulesJSON: map[string]any{"rules": []any{map[string]any{
			"id": "policy-center-" + definition.Key, "tool_pattern": definition.ToolPattern,
			"action": policyCenterAgentGuardAction(choice), policyCenterRuleActionKey: choice, "enabled": true,
		}}}}
		if got := policyCenterAgentGuardRuleAction(policy, definition); got != choice {
			t.Errorf("read back %q, want %q", got, choice)
		}
	}
}

// Merged policy IDs must match migration 900's SQL expression.
func TestWS5PolicyCenterMergedIDMatchesMigration(t *testing.T) {
	// sha256("ws5mig15317") prefix observed from migration 900 on a real DB.
	if got := policyCenterAgentGuardPolicyIDFor("ws5mig15317"); got != "policy-center-ag-9ef72f75fe037b94" {
		t.Fatalf("merged id %q diverges from migration 900", got)
	}
}
