package handler

import (
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

const redlineMetadataArgs = `{"url":"http://169.254.169.254/latest/meta-data/"}`

func approvedMCPPolicy() *MCPEffectivePolicy {
	return &MCPEffectivePolicy{Matched: true, PolicyID: "allow", Mode: "strict", Action: "allow", SupplyChainStatus: "approved"}
}

func redlineEventNeeded(d agentguard.Decision) bool {
	return mcpDecisionNeedsSecurityEvent(&mcpToolCallDecision{Qualified: "files__fetch", Decision: d}, false)
}

func TestMCPRedlineFourLevels(t *testing.T) {
	off := synthesizeMCPDecisionForTenant(approvedMCPPolicy(), "fetch", redlineMetadataArgs, agentguard.ModeStrict, true, map[string]string{"cloud_metadata": "off"}, tenantWith(nil))
	if redlineEventNeeded(off) || off.EffectiveDecision == agentguard.DecisionBlock {
		t.Fatalf("off must not match: %+v", off)
	}
	for _, ev := range off.Evidence {
		if ev.RuleID == "mcp_redline_cloud_metadata" {
			t.Fatalf("off must leave no redline evidence: %+v", off.Evidence)
		}
	}
	record := synthesizeMCPDecisionForTenant(approvedMCPPolicy(), "fetch", redlineMetadataArgs, agentguard.ModeStrict, true, map[string]string{"cloud_metadata": "record"}, tenantWith(nil))
	recorded := false
	for _, ev := range record.Evidence {
		if ev.RuleID == "mcp_redline_cloud_metadata" {
			recorded = true
		}
	}
	if !recorded || redlineEventNeeded(record) || record.EffectiveDecision == agentguard.DecisionBlock {
		t.Fatalf("record must keep evidence without alert: evidence=%v alert=%v", record.Evidence, redlineEventNeeded(record))
	}
	alert := synthesizeMCPDecisionForTenant(approvedMCPPolicy(), "fetch", redlineMetadataArgs, agentguard.ModeStrict, true, nil, tenantWith(nil))
	if !redlineEventNeeded(alert) || alert.EffectiveDecision == agentguard.DecisionBlock {
		t.Fatalf("default alert must alert without blocking: %+v", alert)
	}
	block := synthesizeMCPDecisionForTenant(approvedMCPPolicy(), "fetch", redlineMetadataArgs, agentguard.ModeStrict, true, map[string]string{"cloud_metadata": "block"}, tenantWith(nil))
	if block.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("block must block: %+v", block)
	}
}

func TestMCPRedlineBlockReleasedByScopedException(t *testing.T) {
	actions := map[string]string{"cloud_metadata": "block"}
	for _, tc := range []struct {
		ruleID, pattern string
		released        bool
	}{
		{"cloud_metadata", "", true},
		{"mcp_redline_cloud_metadata", "mcp:files/fetch", true},
		{"cloud_metadata", "mcp:files", true},
		{"cloud_metadata", "mcp:other", false},
		{"private_key_egress", "", false},
	} {
		exception := agentguard.PolicyException{ID: "exc", RuleID: tc.ruleID, TargetPattern: tc.pattern, Decision: agentguard.DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}
		d := synthesizeMCPDecisionForTenant(approvedMCPPolicy(), "fetch", redlineMetadataArgs, agentguard.ModeStrict, true, actions, tenantWith(nil, exception))
		if got := d.EffectiveDecision != agentguard.DecisionBlock; got != tc.released {
			t.Errorf("exception %s/%s released=%v want %v", tc.ruleID, tc.pattern, got, tc.released)
		}
	}
	expired := agentguard.PolicyException{ID: "exc", RuleID: "cloud_metadata", Decision: agentguard.DecisionAllow, ExpiresAt: time.Now().Add(-time.Hour)}
	if d := synthesizeMCPDecisionForTenant(approvedMCPPolicy(), "fetch", redlineMetadataArgs, agentguard.ModeStrict, true, actions, tenantWith(nil, expired)); d.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatal("expired exception must not release the redline")
	}
}

func TestNormalizeMCPRedlineActionsAcceptsFourLevels(t *testing.T) {
	got := normalizeMCPRedlineActions(map[string]string{"cloud_metadata": "OFF", "reverse_shell": "record", "destructive_command": "alert", "private_key_egress": "block", "remote_script_pipe": "drop"})
	if got["cloud_metadata"] != "off" || got["reverse_shell"] != "record" || got["destructive_command"] != "alert" || got["private_key_egress"] != "block" {
		t.Fatalf("normalized = %v", got)
	}
	if _, ok := got["remote_script_pipe"]; ok {
		t.Fatal("unknown action must be dropped (treated as alert)")
	}
}

// 红线例外对“告警”档也生效：命中例外时不发告警，只记录。
func TestMCPRedlineExceptionSilencesAlertLevel(t *testing.T) {
	exception := agentguard.PolicyException{ID: "exc", RuleID: "cloud_metadata", TargetPattern: "mcp:files/fetch", Decision: agentguard.DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}
	d := synthesizeMCPDecisionForTenant(approvedMCPPolicy(), "fetch", redlineMetadataArgs, agentguard.ModeStrict, true, nil, tenantWith(nil, exception))
	if redlineEventNeeded(d) {
		t.Fatalf("an exception must silence the alert-level redline: %+v", d.Evidence)
	}
	recorded := false
	for _, ev := range d.Evidence {
		if ev.RuleID == "mcp_redline_cloud_metadata" {
			recorded = true
		}
	}
	if !recorded {
		t.Fatal("the redline hit must still be recorded")
	}
	other := agentguard.PolicyException{ID: "exc", RuleID: "cloud_metadata", TargetPattern: "mcp:other", Decision: agentguard.DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}
	if d := synthesizeMCPDecisionForTenant(approvedMCPPolicy(), "fetch", redlineMetadataArgs, agentguard.ModeStrict, true, nil, tenantWith(nil, other)); !redlineEventNeeded(d) {
		t.Fatal("an exception for another server must not silence the alert")
	}
}
