package handler

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// 集成项：拦截记录的归因带上防护项键（protection_item），控制台据此定位配置；risk_reason 可能是
// 更强的非防护项原因（例如 command_not_allowlisted）。
func TestBlockAttribution2922CarriesProtectionItem(t *testing.T) {
	decision := agentguard.Decision{
		RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock,
		EffectiveReason: "protection_item", PolicyReason: "protection_item", Reason: "command_not_allowlisted",
		ProtectionItem: "agent.ssh_private_key", ProtectionAction: "block",
	}
	operation := agentGuardBlockOperation(ToolCall{Function: ToolCallFunc{Name: "Bash"}}, decision)
	if operation.ProtectionItem != "agent.ssh_private_key" {
		t.Fatalf("operation=%+v", operation)
	}
	attribution := deriveBlockAttribution(withBlockOperation(context.Background(), operation), "evt-1", nil, "block", "blocked")
	encoded, _ := json.Marshal(attribution)
	if !strings.Contains(string(encoded), `"protection_item":"agent.ssh_private_key"`) {
		t.Fatalf("attribution=%s", encoded)
	}
	explicit := decision
	explicit.EffectiveReason, explicit.PolicyReason, explicit.ProtectionAction = "explicit_block", "explicit_block", "alert_allow"
	if got := agentGuardBlockOperation(ToolCall{Function: ToolCallFunc{Name: "Bash"}}, explicit).ProtectionItem; got != "" {
		t.Fatalf("a block decided by an explicit rule is not attributed to an alerting item: %q", got)
	}
}
