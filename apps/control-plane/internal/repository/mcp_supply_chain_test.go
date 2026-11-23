package repository

import (
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 2.9.22：投毒、同名不一致、Schema 变化默认只打标记、不自动隔离（mcp.* 防护项默认告警放行）；
// 管理员手动隔离、撤销照旧保留；已批准且 Schema 没变的工具不因批准时已有的投毒标记被打回。
func TestDecideMCPToolAdmissionFirstSyncAndThreats(t *testing.T) {
	cases := []struct {
		name      string
		previous  *mcpToolAdmissionRecord
		incoming  *MCPTool
		divergent bool
		status    string
		reason    string
	}{
		{name: "clean first sync", incoming: &MCPTool{SchemaHash: "safe"}, status: "unverified", reason: "pending_administrator_review"},
		// 原期望 quarantined：改为只打标记（mcp.description_poison 默认告警放行）。
		{name: "description poison is flagged not quarantined", incoming: &MCPTool{SchemaHash: "evil", PoisonFlags: []string{"mcp_description_poison"}}, status: "unverified", reason: "description_poison"},
		// 原期望 quarantined：改为只打标记（mcp.shadow_divergence 默认告警放行）。
		{name: "divergent shadow is flagged not quarantined", incoming: &MCPTool{SchemaHash: "new"}, divergent: true, status: "unverified", reason: "shadow_schema_diverges"},
		{name: "identical shadow awaits approval", incoming: &MCPTool{SchemaHash: "same"}, divergent: false, status: "unverified", reason: "pending_administrator_review"},
		// 原期望 quarantined：Schema 变化改由网关按 mcp.drift 处置（解析出 schema_binding_mismatch）。
		{name: "approved schema drift stays approved", previous: &mcpToolAdmissionRecord{Status: "approved", SchemaHash: "v1"}, incoming: &MCPTool{SchemaHash: "v2"}, status: "approved"},
		{name: "approved poison already approved stays approved", previous: &mcpToolAdmissionRecord{Status: "approved", SchemaHash: "v1", ApprovedPoisonFlags: []string{"mcp_description_poison"}}, incoming: &MCPTool{SchemaHash: "v1", PoisonFlags: []string{"mcp_description_poison"}}, status: "approved"},
		{name: "revoked cannot be cleared by sync", previous: &mcpToolAdmissionRecord{Status: "revoked", SchemaHash: "v1"}, incoming: &MCPTool{SchemaHash: "v1"}, status: "revoked"},
		{name: "quarantine cannot be cleared by clean sync", previous: &mcpToolAdmissionRecord{Status: "quarantined", SchemaHash: "v1", QuarantineReason: "manual_quarantine"}, incoming: &MCPTool{SchemaHash: "v1"}, status: "quarantined", reason: "manual_quarantine"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideMCPToolAdmission(tc.previous, tc.incoming, tc.divergent, nil)
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Fatalf("decision=%+v want status=%s reason=%s", got, tc.status, tc.reason)
			}
		})
	}
}

// 管理员把对应防护项设为阻断时，同步照旧自动隔离（2.9.21 行为）。
func TestDecideMCPToolAdmissionQuarantinesWhenItemSetToBlock(t *testing.T) {
	block := func(keys ...string) protection.Settings {
		s := protection.Settings{}
		for _, key := range keys {
			s[key] = protection.Setting{Action: protection.ActionBlock}
		}
		return s
	}
	cases := []struct {
		name      string
		previous  *mcpToolAdmissionRecord
		incoming  *MCPTool
		divergent bool
		settings  protection.Settings
		status    string
		reason    string
	}{
		{name: "poison", incoming: &MCPTool{SchemaHash: "evil", PoisonFlags: []string{"x"}}, settings: block(protection.KeyMCPDescriptionPoison), status: "quarantined", reason: "description_poison"},
		{name: "new poison on approved", previous: &mcpToolAdmissionRecord{Status: "approved", SchemaHash: "v1"}, incoming: &MCPTool{SchemaHash: "v1", PoisonFlags: []string{"x"}}, settings: block(protection.KeyMCPDescriptionPoison), status: "quarantined", reason: "description_poison"},
		{name: "approved poison unchanged", previous: &mcpToolAdmissionRecord{Status: "approved", SchemaHash: "v1", ApprovedPoisonFlags: []string{"x"}}, incoming: &MCPTool{SchemaHash: "v1", PoisonFlags: []string{"x"}}, settings: block(protection.KeyMCPDescriptionPoison), status: "approved"},
		{name: "shadow", incoming: &MCPTool{SchemaHash: "new"}, divergent: true, settings: block(protection.KeyMCPShadowDivergence), status: "quarantined", reason: "shadow_schema_diverges"},
		{name: "drift", previous: &mcpToolAdmissionRecord{Status: "approved", SchemaHash: "v1"}, incoming: &MCPTool{SchemaHash: "v2"}, settings: block(protection.KeyMCPDrift), status: "quarantined", reason: "rug_pull_schema_changed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := decideMCPToolAdmission(tc.previous, tc.incoming, tc.divergent, tc.settings)
			if got.Status != tc.status || got.Reason != tc.reason {
				t.Fatalf("decision=%+v want status=%s reason=%s", got, tc.status, tc.reason)
			}
		})
	}
}

func TestResolveMCPSupplyChainIsStructuralAndPrecedenceAware(t *testing.T) {
	approved := resolveMCPSupplyChainState("approved", "", 2, "approved", "", 3, false, true, "tool-1")
	if approved.StructuralBlock || approved.Status != "approved" || len(approved.Reasons) != 0 {
		t.Fatalf("approved resolution=%+v", approved)
	}
	removed := resolveMCPSupplyChainState("approved", "", 2, "approved", "", 3, true, true, "tool-1")
	if !removed.StructuralBlock || removed.Status != "removed" || len(removed.Reasons) != 1 || removed.Reasons[0] != "mcp_tool_removed" {
		t.Fatalf("removed resolution=%+v", removed)
	}
	quarantined := resolveMCPSupplyChainState("quarantined", "rug_pull_manifest_changed", 4, "approved", "", 3, false, true, "tool-1")
	if !quarantined.StructuralBlock || quarantined.Status != "quarantined" ||
		len(quarantined.Reasons) != 2 || quarantined.Reasons[0] != "mcp_server_quarantined" ||
		quarantined.Reasons[1] != "rug_pull_manifest_changed" {
		t.Fatalf("quarantined resolution=%+v", quarantined)
	}
	unknown := resolveMCPSupplyChainState("approved", "", 2, "", "", 0, false, false, "")
	if !unknown.StructuralBlock || unknown.Status != "unknown" || unknown.Reasons[0] != "mcp_tool_unknown" {
		t.Fatalf("unknown resolution=%+v", unknown)
	}
}

func TestMCPAdmissionStatusValidation(t *testing.T) {
	for _, status := range []string{"approved", "quarantined", "revoked"} {
		if !validMCPAdmissionMutation(status) {
			t.Fatalf("%s should be valid", status)
		}
	}
	for _, status := range []string{"", "unverified", "allow", "removed"} {
		if validMCPAdmissionMutation(status) {
			t.Fatalf("%s should be invalid", status)
		}

	}
}

// 扫描不可用：新工具只打标记（mcp.scan_unavailable 默认告警放行），设为阻断时照旧隔离；
// 已批准且没变的工具不受影响。
func TestMCPDescriptionScanUnavailableFlagsNewTools(t *testing.T) {
	pending := mcpAdmissionDecision{Status: "unverified", Reason: "pending_administrator_review"}
	got := applyMCPDescriptionScanGate(nil, pending, false, nil)
	if got.Status != "unverified" || got.Reason != "description_scan_unavailable" {
		t.Fatalf("unscanned new tool = %+v", got)
	}
	blocked := applyMCPDescriptionScanGate(nil, pending, false, protection.Settings{protection.KeyMCPScanUnavailable: {Action: protection.ActionBlock}})
	if blocked.Status != "quarantined" || blocked.Reason != "description_scan_unavailable" {
		t.Fatalf("scan_unavailable=block: %+v", blocked)
	}
	poisoned := applyMCPDescriptionScanGate(nil, mcpAdmissionDecision{Status: "unverified", Reason: "description_poison"}, false, nil)
	if poisoned.Reason != "description_poison" {
		t.Fatalf("a stronger finding must not be overwritten: %+v", poisoned)
	}
	previouslyApproved := applyMCPDescriptionScanGate(
		&mcpToolAdmissionRecord{Status: "approved", SchemaHash: "same"},
		mcpAdmissionDecision{Status: "approved"}, false, nil,
	)
	if previouslyApproved.Status != "approved" {
		t.Fatalf("unchanged approved snapshot was spuriously cleared: %+v", previouslyApproved)
	}
}

// 未准入工具的发现原因（投毒、同名不一致、扫描不可用）随解析结果下发给网关。
func TestResolveMCPSupplyChainCarriesFindingReasonsForUnverifiedTools(t *testing.T) {
	got := resolveMCPSupplyChainState("approved", "", 1, "unverified", "shadow_schema_diverges", 2, false, true, "tool-1")
	if !got.StructuralBlock || len(got.Reasons) != 2 || got.Reasons[0] != "mcp_tool_unverified" || got.Reasons[1] != "shadow_schema_diverges" {
		t.Fatalf("resolution=%+v", got)
	}
	pending := resolveMCPSupplyChainState("approved", "", 1, "unverified", "pending_administrator_review", 2, false, true, "tool-1")
	if len(pending.Reasons) != 1 {
		t.Fatalf("pending review must not add a second reason: %+v", pending)
	}
}

func TestMCPSupplyChainRevisionBindsTerminalState(t *testing.T) {
	approved := mcpBoundSupplyChainRevision("base", "r", "r", "s", "s", "approved", "")
	removed := mcpBoundSupplyChainRevision("base", "r", "r", "s", "s", "removed", "mcp_tool_removed")
	if approved == removed {
		t.Fatal("removed state reused approved supply-chain revision")
	}
}
