package handler

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpadmission"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func structuralPolicy(status string, reasons ...string) *MCPEffectivePolicy {
	// 不写死 strict：租户没有匹配的 MCP 策略时就是 audit。
	return &MCPEffectivePolicy{
		Matched: false, Mode: "audit", Action: "audit",
		SupplyChainStatus: status, SupplyChainReasons: reasons, SupplyChainRevision: "mcpsc_x", StructuralBlock: true,
	}
}

func tenantWith(settings protection.Settings, exceptions ...agentguard.PolicyException) mcpTenantContext {
	return mcpTenantContext{ServerName: "files", Protections: settings, Exceptions: exceptions}
}

func blockItem(key string) protection.Settings {
	return protection.Settings{key: {Action: protection.ActionBlock}}
}

// systemQuarantined 标出系统自动隔离（admission_reviewed_by='system'）。审查 1 起管理员处置按来源
// 判断、不再看原因文字：下面两组用例原来只靠原因码区分系统隔离，现在要显式带上来源才按防护项处置。
func systemQuarantined(policy *MCPEffectivePolicy) *MCPEffectivePolicy {
	policy.ServerAdmissionSource, policy.ToolAdmissionSource = mcpadmission.SourceSystem, mcpadmission.SourceSystem
	return policy
}

func TestMCPSupplyChainFindingsDefaultToAlertAllow(t *testing.T) {
	for _, tc := range []struct {
		name    string
		policy  *MCPEffectivePolicy
		itemKey string
	}{
		{"unverified", structuralPolicy("unverified", "mcp_server_unverified", "mcp_tool_unverified"), protection.KeyMCPUnadmitted},
		{"unknown", structuralPolicy("unknown", "mcp_tool_unknown"), protection.KeyMCPUnadmitted},
		{"route drift", structuralPolicy("quarantined", "route_binding_mismatch"), protection.KeyMCPDrift},
		{"legacy system quarantine", systemQuarantined(structuralPolicy("quarantined", "mcp_tool_quarantined", "rug_pull_schema_changed")), protection.KeyMCPDrift},
		{"poison", systemQuarantined(structuralPolicy("quarantined", "mcp_tool_quarantined", "description_poison")), protection.KeyMCPDescriptionPoison},
		{"shadow", structuralPolicy("unverified", "mcp_tool_unverified", "shadow_schema_diverges"), protection.KeyMCPUnadmitted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := synthesizeMCPDecisionForTenant(tc.policy, "read", "{}", agentguard.ModeStrict, true, nil, tenantWith(nil))
			if d.EffectiveDecision == agentguard.DecisionBlock || d.EffectiveDecision == agentguard.DecisionConfirm {
				t.Fatalf("default must not block: %+v", d)
			}
			if d.ProtectionItem != tc.itemKey || d.ProtectionAction != string(protection.ActionAlertAllow) || !d.NotificationRequired {
				t.Fatalf("item=%s action=%s notify=%v, want %s alert", d.ProtectionItem, d.ProtectionAction, d.NotificationRequired, tc.itemKey)
			}
		})
	}
}

func TestMCPSupplyChainFindingBlocksWhenItemSetToBlock(t *testing.T) {
	for _, tc := range []struct {
		policy  *MCPEffectivePolicy
		itemKey string
	}{
		{structuralPolicy("unverified", "mcp_server_unverified", "mcp_tool_unverified"), protection.KeyMCPUnadmitted},
		{structuralPolicy("quarantined", "schema_binding_mismatch"), protection.KeyMCPDrift},
		{systemQuarantined(structuralPolicy("quarantined", "mcp_tool_quarantined", "description_poison")), protection.KeyMCPDescriptionPoison},
		{structuralPolicy("unverified", "mcp_tool_unverified", "shadow_schema_diverges"), protection.KeyMCPShadowDivergence},
		{structuralPolicy("unverified", "mcp_tool_unverified", "description_scan_unavailable"), protection.KeyMCPScanUnavailable},
	} {
		d := synthesizeMCPDecisionForTenant(tc.policy, "read", "{}", agentguard.ModeStrict, true, nil, tenantWith(blockItem(tc.itemKey)))
		if d.EffectiveDecision != agentguard.DecisionBlock || d.ProtectionItem != tc.itemKey {
			t.Fatalf("%s=block: %+v", tc.itemKey, d)
		}
	}
}

func TestMCPAdministratorQuarantineAndRevokeStillBlock(t *testing.T) {
	for _, policy := range []*MCPEffectivePolicy{
		structuralPolicy("quarantined", "mcp_tool_quarantined", "manual_quarantine"),
		structuralPolicy("quarantined", "mcp_server_quarantined", "停用：供应商下线"),
		structuralPolicy("revoked", "mcp_tool_revoked", "mcp_tool_unverified"),
	} {
		d := synthesizeMCPDecisionForTenant(policy, "read", "{}", agentguard.ModeStrict, true, nil, tenantWith(nil))
		if d.EffectiveDecision != agentguard.DecisionBlock || !d.ConfiguredEnforcement {
			t.Fatalf("administrator admission %v must block: %+v", policy.SupplyChainReasons, d)
		}
	}
}

func TestMCPProtectionExceptionScopedToServerAndTool(t *testing.T) {
	policy := structuralPolicy("quarantined", "route_binding_mismatch")
	exception := func(pattern string) agentguard.PolicyException {
		return agentguard.PolicyException{ID: "exc_1", RuleID: protection.KeyMCPDrift, TargetPattern: pattern, Decision: agentguard.DecisionAllow, ExpiresAt: time.Now().Add(time.Hour)}
	}
	for pattern, released := range map[string]bool{
		"mcp:files/read": true, "mcp:files": true, "mcp:files/write": false, "mcp:file": false, "mcp:other/read": false,
	} {
		d := synthesizeMCPDecisionForTenant(policy, "read", "{}", agentguard.ModeStrict, true, nil, tenantWith(blockItem(protection.KeyMCPDrift), exception(pattern)))
		if got := d.EffectiveDecision != agentguard.DecisionBlock; got != released {
			t.Errorf("exception %q released=%v want %v (%+v)", pattern, got, released, d)
		}
	}
}

func TestMCPProtectionAlertWritesSecurityEventOutsideRecordMode(t *testing.T) {
	d := synthesizeMCPDecisionForTenant(structuralPolicy("unverified", "mcp_tool_unverified"), "read", "{}", agentguard.ModeStrict, true, nil, tenantWith(nil))
	decision := &mcpToolCallDecision{Qualified: "files__read", Decision: d}
	if !mcpDecisionNeedsSecurityEvent(decision, false) {
		t.Fatal("an alert_allow MCP protection item must raise a security event")
	}
	if mcpDecisionNeedsSecurityEvent(decision, true) {
		t.Fatal("record mode must not raise an alert for alert_allow items")
	}
	args := mcpSecurityEventArgs(mcpProxyAuditRecord{RequestID: "r", TenantID: "t"}, decision, false)
	if args[4] != "mcp_protection_alert" || args[7] != "alert" {
		t.Fatalf("event type/action = %v/%v", args[4], args[7])
	}
}

// 行为矩阵 8.2：故障类 mcp.* 项（确认单建不出来、批准后重放时环境变化或策略拉不到）与其他防护项一样
// 可加例外（控制台每行都有“加例外”）；设为阻断时结论归因到该项。
func TestMCPFallbackItemsHonorExceptionsAndAttributeBlocks(t *testing.T) {
	confirm := agentguard.Decision{RawDecision: agentguard.DecisionConfirm, EffectiveDecision: agentguard.DecisionConfirm}
	for _, tc := range []struct{ reason, key string }{
		{"mcp_confirmation_unavailable", protection.KeyMCPConfirmUnavailable},
		{"approval_context_drift", protection.KeyMCPReplayChanged},
		{"policy_runtime_unavailable", protection.KeyMCPReplayChanged},
	} {
		blocked, enforce := mcpProtectionFallback(confirm, tc.reason, tenantWith(blockItem(tc.key)), "read", false)
		if !enforce || blocked.ProtectionItem != tc.key || blocked.ProtectionAction != string(protection.ActionBlock) {
			t.Fatalf("%s=block must enforce and name the item: enforce=%v %+v", tc.key, enforce, blocked)
		}
		for _, ruleID := range []string{tc.key, tc.reason} {
			for pattern, released := range map[string]bool{"": true, "mcp:files/read": true, "mcp:files": true, "mcp:files/write": false, "mcp:other": false} {
				exception := agentguard.PolicyException{ID: "exc_fault", RuleID: ruleID, TargetPattern: pattern, Decision: agentguard.DecisionAudit, ExpiresAt: time.Now().Add(time.Hour)}
				got, enforce := mcpProtectionFallback(confirm, tc.reason, tenantWith(blockItem(tc.key), exception), "read", false)
				if enforce == released {
					t.Errorf("%s exception rule=%s target=%q released=%v want %v (%+v)", tc.reason, ruleID, pattern, !enforce, released, got)
					continue
				}
				if released && (got.ProtectionAction != string(protection.ActionRecord) || got.NotificationRequired || len(got.ProtectionExceptionIDs()) != 1) {
					t.Errorf("%s released by an exception must only record: %+v", tc.reason, got)
				}
			}
		}
	}
}

// 行为矩阵 8.2：MCP 拦截落库的安全事件要写下决定处置的防护项（含故障类项配成阻断由它本身拦下）。
func TestMCPSecurityEventNamesDecidingProtectionItem(t *testing.T) {
	summaryOf := func(d agentguard.Decision) map[string]any {
		t.Helper()
		args := mcpSecurityEventArgs(mcpProxyAuditRecord{RequestID: "r", TenantID: "t"}, &mcpToolCallDecision{Qualified: "files__read", Decision: d}, false)
		var summary map[string]any
		if err := json.Unmarshal(args[8].([]byte), &summary); err != nil {
			t.Fatal(err)
		}
		return summary
	}
	structural := synthesizeMCPDecisionForTenant(systemQuarantined(structuralPolicy("quarantined", "mcp_tool_quarantined", "schema_hash_mismatch")), "read", "{}", agentguard.ModeStrict, true, nil, tenantWith(blockItem(protection.KeyMCPDrift)))
	if structural.EffectiveDecision != agentguard.DecisionBlock || summaryOf(structural)["protection_item"] != protection.KeyMCPDrift {
		t.Fatalf("structural block must name mcp.drift: %+v %v", structural, summaryOf(structural))
	}
	confirm := agentguard.Decision{RawDecision: agentguard.DecisionConfirm, EffectiveDecision: agentguard.DecisionConfirm, EffectiveReason: "explicit_confirm"}
	fault, enforce := mcpProtectionFallback(confirm, "mcp_confirmation_unavailable", tenantWith(blockItem(protection.KeyMCPConfirmUnavailable)), "read", false)
	if !enforce || summaryOf(fault)["protection_item"] != protection.KeyMCPConfirmUnavailable {
		t.Fatalf("a fault item configured to block must be named: %v", summaryOf(fault))
	}
	if _, named := summaryOf(confirm)["protection_item"]; named {
		t.Fatalf("an explicit confirm rule is not a protection item: %v", summaryOf(confirm))
	}
}

// 行为矩阵 8.2：mcp.* 项设为仅记录（或被例外放开）时只记录、不告警。
func TestMCPRecordedItemsDoNotRaiseSecurityEvents(t *testing.T) {
	confirm := agentguard.Decision{RawDecision: agentguard.DecisionConfirm, EffectiveDecision: agentguard.DecisionConfirm}
	for action, wantEvent := range map[protection.Action]bool{protection.ActionRecord: false, protection.ActionAlertAllow: true} {
		released, enforce := mcpProtectionFallback(confirm, "mcp_confirmation_unavailable",
			tenantWith(protection.Settings{protection.KeyMCPConfirmUnavailable: {Action: action}}), "read", false)
		decision := &mcpToolCallDecision{Qualified: "files__read", Decision: released, ExecutionForwarded: true}
		if enforce || mcpDecisionNeedsSecurityEvent(decision, false) != wantEvent {
			t.Errorf("confirm_unavailable=%s forwarded: event=%v want %v (%+v)", action, !wantEvent, wantEvent, released)
		}
	}
}

func TestWS1ToolsListRecordedFindingsOnlyLeaveEvidence(t *testing.T) {
	long := strings.Replace(ws1ReadFileTool, `"Read a file <b>&</b>"`, `"`+strings.Repeat("x", 9000)+`"`, 1)
	for _, tc := range []struct {
		name, agentGuard string
		wantAlert        bool
	}{
		{"default alerts", `{"mode":"audit"}`, true},
		{"record only records", `{"mode":"audit","protections":{"mcp.oversize":{"action":"record"},"mcp.drift":{"action":"record"}}}`, false},
		{"exception only records", `{"mode":"audit","protections":{"mcp.drift":{"action":"record"}},"exceptions":[{"id":"exc_size","rule_id":"mcp.oversize","target_pattern":"mcp:demo/read_file","decision":"audit","expires_at":"2099-01-01T00:00:00Z"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := ws1ToolsListEnv(t, false, ws1ToolsListResponse(long), "application/json", ws1StaticLoader(ws1ApprovedSet()))
			env.agentGuardData = tc.agentGuard
			db := newFakeAuditDB()
			env.handler.auditRecorder = &mcpProxyAuditRecorder{db: db}
			if body := env.post(t, ws1ToolsListRequest).Body.String(); !strings.Contains(body, `"read_file"`) {
				t.Fatalf("a non-blocking finding must keep the tool: %s", body)
			}
			alerted := false
			for _, args := range db.tx.execedArgs {
				if len(args) == 11 && args[4] == "mcp_tools_list_drift" {
					alerted = true
				}
			}
			if alerted != tc.wantAlert {
				t.Fatalf("tools/list drift event=%v want %v", alerted, tc.wantAlert)
			}
			logs := env.logs()
			if len(logs) == 0 || !strings.Contains(fmt.Sprint(logs[len(logs)-1]["evidence_json"]), "mcp_tools_list_exceeds_admission_bounds") {
				t.Fatalf("the finding must still be recorded in the tool log: %v", logs)
			}
		})
	}
}
