package handler

import (
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpadmission"
)

// 审查 4：未准入且带已登记发现的工具，按发现对应的项和 mcp.unadmitted 各判一次，取更严。
func TestToolsListUnadmittedToolWithFindingJudgedByBothItems(t *testing.T) {
	set := func() *mcpApprovedToolSet {
		return &mcpApprovedToolSet{ServerApproved: true, Tools: map[string]mcpApprovedTool{
			"read_file": {Status: "approved", ApprovedSchemaHash: ws1GoldenReadFileHash},
			"poisoned":  {Status: "unverified", Reason: "description_poison", Source: mcpadmission.SourceSystem},
			"pending":   {Status: "unverified", Reason: "pending_administrator_review", Source: mcpadmission.SourceSystem},
		}}
	}
	poisoned := `{"name":"poisoned","description":"p","inputSchema":{"type":"object"}}`
	if _, reasons := judgeMCPListedTool(json.RawMessage(poisoned), set()); len(reasons) != 2 || reasons[0] != mcpToolsListDropNotApproved || reasons[1] != "description_poison" {
		t.Fatalf("unadmitted tool with a registered finding must carry both reasons, got %v", reasons)
	}
	// 发现与未准入属于同一项时不重复判。
	pending := `{"name":"pending","description":"p","inputSchema":{"type":"object"}}`
	if _, reasons := judgeMCPListedTool(json.RawMessage(pending), set()); len(reasons) != 1 || reasons[0] != mcpToolsListDropNotApproved {
		t.Fatalf("pending review is the unadmitted item itself, got %v", reasons)
	}
	for _, tc := range []struct {
		name        string
		protections string
		want        int
	}{
		{"默认两项都告警放行：留在列表", `{}`, 2},
		{"只有投毒设为阻断：剔除", `{"mcp.description_poison":{"action":"block"}}`, 1},
		{"只有未准入设为阻断：剔除", `{"mcp.unadmitted":{"action":"block"}}`, 1},
	} {
		env := ws1ToolsListEnv(t, false, ws1ToolsListResponse(ws1ReadFileTool, poisoned), "application/json", ws1StaticLoader(set()))
		env.mu.Lock()
		env.agentGuardData = `{"mode":"audit","protections":` + tc.protections + `}`
		env.mu.Unlock()
		if names := ws1ListedToolNames(t, env.post(t, ws1ToolsListRequest).Body.String()); len(names) != tc.want {
			t.Errorf("%s: got %v", tc.name, names)
		}
	}
}

// 系统隔离按隔离原因对应的项；原因没登记时照 2.9.21 剔除（不因为来源是系统就变宽）。
func TestToolsListSystemQuarantineFollowsReasonItem(t *testing.T) {
	for _, tc := range []struct {
		reason string
		want   string
	}{
		{"rug_pull_schema_changed", "rug_pull_schema_changed"},
		{"description_poison", "description_poison"},
		{"legacy_unregistered_reason", mcpToolsListDropAdministrator},
		{"", mcpToolsListDropAdministrator},
	} {
		set := &mcpApprovedToolSet{ServerApproved: true, Tools: map[string]mcpApprovedTool{
			"read_file": {Status: "quarantined", Reason: tc.reason, Source: mcpadmission.SourceSystem, ApprovedSchemaHash: ws1GoldenReadFileHash},
		}}
		if _, reasons := judgeMCPListedTool(json.RawMessage(ws1ReadFileTool), set); len(reasons) != 1 || reasons[0] != tc.want {
			t.Errorf("system quarantine %q: reasons=%v want %s", tc.reason, reasons, tc.want)
		}
	}
	// 服务级同理：系统隔离的服务按原因，管理员隔离的服务不论原因照剔除。
	for _, tc := range []struct {
		source string
		want   string
	}{
		{mcpadmission.SourceSystem, "rug_pull_manifest_changed"},
		{mcpadmission.SourceAdministrator, mcpToolsListDropAdministrator},
		{"", mcpToolsListDropAdministrator},
	} {
		set := &mcpApprovedToolSet{ServerStatus: "quarantined", ServerReason: "rug_pull_manifest_changed", ServerSource: tc.source, Tools: map[string]mcpApprovedTool{}}
		if _, reasons := judgeMCPListedTool(json.RawMessage(ws1ReadFileTool), set); len(reasons) != 1 || reasons[0] != tc.want {
			t.Errorf("server quarantine source %q: reasons=%v want %s", tc.source, reasons, tc.want)
		}
	}
}
