package repository

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func TestContentBlockLinksToThePolicyCenterEntry(t *testing.T) {
	record := SecurityBlockRecord{Layer: "input_content", RuleName: "证书/私钥检测"}
	summary := map[string]any{"block": map[string]any{"rule_id": "rule_631f3819", "layer": "input_content"}}
	link := blockPolicyLink(&record, summary, "", true)
	if link.Kind != "policy" || link.Path != "/security/policies?policy=rule_631f3819" || link.Label != "证书/私钥检测" {
		t.Fatalf("link=%+v", link)
	}
}

func TestContentBlockWithoutPolicyRowIsMarkedDeleted(t *testing.T) {
	record := SecurityBlockRecord{Layer: "input_content", RuleName: "历史规则"}
	summary := map[string]any{"block": map[string]any{"rule_id": "rule_deleted"}}
	link := blockPolicyLink(&record, summary, "", false)
	if link.Kind != "deleted" || link.Path != "" || link.Label != "历史规则" {
		t.Fatalf("deleted rule must be marked deleted without a link: %+v", link)
	}
}

func TestNonRulesTableIDsAreNotMarkedDeleted(t *testing.T) {
	for _, ruleID := range []string{"catalog_code_xss_generation", "semantic_semantic_jailbreak", ""} {
		record := SecurityBlockRecord{Layer: "input_content", RuleName: "内置检测"}
		summary := map[string]any{"block": map[string]any{"rule_id": ruleID}}
		if link := blockPolicyLink(&record, summary, "", false); link.Kind != "none" || link.Path != "" {
			t.Fatalf("%q: only rules-table ids may be reported deleted: %+v", ruleID, link)
		}
	}
}

// 防护项只用于智能体工具层：其他层即使带着能对应防护项的原因码，也走通用的规则归因（已删除的规则仍显示已删除）。
func TestNonAgentToolLayerNeverUsesProtectionItems(t *testing.T) {
	record := SecurityBlockRecord{Layer: "input_content", RuleName: "内置检测"}
	summary := map[string]any{"block": map[string]any{"rule_id": "rule_gone", "cause": "protection_item", "risk_reason": "blocked_ssh_private_key_path"}}
	if link := blockPolicyLink(&record, summary, "", false); link.Kind != "deleted" || link.Label != "内置检测" {
		t.Fatalf("link=%+v", link)
	}
}

func TestBlockFinalRuleIDFollowsTheProjectionOrder(t *testing.T) {
	summary := map[string]any{
		"rule_id":  "rule_summary",
		"findings": []any{map[string]any{"type": "tool_attempt_blocked", "action": "block", "rule_id": "rule_finding"}},
	}
	if got := blockFinalRuleID(summary, "rule_event"); got != "rule_finding" {
		t.Fatalf("got %q", got)
	}
	if got := blockFinalRuleID(map[string]any{}, " rule_event "); got != "rule_event" {
		t.Fatalf("got %q", got)
	}
	if got := blockFinalRuleID(map[string]any{"block": map[string]any{"rule_id": "rule_block"}, "rule_id": "rule_summary"}, "rule_event"); got != "rule_block" {
		t.Fatalf("got %q", got)
	}
}

func TestManagedBehaviorBlockLinksToTheBehavior(t *testing.T) {
	summary := agentToolBlockSummary("policy-center-system_command", "", "explicit_block", "Bash · ls", "Bash · ls")
	record := projectAgentToolBlock("block", summary)
	link := blockPolicyLink(&record, summary, "", false)
	if link.Kind != "agent_behavior" || link.Path != "/security/agents?behavior=system_command" || link.Label != "系统命令" {
		t.Fatalf("link=%+v", link)
	}
}

func analyzerBlock(reason, detail string) (SecurityBlockRecord, map[string]any) {
	summary := agentToolBlockSummary("", "", "analyzer_high_risk_block", detail, detail)
	block := summary["block"].(map[string]any)
	block["cause"] = "analyzer_high_risk_block"
	block["risk_reason"] = reason
	return projectAgentToolBlock("block", summary), summary
}

func TestAnalyzerHighRiskBlockLinksToTheHighRiskItemWithAPrefilledException(t *testing.T) {
	// 例外按调用目标（地址、路径、命令）匹配，不是工具名。
	record, summary := analyzerBlock("tainted_irreversible_network_egress", "Bash · curl https://example.com/api")
	link := blockPolicyLink(&record, summary, "", false)
	want := "/security/agents?protection=agent.high_risk_without_rule&" + url.Values{
		"rule": {"tainted_irreversible_network_egress"}, "target": {"curl https://example.com/api"},
	}.Encode()
	if link.Kind != "protection_item" || link.ItemKey != "agent.high_risk_without_rule" || link.Path != want || link.Label != "未配置规则的高风险调用" {
		t.Fatalf("link=%+v want path %s", link, want)
	}
	if record.RuleName != "未配置规则的高风险调用" {
		t.Fatalf("rule name=%q", record.RuleName)
	}
}

func TestAnalyzerExceptionLinkHasNoTargetWhenNoneIsRecorded(t *testing.T) {
	for _, detail := range []string{"mcp__devhub__get_merge_request", "Bash · ", "Bash ·"} {
		record, summary := analyzerBlock("tainted_irreversible_network_egress", detail)
		link := blockPolicyLink(&record, summary, "", false)
		if link.Kind != "protection_item" || link.ItemKey != "agent.high_risk_without_rule" || strings.Contains(link.Path, "target=") {
			t.Fatalf("detail %q: link=%+v", detail, link)
		}
	}
}

// 2.9.22：不再有“产品内置安全底线”。注册表里每个原因码都对应一个防护项，
// 阻断记录必须链接到该防护项的配置位置，并且可加例外。
func protectionItemBlock(reason, detail string) (SecurityBlockRecord, map[string]any) {
	summary := agentToolBlockSummary("", "", "protection_item", detail, detail)
	summary["block"].(map[string]any)["risk_reason"] = reason
	return projectAgentToolBlock("block", summary), summary
}

// analyzer 阻断里的 Skill 准入类原因：注册表里没有的（管理员隔离、撤销）指向 Skill 准入，依据和链接一致。
// 已登记为防护项的（危险命令、身份异常——批次 1 起 skill_identity_* 登记在 skill.identity_invalid 下）
// 不再走 Skill 准入：analyzer 阶段记录按阶段项“未配置规则的高风险调用”归类（与危险命令同口径，
// 是这条记录真正的决定方）；2.9.22 网关按防护项写的记录（cause=protection_item）链接到
// skill.identity_invalid，见 TestEveryGatewayProtectionReasonLinksToItsItem。
func TestUnregisteredSkillAdmissionReasonPointsAtSkillAdmissionInBasisAndLink(t *testing.T) {
	for _, reason := range []string{"skill_version_revoked", "skill_version_quarantined"} {
		record, summary := analyzerBlock(reason, "Skill · x")
		link := blockPolicyLink(&record, summary, "", false)
		if link.Kind != "skill" || link.Path != "/security/skills" || record.RuleName != "Skill 准入" || record.Basis != "Skill 准入" {
			t.Fatalf("%s: link=%+v name=%q basis=%q", reason, link, record.RuleName, record.Basis)
		}
	}
	for _, reason := range []string{"skill_dangerous_command", "skill_identity_conflict", "skill_identity_invalid", "skill_identity_misplaced"} {
		record, summary := analyzerBlock(reason, "Skill · x")
		link := blockPolicyLink(&record, summary, "", false)
		if link.Kind != "protection_item" || link.ItemKey != "agent.high_risk_without_rule" || strings.Contains(record.Basis, "Skill 准入") {
			t.Fatalf("%s: registered skill reason follows the analyzer-stage protection item: link=%+v basis=%q", reason, link, record.Basis)
		}
	}
	record, summary := protectionItemBlock("skill_identity_conflict", "Skill · x")
	link := blockPolicyLink(&record, summary, "", false)
	if link.Kind != "protection_item" || link.ItemKey != "skill.identity_invalid" || !strings.HasPrefix(link.Path, "/security/skills?protection=skill.identity_invalid") {
		t.Fatalf("protection-item record links to skill.identity_invalid: link=%+v", link)
	}
}

// 每个分组的页面路径与依据前缀（页面路由以 web-console 路由定义为准）。
var wantGroupPage = map[protection.Group]struct{ path, basisPrefix string }{
	protection.GroupAgentTarget:     {"/security/agents", "策略中心 → 智能体行为 → "},
	protection.GroupAgentFallback:   {"/security/agents", "策略中心 → 智能体行为 → "},
	protection.GroupAgentRestricted: {"/security/agents", "策略中心 → 智能体行为 → 敏感资源访问 → "},
	protection.GroupSkill:           {"/security/skills", "Skill 安全准入 → "},
	protection.GroupMCP:             {"/mcp-gateway/policies", "MCP 调用策略 → "},
	protection.GroupEndpoint:        {"/security/agents", "策略中心 → 智能体行为 → 端侧内置规则 → "},
}

// 注册表里实际出现的每个分组都必须登记页面；未登记的分组不能静默借用别的页面。
func TestEveryRegistryGroupHasAPageMapping(t *testing.T) {
	for _, item := range protection.All() {
		if _, ok := pageForGroup(item.Group); !ok {
			t.Fatalf("%s: group %s is not in protectionGroupPages", item.Key, item.Group)
		}
	}
	if _, ok := pageForGroup(protection.Group("no_such_group")); ok {
		t.Fatal("an unknown group must not resolve to a page")
	}
	// 批次 2B：端侧内置规则放在智能体行为页（原断言“端点分组还没有页面”）。
	if page, ok := pageForGroup(protection.GroupEndpoint); !ok || page.path != "/security/agents" {
		t.Fatalf("endpoint group page=%+v ok=%v", page, ok)
	}
}

func TestEveryGatewayProtectionReasonLinksToItsItem(t *testing.T) {
	covered := 0
	for _, item := range protection.All() {
		page, ok := wantGroupPage[item.Group]
		if !ok {
			t.Fatalf("%s: group %s has no page mapping in the test", item.Key, item.Group)
		}
		for _, reason := range item.Reasons {
			covered++
			record, summary := protectionItemBlock(reason, "Bash · x")
			link := blockPolicyLink(&record, summary, "", false)
			want := page.path + "?protection=" + url.QueryEscape(item.Key)
			if link.Kind != "protection_item" || link.Path != want || link.ItemKey != item.Key || link.Label != item.Label {
				t.Fatalf("%s (%s): link=%+v want path %s", reason, item.Key, link, want)
			}
			if record.RuleName != item.Label || record.Basis != page.basisPrefix+item.Label+" 动作为阻断" {
				t.Fatalf("%s: record name=%q basis=%q", reason, record.RuleName, record.Basis)
			}
			// 任何非规则类 cause（旧记录的 cause 也一样）只要原因码能对应防护项，就按该防护项给链接和依据；
			// 旧 exception_eligible=false 不影响。改 cause 后重新解释，依据与链接必须仍然一致。
			summary["block"].(map[string]any)["cause"] = "some_older_cause"
			summary["block"].(map[string]any)["exception_eligible"] = false
			record = projectAgentToolBlock("block", summary)
			link = blockPolicyLink(&record, summary, "", false)
			if link.Kind != "protection_item" || link.ItemKey != item.Key || link.Path != want {
				t.Fatalf("%s: other causes must still resolve by reason: %+v", reason, link)
			}
			if record.RuleName != item.Label || record.Basis != page.basisPrefix+item.Label+" 动作为阻断" {
				t.Fatalf("%s: re-explained record name=%q basis=%q", reason, record.RuleName, record.Basis)
			}
		}
	}
	if covered == 0 {
		t.Fatal("registry has no reasons")
	}
}

// 确认动作下，防护项的原因写明需人工确认。
func TestProtectionItemConfirmActionSaysSoInTheReason(t *testing.T) {
	summary := agentToolBlockSummary("", "", "protection_item", "Read · ~/.ssh/id_rsa", "Read · ~/.ssh/id_rsa")
	summary["block"].(map[string]any)["risk_reason"] = "blocked_ssh_private_key_path"
	record := projectAgentToolBlock("confirm", summary)
	if record.Reason != "智能体工具调用触及「SSH 私钥」，需人工确认" || record.Basis != "策略中心 → 智能体行为 → SSH 私钥 动作为人工确认" {
		t.Fatalf("reason=%q basis=%q", record.Reason, record.Basis)
	}
}

func TestStageItemsLinkToTheirProtectionItem(t *testing.T) {
	record, summary := analyzerBlock("", "Bash · x")
	if link := blockPolicyLink(&record, summary, "", false); link.Kind != "protection_item" || link.Path != "/security/agents?protection=agent.high_risk_without_rule" {
		t.Fatalf("high risk without rule: %+v", link)
	}
	summary = agentToolBlockSummary("", "", "confirm_without_channel_fail_closed", "Bash · x", "Bash · x")
	summary["block"].(map[string]any)["cause"] = "confirm_without_channel_fail_closed"
	record = projectAgentToolBlock("block", summary)
	link := blockPolicyLink(&record, summary, "", false)
	if link.Kind != "protection_item" || link.ItemKey != "agent.confirm_without_channel" || link.Path != "/security/agents?protection=agent.confirm_without_channel" {
		t.Fatalf("confirm without channel: %+v", link)
	}
	if record.Basis != "策略中心 → 智能体行为 → 需要确认但无法确认 动作为阻断" {
		t.Fatalf("basis=%q", record.Basis)
	}
}

func TestLegacySensitiveLocalFileReasonLinksToTheTargetGroup(t *testing.T) {
	record, summary := protectionItemBlock("blocked_sensitive_local_file_path", "Read · /etc/x")
	link := blockPolicyLink(&record, summary, "", false)
	if link.Kind != "protection_group" || link.Group != "agent_target" || link.ItemKey != "" || link.Label != "敏感目标" || link.Path != "/security/agents?protection_group=agent_target" {
		t.Fatalf("link=%+v", link)
	}
	if record.RuleName != "敏感目标" || record.Basis != "策略中心 → 智能体行为 → 敏感目标 动作为阻断" {
		t.Fatalf("rule name=%q basis=%q", record.RuleName, record.Basis)
	}
}

// 依据和链接必须说同一处：由显式规则决定的阻断，旧原因码不能把链接带到“敏感目标”。
func TestLegacySensitiveReasonDoesNotOverrideAnExplicitRuleBlock(t *testing.T) {
	for _, cause := range []string{"explicit_block", "explicit_confirm", "global_default"} {
		summary := agentToolBlockSummary("policy-center-system_command", "", cause, "Bash · ls", "Bash · ls")
		block := summary["block"].(map[string]any)
		block["cause"] = cause
		block["risk_reason"] = "blocked_sensitive_local_file_path"
		record := projectAgentToolBlock("block", summary)
		link := blockPolicyLink(&record, summary, "", false)
		if link.Kind != "agent_behavior" || link.Path != "/security/agents?behavior=system_command" {
			t.Fatalf("%s: link=%+v", cause, link)
		}
		if record.RuleName == "敏感目标" || strings.Contains(record.Basis, "敏感目标") {
			t.Fatalf("%s: record name=%q basis=%q", cause, record.RuleName, record.Basis)
		}
	}
}

func TestProtectionItemCauseWithoutAKnownItemSaysSo(t *testing.T) {
	record, summary := protectionItemBlock("", "Bash · x")
	link := blockPolicyLink(&record, summary, "", false)
	if record.Basis != "防护项动作为阻断" {
		t.Fatalf("basis=%q", record.Basis)
	}
	if link.Kind != "none" || link.Label != record.RuleName {
		t.Fatalf("link=%+v rule name=%q", link, record.RuleName)
	}
}

// 2.9.15 修过的问题不能回归：旧版本写入的底线类处置原因（cause，或 2.9.15 前只有 finding.evidence_reason）
// 没有 risk_reason 时，不能归到托管行为卡片（如“系统命令”），只给中性口径、不链接行为卡片。
func TestOldFloorCauseWithoutReasonIsNeutralAndNotAttributedToABehavior(t *testing.T) {
	for _, withBlockCause := range []bool{true, false} {
		summary := agentToolBlockSummary("policy-center-system_command", "", "independent_safety_floor", "Bash · git credential fill", "Bash · git credential fill")
		if withBlockCause {
			summary["block"].(map[string]any)["cause"] = "independent_safety_floor"
		}
		record := projectAgentToolBlock("block", summary)
		link := blockPolicyLink(&record, summary, "", false)
		if link.Kind != "none" || link.Label != "智能体行为策略" || link.Path != "" {
			t.Fatalf("block.cause=%v: link=%+v", withBlockCause, link)
		}
		if record.RuleName != "智能体行为策略" || record.Basis != "智能体行为策略" || strings.Contains(record.RuleName+record.Basis, "系统命令") {
			t.Fatalf("block.cause=%v: name=%q basis=%q", withBlockCause, record.RuleName, record.Basis)
		}
	}
}

func TestRestrictedFileAndDestructiveBlocksLinkToTheirBehavior(t *testing.T) {
	cases := map[string]string{
		"restricted_file":       "/security/agents?behavior=sensitive_resource",
		"destructive_operation": "/security/agents?behavior=destructive_operation",
		"mcp_tool":              "/mcp-gateway/policies",
	}
	for layer, want := range cases {
		record := SecurityBlockRecord{Layer: layer}
		if link := blockPolicyLink(&record, map[string]any{}, "", false); link.Path != want {
			t.Fatalf("%s link=%+v want %s", layer, link, want)
		}
	}
}

func TestCustomAgentRuleHasNoLinkBecauseTheConsoleCannotEditIt(t *testing.T) {
	record := SecurityBlockRecord{Layer: "agent_tool", RuleName: "禁止 curl 外联"}
	summary := map[string]any{"block": map[string]any{"rule_id": "rule_adv1"}}
	link := blockPolicyLink(&record, summary, "", false)
	if link.Kind != "none" || link.Path != "" || link.Label != "禁止 curl 外联" {
		t.Fatalf("link=%+v", link)
	}
}

func TestBehaviorLinkNeverHasAnEmptyLabel(t *testing.T) {
	for _, key := range []string{"sensitive_resource", "destructive_operation", "system_command"} {
		if PolicyCenterAgentBehaviorLabels[key] == "" {
			t.Fatalf("behavior %s has no label", key)
		}
	}
	if link := agentBehaviorLink("future_behavior", "某规则名"); link.Label != "某规则名" {
		t.Fatalf("unlabelled behavior must fall back to the block's rule name: %+v", link)
	}
	record := SecurityBlockRecord{Layer: "restricted_file", RuleName: "受限文件"}
	if link := blockPolicyLink(&record, map[string]any{}, "", false); link.Label == "" {
		t.Fatalf("empty label: %+v", link)
	}
}

func TestEveryAnalyzerReasonIsExplainedWithoutCodes(t *testing.T) {
	for _, reason := range []string{
		"blocked_git_credential_dump", "command_not_allowlisted", "scoped_mutation_requires_confirm",
		"shell_interpolation_requires_confirm", "shell_composition_observed", "shell_interpreter_observed",
		"unknown_sql_requires_audit", "tainted_irreversible_network_egress",
	} {
		text := agentToolRiskExplanations[reason]
		if text == "" {
			t.Fatalf("%s has no explanation", reason)
		}
		assertNoInternalCode(t, reason, text)
		for _, verdict := range []string{"已阻断", "已拦截", "人工确认", "需要确认", "需确认"} {
			if strings.Contains(text, verdict) {
				t.Fatalf("%s: 风险原因只描述事实与影响，不写处置结论: %q", reason, text)
			}
		}
	}
}

func TestAlertPolicyLink(t *testing.T) {
	cases := []struct {
		name string
		item AlertOccurrence
		want string
	}{
		{"policy bound", AlertOccurrence{RuleID: "rule_41346ec5", RuleName: "XSS 代码生成", PolicyCode: "builtin.code_security.46a74885f15123bb"}, "/security/policies?policy=rule_41346ec5"},
		{"custom regex", AlertOccurrence{RuleID: "rule_997bd32c", RuleName: "密钥相关", RuleType: "regex"}, "/security/policies?policy=rule_997bd32c"},
		{"destructive", AlertOccurrence{Type: "tool_destructive_intent", RuleName: "Bash"}, "/security/agents?behavior=destructive_operation"},
		{"unbound catalog", AlertOccurrence{RuleID: "catalog_code_xss_generation", RuleType: "builtin"}, ""},
		{"semantic", AlertOccurrence{RuleID: "semantic_semantic_jailbreak"}, ""},
	}
	for _, tc := range cases {
		link := alertPolicyLink(&tc.item)
		got := ""
		if link != nil {
			got = link.Path
		}
		if got != tc.want {
			t.Fatalf("%s: path=%q want %q", tc.name, got, tc.want)
		}
	}
}

func TestListBlockRecordsFillsPolicyLinkFromTheRulesTable(t *testing.T) {
	repo, pool := newBlockRecordsTestRepo(t)
	ctx := context.Background()
	for _, stmt := range []string{
		// evt_input 的规则仍在（本租户已发布规则集）；evt_legacy 的规则（只在 findings 里记录）已不存在。
		`INSERT INTO rules (id,name,rule_type,rule_set_id) VALUES ('rule_525f3078','密码明文检测','regex','rs_t1')`,
		// 墓碑：策略中心删除只是保留行并写 deleted_at。
		`INSERT INTO rules (id,name,rule_type,rule_set_id,scope_json) VALUES ('rule_tomb','已删策略','regex','rs_t1','{"deleted_at":"2026-11-13T00:00:00Z"}')`,
		// 规则集未发布、别的租户的规则集：策略列表看不到，也不能链接过去。
		`INSERT INTO rules (id,name,rule_type,rule_set_id) VALUES ('rule_draft','草稿','regex','rs_draft'), ('rule_other','别家','regex','rs_t2')`,
		// 系统预置规则集的规则所有租户可见。
		`INSERT INTO rules (id,name,rule_type,rule_set_id) VALUES ('rule_sys','预置规则','regex','rs_sys')`,
		`INSERT INTO security_events (id,request_id,tenant_id,project_id,user_id,event_type,severity,action_taken,matched_summary,created_at) VALUES
			('evt_tomb','req-tomb','t1','p1','u1','security_check','high','security_blocked','{"stage":"input","block":{"block_id":"evt_tomb","layer":"input_content","rule_id":"rule_tomb","rule_name":"已删策略"}}', NOW() - interval '10 minutes'),
			('evt_draft','req-draft','t1','p1','u1','security_check','high','security_blocked','{"stage":"input","block":{"block_id":"evt_draft","layer":"input_content","rule_id":"rule_draft","rule_name":"草稿"}}', NOW() - interval '11 minutes'),
			('evt_xtenant','req-other','t1','p1','u1','security_check','high','security_blocked','{"stage":"input","block":{"block_id":"evt_other","layer":"input_content","rule_id":"rule_other","rule_name":"别家"}}', NOW() - interval '12 minutes'),
			('evt_sys','req-sys','t1','p1','u1','security_check','high','security_blocked','{"stage":"input","primary_finding":{"rule_id":"rule_sys","rule_name":"预置规则"},"block":{"block_id":"evt_sys","layer":"input_content","rule_name":"预置规则"}}', NOW() - interval '13 minutes'),
			('evt_cur','req-cur','t1','p1','u1','tool_attempt_blocked','high','block','{"stage":"tool","block":{"block_id":"evt_cur","layer":"agent_tool","cause":"explicit_block","rule_name":"系统命令","detail":"Bash · ls"}}', NOW() - interval '14 minutes')`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("%q: %v", stmt, err)
		}
	}
	records, _, err := repo.ListBlockRecords(ctx, "t1", SecurityBlockRecordFilter{})
	if err != nil {
		t.Fatal(err)
	}
	links := map[string]*PolicyLink{}
	names := map[string]string{}
	for _, record := range records {
		links[record.BlockID] = record.PolicyLink
		names[record.BlockID] = record.RuleName
	}
	if l := links["evt_input"]; l == nil || l.Kind != "policy" || l.Path != "/security/policies?policy=rule_525f3078" {
		t.Fatalf("existing rule: %+v", l)
	}
	if l := links["evt_legacy"]; l == nil || l.Kind != "deleted" || l.Path != "" || l.Label != "硬编码凭据示例" {
		t.Fatalf("deleted rule recorded only in findings: %+v", l)
	}
	for _, id := range []string{"evt_tomb", "evt_draft", "evt_xtenant"} {
		if l := links[id]; l == nil || l.Kind != "deleted" || l.Path != "" {
			t.Fatalf("%s: tombstone / unpublished / other-tenant rule must read as deleted: %+v", id, l)
		}
	}
	if l := links["evt_sys"]; l == nil || l.Kind != "policy" || l.Path != "/security/policies?policy=rule_sys" {
		t.Fatalf("system preset rule found through primary_finding: %+v", l)
	}
	if l := links["evt_tool"]; l == nil || l.Kind != "agent_behavior" || l.Path != "/security/agents?behavior=destructive_operation" {
		t.Fatalf("destructive layer: %+v", l)
	}
	if l := links["evt_cur"]; l == nil || l.Kind != "agent_behavior" || l.Path != "/security/agents?behavior=system_command" || names["evt_cur"] != "系统命令" {
		t.Fatalf("current gateway shape (no rule_id): link=%+v name=%q", l, names["evt_cur"])
	}
}

// 当前网关形态：托管行为的阻断 rule_id 为空，block.rule_name 就是行为中文名。
func managedBehaviorBlock(mutate func(block map[string]any)) (SecurityBlockRecord, map[string]any) {
	summary := agentToolBlockSummary("", "", "explicit_block", "Bash · ls", "Bash · ls")
	block := summary["block"].(map[string]any)
	block["rule_name"] = "系统命令"
	block["cause"] = "explicit_block"
	if mutate != nil {
		mutate(block)
	}
	return projectAgentToolBlock("block", summary), summary
}

func TestManagedBehaviorIsRecognisedFromTheCurrentGatewayShape(t *testing.T) {
	record, summary := managedBehaviorBlock(nil)
	if record.RuleName != "系统命令" {
		t.Fatalf("规则名要保留行为中文名，got %q", record.RuleName)
	}
	link := blockPolicyLink(&record, summary, "", false)
	if link.Kind != "agent_behavior" || link.Path != "/security/agents?behavior=system_command" || link.Label != "系统命令" {
		t.Fatalf("link=%+v", link)
	}
}

func TestManagedBehaviorKeyPrefersGatewayFieldThenRuleIDThenName(t *testing.T) {
	record, summary := managedBehaviorBlock(func(b map[string]any) {
		b["managed_behavior"] = "network_egress"
		b["rule_name"] = "智能体行为策略"
	})
	if link := blockPolicyLink(&record, summary, "", false); link.Path != "/security/agents?behavior=network_egress" || record.RuleName != "网络外联" {
		t.Fatalf("managed_behavior: link=%+v name=%q", link, record.RuleName)
	}
	record, summary = managedBehaviorBlock(func(b map[string]any) {
		b["rule_id"] = "policy-center-database_change"
		b["rule_name"] = "策略中心托管规则"
	})
	if link := blockPolicyLink(&record, summary, "", false); link.Path != "/security/agents?behavior=database_change" || record.RuleName != "数据库变更" {
		t.Fatalf("legacy rule_id: link=%+v name=%q", link, record.RuleName)
	}
}

func TestBehaviorNameLookupDoesNotCaptureContentRules(t *testing.T) {
	record := SecurityBlockRecord{Layer: "input_content", RuleName: "系统命令"}
	summary := map[string]any{"block": map[string]any{"rule_name": "系统命令", "layer": "input_content"}}
	if link := blockPolicyLink(&record, summary, "", false); link.Kind == "agent_behavior" {
		t.Fatalf("内容规则恰好叫“系统命令”不能当成智能体行为: %+v", link)
	}
}

func TestBlockLinkKindFollowsTheReasonAndIgnoresLegacyExceptionEligibility(t *testing.T) {
	cases := []struct {
		name     string
		reason   string
		eligible any
		kind     string
	}{
		{"unregistered reason, eligible", "tainted_irreversible_network_egress", true, "protection_item"},
		{"unregistered reason, old not-eligible", "tainted_irreversible_network_egress", false, "protection_item"},
		{"unregistered reason, old data", "tainted_irreversible_network_egress", nil, "protection_item"},
		{"formerly floor reason (analyzer cause) goes to the high risk item", "blocked_loopback_or_private_ip", nil, "protection_item"},
		{"skill reason without its own item", "skill_version_revoked", nil, "skill"},
		{"skill dangerous command has its own item", "skill_dangerous_command", nil, "protection_item"},
		{"skill dangerous command, old not-eligible", "skill_dangerous_command", false, "protection_item"},
		{"skill admission unavailable has its own item", "skill_admission_unavailable", nil, "protection_item"},
		// 批次 1 起 Skill 身份异常登记为防护项 skill.identity_invalid，与危险命令同口径。
		{"skill identity misplaced has its own item", "skill_identity_misplaced", nil, "protection_item"},
		{"skill identity invalid has its own item", "skill_identity_invalid", nil, "protection_item"},
		{"skill identity conflict, old not-eligible", "skill_identity_conflict", false, "protection_item"},
		{"skill quarantined", "skill_version_quarantined", nil, "skill"},
	}
	for _, tc := range cases {
		record, summary := analyzerBlock(tc.reason, "Bash · x")
		if tc.eligible != nil {
			summary["block"].(map[string]any)["exception_eligible"] = tc.eligible
		}
		link := blockPolicyLink(&record, summary, "", false)
		if link.Kind != tc.kind {
			t.Fatalf("%s: link=%+v want kind %s", tc.name, link, tc.kind)
		}
		if tc.kind == "protection_item" && !strings.HasPrefix(link.Path, "/security/agents?protection=") {
			t.Fatalf("%s: link=%+v", tc.name, link)
		}
		if tc.kind == "skill" && link.Path != "/security/skills" {
			t.Fatalf("%s: link=%+v", tc.name, link)
		}
	}
}

func TestExceptionTargetIsSanitisedAndBounded(t *testing.T) {
	target := func(detail string) (string, string) {
		record, summary := analyzerBlock("tainted_irreversible_network_egress", detail)
		link := blockPolicyLink(&record, summary, "", false)
		parsed, _ := url.Parse(link.Path)
		return link.Kind, parsed.Query().Get("target")
	}
	if _, got := target("Bash · curl https://admin:s3cret@example.com/a/b?token=abc&k=v#frag"); got != "" {
		t.Fatalf("a target carrying credentials cannot be pre-filled (the stripped text no longer matches the call): %q", got)
	}
	if _, got := target("Bash · curl https://example.com/a/b?token=abc&k=v#frag"); got != "curl https://example.com/a/b" {
		t.Fatalf("query and fragment must be removed: %q", got)
	}
	if _, got := target("Bash · curl https://x.example/a?k=v -o out"); got != "" {
		t.Fatalf("stripping the query leaves text that is no longer part of the call: %q", got)
	}
	if _, got := target("WebFetch · https://example.com/path?sig=zzz"); got != "https://example.com/path" {
		t.Fatalf("query must be removed: %q", got)
	}
	if kind, got := target("Bash · " + strings.Repeat("a", 300)); kind != "protection_item" || got != "" {
		t.Fatalf("over-long target must be left out: kind=%s len=%d", kind, len(got))
	}
	if _, got := target("Bash · curl https://example.com/aaaaaaaaaa…"); got != "" {
		t.Fatalf("truncated target must be left out: %q", got)
	}
}

func TestTaintedEgressExplanationSaysWhereTheDataComesFrom(t *testing.T) {
	want := "调用参数取自网页、工具返回等外部内容，且会向外发送数据，发出后无法撤回"
	if got := agentToolRiskExplanations["tainted_irreversible_network_egress"]; got != want {
		t.Fatalf("got %q", got)
	}
}

func TestMCPProxyBlockLinksToMCPPolicies(t *testing.T) {
	record := SecurityBlockRecord{EventType: "tool_attempt_blocked", Layer: "agent_tool", RuleName: "MCP 工具调用"}
	summary := map[string]any{"source": "gateway_mcp", "stage": "tool", "reason": "x"}
	link := blockPolicyLink(&record, summary, "", false)
	if link.Kind != "mcp_tool" || link.Path != "/mcp-gateway/policies" || link.Label != "MCP 调用策略" {
		t.Fatalf("link=%+v", link)
	}
}

// 集成项：网关写下的 protection_item 优先于原因码（原因码可能是更强的非防护项原因）；
// 显式规则决定的处置仍归规则；注册表里查不到的键不给链接。
func TestAgentToolBlockPrefersGatewayProtectionItem(t *testing.T) {
	record, summary := analyzerBlock("command_not_allowlisted", "Bash · cat ~/.ssh/id_rsa")
	block := summary["block"].(map[string]any)
	block["cause"], block["protection_item"] = "protection_item", "agent.ssh_private_key"
	record = projectAgentToolBlock("block", summary)
	link := blockPolicyLink(&record, summary, "", false)
	if link.Kind != "protection_item" || link.ItemKey != "agent.ssh_private_key" || !strings.HasPrefix(link.Path, "/security/agents?protection=agent.ssh_private_key") {
		t.Fatalf("link=%+v", link)
	}
	if record.Basis != "策略中心 → 智能体行为 → SSH 私钥 动作为阻断" {
		t.Fatalf("basis=%q", record.Basis)
	}

	record, summary = analyzerBlock("builtin_env_files", "Read · /app/.env")
	block = summary["block"].(map[string]any)
	block["cause"], block["protection_item"] = "protection_item", "endpoint.rule.builtin_env_files"
	record = projectAgentToolBlock("block", summary)
	link = blockPolicyLink(&record, summary, "", false)
	if link.Kind != "protection_item" || link.Path != "/security/agents?protection=endpoint.rule.builtin_env_files" ||
		!strings.HasPrefix(record.Basis, "策略中心 → 智能体行为 → 端侧内置规则 → ") {
		t.Fatalf("endpoint rule: link=%+v basis=%q", link, record.Basis)
	}

	record, summary = analyzerBlock("command_not_allowlisted", "Bash · x")
	block = summary["block"].(map[string]any)
	block["cause"], block["protection_item"] = "explicit_block", "agent.ssh_private_key"
	record = projectAgentToolBlock("block", summary)
	if link := blockPolicyLink(&record, summary, "", false); link.Kind == "protection_item" {
		t.Fatalf("an explicit rule decision stays with the rule: %+v", link)
	}

	record, summary = analyzerBlock("command_not_allowlisted", "Bash · x")
	block = summary["block"].(map[string]any)
	block["cause"], block["protection_item"] = "protection_item", "agent.no_such_item"
	record = projectAgentToolBlock("block", summary)
	if link := blockPolicyLink(&record, summary, "", false); link.Kind != "none" {
		t.Fatalf("an unknown key gets no link: %+v", link)
	}
}
