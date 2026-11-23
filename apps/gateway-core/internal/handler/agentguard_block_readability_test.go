package handler

import (
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// 客户现场 2.9.15：规则「系统命令」动作为告警，但安全底线拦下的调用被记成
// 「智能体行为规则「policy-center-system_command」动作为阻断」，依据还外露
// analyzer_high_risk_block、confirm_channel_available 等内部代号。

var agentBlockInternalCode = regexp.MustCompile(`[A-Za-z]+[_-][A-Za-z_-]+`)

func bashCall(command string) ToolCall {
	return ToolCall{ID: "call_1", Type: "function", Function: ToolCallFunc{Name: "Bash", Arguments: `{"command":"` + command + `"}`}}
}

func assertAgentBasisReadable(t *testing.T, operation blockOperation) {
	t.Helper()
	for field, value := range map[string]string{"basis": operation.Basis, "rule_name": operation.RuleName, "reason": operation.Reason} {
		if strings.Contains(value, "策略中心托管规则") || agentBlockInternalCode.MatchString(value) {
			t.Fatalf("%s 外露内部代号: %q", field, value)
		}
	}
}

// 2.9.22 起没有“产品内置安全底线”：托管卡片（系统命令）为记录时，SSH 私钥被拦是因为防护项
// 配成阻断，规则名写防护项显示名，依据写“策略中心 → 智能体行为 → <显示名>”。
func TestProtectionItemBlockIsAttributedToTheItem(t *testing.T) {
	decision := agentguard.Decision{
		RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock,
		EffectiveReason: "protection_item", PolicyReason: "protection_item",
		Reason: "blocked_ssh_private_key_path", MatchedRuleID: "policy-center-system_command",
		MatchedPolicyName: "策略中心托管规则", NormalizedTarget: "cat ~/.ssh/id_rsa",
		ProtectionItem: "agent.ssh_private_key", ProtectionAction: "block", ConfiguredEnforcement: true,
	}
	operation := agentGuardBlockOperation(bashCall("cat ~/.ssh/id_rsa"), decision)
	if operation.RuleName != "SSH 私钥" || operation.Cause != "protection_item" || operation.RiskReason != "blocked_ssh_private_key_path" {
		t.Fatalf("防护项归因: %+v", operation)
	}
	if operation.Basis != "策略中心 → 智能体行为 → SSH 私钥 动作为阻断" || strings.Contains(operation.Basis, "系统命令") ||
		strings.Contains(operation.Basis, "产品内置") {
		t.Fatalf("依据应指向防护项而不是「系统命令」卡片, got %q", operation.Basis)
	}
	if operation.ExceptionEligible == nil || !*operation.ExceptionEligible {
		t.Fatalf("防护项阻断可被例外改变: %+v", operation)
	}
	assertAgentBasisReadable(t, operation)

	attribution := deriveBlockAttribution(withBlockOperation(context.Background(), operation), "evt_1",
		[]SecurityFinding{{Type: "tool_attempt_blocked", Action: "block", RuleName: operation.RuleName}}, "block", "")
	if attribution.Cause != "protection_item" || attribution.RiskReason != "blocked_ssh_private_key_path" {
		t.Fatalf("matched_summary.block 应写入 cause 与 risk_reason 供控制台归因: %+v", attribution)
	}
}

func TestConfiguredBehaviorBlockNamesThePolicyPagePath(t *testing.T) {
	decision := agentguard.Decision{
		RawDecision: agentguard.DecisionAudit, EffectiveDecision: agentguard.DecisionBlock,
		EffectiveReason: "explicit_block", PolicyReason: "explicit_block",
		MatchedRuleID: "policy-center-system_command", MatchedPolicyName: "策略中心托管规则", ConfiguredEnforcement: true,
	}
	operation := agentGuardBlockOperation(bashCall("ls"), decision)
	if operation.RuleName != "系统命令" || operation.Basis != "策略中心 → 智能体行为 → 系统命令 动作为阻断" {
		t.Fatalf("配置阻断: %+v", operation)
	}
}

// 2.9.22：原“Skill 准入底线要求确认”改为防护项 skill.admission_unavailable 配成确认，
// 依据写防护项显示名。
func TestStrictConfirmRecordsWhatRequiredConfirmation(t *testing.T) {
	decision := agentguard.Decision{
		RawDecision: agentguard.DecisionConfirm, EffectiveDecision: agentguard.DecisionConfirm,
		EffectiveReason: "confirm_channel_available", PolicyReason: "protection_item", Reason: "skill_admission_unavailable",
		ProtectionItem: "skill.admission_unavailable", ProtectionAction: "confirm", ConfiguredEnforcement: true,
		MatchedPolicyName: "策略中心托管规则",
	}
	operation := agentGuardBlockOperation(ToolCall{Function: ToolCallFunc{Name: "Skill"}}, decision)
	if operation.Cause != "protection_item" || !strings.Contains(operation.Basis, "人工确认") ||
		operation.RuleName != "准入服务不可用" || operation.Basis != "策略中心 → 智能体行为 → 准入服务不可用 动作为人工确认" {
		t.Fatalf("确认原因: %+v", operation)
	}
	assertAgentBasisReadable(t, operation)
}

func TestAnalyzerHighRiskBlockBasisIsReadable(t *testing.T) {
	decision := agentguard.Decision{
		RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock,
		EffectiveReason: "analyzer_high_risk_block", PolicyReason: "analyzer_default", Reason: "skill_dangerous_command",
		MatchedPolicyName: "策略中心托管规则",
	}
	operation := agentGuardBlockOperation(ToolCall{Function: ToolCallFunc{Name: "Skill"}}, decision)
	if operation.Cause != "analyzer_high_risk_block" || !strings.Contains(operation.Basis, "高风险") {
		t.Fatalf("高风险判定: %+v", operation)
	}
	assertAgentBasisReadable(t, operation)
}

func TestBlockDetailKeepsTheDangerousTail(t *testing.T) {
	full := `Bash · echo "---git credential helper---"; git config --global credential.helper; echo "---check stored cred files---"; ls -la ~/.git-credentials 2>&1; printf "protocol=https\nhost=example.invalid\n" | git credential fill`
	attribution := deriveBlockAttribution(withBlockOperation(context.Background(), blockOperation{Layer: "agent_tool", Detail: full}), "evt_1", nil, "block", "")
	if attribution.Detail != full {
		t.Fatalf("阻断记录应保存完整的脱敏命中内容, got %q", attribution.Detail)
	}
	notice := renderBlockNotice(DefaultBlockNoticeTemplate, attribution)
	if !strings.Contains(notice, "git credential fill") {
		t.Fatalf("阻断提示截断时应保留末段, got %q", notice)
	}
	if strings.Contains(notice, full) {
		t.Fatalf("阻断提示里的命中内容仍应限长")
	}
}

// 阻断记录的命中内容只在超过落库上限时截断，截断时写 detail_truncated 标记；控制面只认这个标记
// 去用完整证据补全，不再按“以 … 结尾”猜。本身以 … 结尾的命令不能被当成截断。
func TestBlockDetailMarksOnlyRealTruncation(t *testing.T) {
	ellipsisCommand := "Bash · echo 处理中…"
	plain := deriveBlockAttribution(withBlockOperation(context.Background(), blockOperation{Layer: "agent_tool", Detail: ellipsisCommand}), "evt_1", nil, "block", "")
	if plain.Detail != ellipsisCommand || plain.DetailTruncated {
		t.Fatalf("未截断的命中内容不能打截断标记: %+v", plain)
	}
	if raw, _ := json.Marshal(plain); strings.Contains(string(raw), "detail_truncated") {
		t.Fatalf("未截断时不写标记: %s", raw)
	}

	long := "Bash · " + strings.Repeat("a", maxBlockRecordDetailRunes)
	for name, attribution := range map[string]blockAttribution{
		"operation": deriveBlockAttribution(withBlockOperation(context.Background(), blockOperation{Layer: "agent_tool", Detail: long}), "evt_2", nil, "block", ""),
		"finding": deriveBlockAttribution(context.Background(), "evt_3",
			[]SecurityFinding{{Type: "pii", Category: "pii_email", Action: "block", RedactedEvidence: long}}, "security_blocked", ""),
	} {
		if !attribution.DetailTruncated || utf8.RuneCountInString(attribution.Detail) != maxBlockRecordDetailRunes+1 {
			t.Fatalf("%s: 超过落库上限要截断并打标记, truncated=%v runes=%d", name, attribution.DetailTruncated, utf8.RuneCountInString(attribution.Detail))
		}
		if raw, _ := json.Marshal(attribution); !strings.Contains(string(raw), `"detail_truncated":true`) {
			t.Fatalf("%s: 截断标记要写进 matched_summary.block: %s", name, raw)
		}
	}
}
