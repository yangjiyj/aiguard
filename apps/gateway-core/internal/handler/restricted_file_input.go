package handler

import (
	"context"
	"fmt"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// checkCodexMentionedFilesRestricted 对最新用户消息里的 Codex 附件清单
// （# Files … by the user:）按租户受限文件模式拦截（任务 7.3）。
// 作用范围不含“用户消息提及”时不检查。命中的动作与工具调用同一口径：RestrictedFiles.Action，
// 指向受限文件的例外（rule_id 为 restricted_file_pattern 或 agent.restricted_file，路径按层级比对）
// 放开对应文件。block → 与输入链 1502 同款 error 路径 + security_blocked 事件；其余放行并记
// security_audit 事件。执行模式以控制台为准：审计（record）模式最高优先级，配置 block 也只记。
func (h *ChatCompletionsHandler) checkCodexMentionedFilesRestricted(ctx context.Context, envelope *modelrouter.RequestEnvelope, messages []Message) (bool, error) {
	if h.toolRiskClient == nil {
		return false, nil
	}
	// 最新用户消息文本
	var latest string
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			latest = messageText(messages[i].Content)
			break
		}
	}
	if latest == "" {
		return false, nil
	}
	paths := aimsg.ExtractMentionedFilePaths(latest)
	if len(paths) == 0 {
		return false, nil
	}

	policy, err := h.toolRiskClient.GetAgentGuardPolicy(ctx, envelope)
	if err != nil || policy == nil || policy.RestrictedFiles == nil || len(policy.RestrictedFiles.Patterns) == 0 ||
		!policy.RestrictedFiles.Applies(agentguard.RestrictedFileScopeUserMention) {
		// 策略拉取失败视为无策略（已有缓存语义），功能关闭。
		return false, nil
	}
	matcher, err := filerestrict.Compile(policy.RestrictedFiles.Patterns)
	if err != nil {
		return false, nil
	}
	hits := matcher.MatchPaths(paths)
	if len(hits) == 0 {
		return false, nil
	}
	hit, action, exceptionID := hits[0], protection.Action(""), ""
	for _, candidate := range hits {
		resolved, exception := agentguard.ResolveRestrictedFileHit(policy, candidate.Target)
		if action == "" || protection.Rank(resolved) > protection.Rank(action) {
			hit, action, exceptionID = candidate, resolved, exception
		}
	}
	enforce := action == protection.ActionBlock &&
		securityexit.Decide(securityexit.ModeFromAuditOnly(h.securityAuditOnly(ctx)), "block", securityexit.ToolPolicy).Enforce

	countsAsFinding := true
	finding := SecurityFinding{
		Type:     "restricted_file_access",
		Severity: "high",
		Category: "restricted_file_access",
		RuleName: "agentguard-restricted-file-pattern",
		RuleID:   "agentguard-restricted-file-pattern",
		// 证据只含模式 + 脱敏目标，不含完整路径原文。
		RedactedEvidence:        fmt.Sprintf("pattern=%s target=%s", hit.Pattern, filerestrict.RedactTarget(hit.Target)),
		CountsAsSecurityFinding: &countsAsFinding,
		ContentSource:           "user",
	}

	if enforce {
		h.writeSecurityEvent(ctx, envelope, []SecurityFinding{finding}, "security_blocked",
			fmt.Sprintf("blocked Codex mentioned file by restricted pattern %s", hit.Pattern))
		return true, fmt.Errorf("受限文件类型不允许交给模型：%s", hit.Pattern)
	}
	// 审计模式下的 block，以及 record / alert_allow、被例外放开的文件：放行，记 security_audit。
	summary := fmt.Sprintf("Codex mentioned file matches restricted pattern %s (action=%s)", hit.Pattern, action)
	if exceptionID != "" {
		summary += " exception=" + exceptionID
	}
	h.writeSecurityEvent(ctx, envelope, []SecurityFinding{finding}, "security_audit", summary)
	return false, nil
}
