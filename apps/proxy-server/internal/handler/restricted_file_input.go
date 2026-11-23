package handler

import (
	"context"
	"fmt"
	"net/http"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/filerestrict"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// checkCodexMentionedFilesRestrictedInput 对最新 SourceUser 消息里的 Codex 附件清单
// 按受限文件模式拦截（任务 7.4；审计模式下只记）。命中合成 stage=input finding 并入 blocked 判定。
// 返回 (action, findings, blocked)；无清单/无策略/无命中 → 零值。
func (h *ProxyHandler) checkCodexMentionedFilesRestrictedInput(tenantID string, auditRecord ProxyAuditRecord, clientReq *http.Request, requestBody []byte, requestDecoder string) (string, []map[string]interface{}, bool) {
	if h.restrictedFilePolicy == nil || len(requestBody) == 0 {
		return "", nil, false
	}
	extracted := extractRequestContentWithDecoder(clientReq, requestBody, requestDecoder)
	var latest string
	for i := len(extracted.Messages) - 1; i >= 0; i-- {
		if extracted.Messages[i].Source == aimsg.SourceUser {
			latest = extracted.Messages[i].Content
			break
		}
	}
	if latest == "" {
		return "", nil, false
	}
	paths := aimsg.ExtractMentionedFilePaths(latest)
	if len(paths) == 0 {
		return "", nil, false
	}

	policy := h.restrictedFilePolicy.Get(context.Background(), tenantID, auditRecord.AgentType)
	if len(policy.Patterns) == 0 || !policy.applies(restrictedFileScopeUserMention) {
		return "", nil, false
	}
	matcher, err := filerestrict.Compile(policy.Patterns)
	if err != nil {
		return "", nil, false
	}
	hits := matcher.MatchPaths(paths)
	if len(hits) == 0 {
		return "", nil, false
	}
	kept, exceptionID := policy.splitExceptedHits(hits)
	hit := hits[0]
	if len(kept) > 0 {
		hit = kept[0]
	}
	// 被例外放开的文件不按受限处置，只记录。
	configBlocks := policy.Action == string(filerestrict.ActionBlock) && len(kept) > 0

	// 执行模式以控制台为准：审计（record）模式最高优先级，配置为"阻断"也只记录；
	// 只有防护（protect）模式才按策略阻断。
	action := "audit"
	if configBlocks && securityexit.Decide(h.exitMode(), "block", securityexit.ToolPolicy).Enforce {
		action = "block"
	}
	finding := map[string]interface{}{
		"type":                       "agent",
		"category":                   "restricted_file_access",
		"rule_id":                    "agentguard-restricted-file-pattern",
		"severity":                   "high",
		"action":                     action,
		"counts_as_security_finding": true,
		"content_source":             "user",
		"stage":                      "input",
		"matched_text_preview":       fmt.Sprintf("pattern=%s target=%s", hit.Pattern, filerestrict.RedactTarget(hit.Target)),
	}
	if len(kept) == 0 {
		finding["exception_id"] = exceptionID
	}
	blocked := action == "block"
	return action, []map[string]interface{}{finding}, blocked
}
