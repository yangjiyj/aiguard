package handler

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
	"github.com/yangjiyj/aiguard/packages/shared-go/llmcatalog"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// reverseProxySourceAwareEnabled 读 SECURITY_SOURCE_AWARE_ENABLED（共享契约第 10 条）。
// 代码默认 false（引擎"新能力默认关"惯例）；P1-A 的 compose 与升级脚本显式置 true。
// 关闭时反代输入检测与现状字节级一致（整包 string(body) 单次送检、无 content_source）。
func reverseProxySourceAwareEnabled() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("SECURITY_SOURCE_AWARE_ENABLED")), "true")
}

// isReverseProxyChatEndpoint 判定目标是否 chat 型 LLM API 端点（消息数组解析的适用范围）。
// 必须按"请求路径形态"判定，不能用 matchReverseProxyProvider(...).EndpointKind：后者的
// EndpointKind 来自目录 provider 分类（如 doubao 整站 category=chat），会把该 host 下的网页
// 静态资源（/static/app.js）误判为 chat 端点，从而对纯浏览反代流量误启结构化解析。
// classifyReverseProxyEndpointKind 是纯路径分类（含 message/response/completion 关键字→chat），
// 再叠加 /v1/messages、chat/completions 显式形态双保险（覆盖 OpenAI 兼容端点）。
// targetHost 保留在签名中以对齐调用点与既有测试，路径判定不依赖它。
func isReverseProxyChatEndpoint(targetHost, targetPath string) bool {
	_ = targetHost
	if classifyReverseProxyEndpointKind(targetPath) == "chat" {
		return true
	}
	lower := strings.ToLower(targetPath)
	return strings.Contains(lower, "/v1/messages") || strings.Contains(lower, "/chat/completions") || strings.Contains(lower, ":generatecontent") || strings.Contains(lower, ":streamgeneratecontent")
}

// sourceGroup 是按 content_source 聚合后的一段送检内容。
type sourceGroup struct {
	Source  string
	Content string
}

// groupMessagesBySource 把消息按 source 聚合（保持首次出现顺序），供逐 source 送检。
// 最多 6 组（system_prompt/tool_def/user/assistant_history/tool_result/unknown）。
func groupMessagesBySource(msgs []aimsg.ConvMessage) []sourceGroup {
	index := map[string]int{}
	parts := make([][]string, 0, 6)
	groups := make([]sourceGroup, 0, 6)
	for _, m := range msgs {
		content := strings.TrimSpace(m.Content)
		if content == "" {
			continue
		}
		i, ok := index[m.Source]
		if !ok {
			index[m.Source] = len(groups)
			groups = append(groups, sourceGroup{Source: m.Source})
			parts = append(parts, []string{content})
			continue
		}
		if m.Source == aimsg.SourceUser {
			parts[i] = []string{content}
			continue
		}
		parts[i] = append(parts[i], content)
	}
	for i := range groups {
		groups[i].Content = strings.Join(parts[i], "\n")
	}
	return groups
}

// maxSecurityAction 取两个引擎动作里更严的那个：block/reply/deny > mask > audit > 其余(allow/空)。
// audit 必须严于 allow：否则全组 allow 时初值 audit 会虚报、或任一组 audit 被 allow 吞掉。
func maxSecurityAction(a, b string) string {
	rank := func(s string) int {
		if securityexit.Blocks(s) {
			return 4
		}
		switch s {
		case "mask":
			return 3
		case "audit":
			return 2
		default:
			return 1
		}
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// Security projection is independent of the customer-visible retained user text.
// Protocol roles classify content; they never attest that tool results are trusted.
func (h *ReverseProxyHandler) checkRequestSecurityStructured(ctx context.Context, requestID string, req *http.Request, body []byte, contentType, targetHost, targetPath string) (reverseProxySecurityDecision, error) {
	if llmcatalog.IsTelemetry(targetHost, targetPath) {
		return reverseProxySecurityDecision{Body: body, Allowed: true, Action: "allow"}, nil
	}
	attachments := extractRequestAttachmentsForProxy(body, contentType, targetPath)
	if !isReverseProxyChatEndpoint(targetHost, targetPath) {
		return h.checkRequestSecurityWithAttachments(ctx, requestID, body, contentType, targetHost, targetPath, attachments)
	}
	parsed, ok := aimsg.ParseChatRequest(targetPath, body)
	if !ok {
		decision, err := h.checkSecurityWithExtras(ctx, requestID, "/check-input/", body, string(body), contentType, targetHost, targetPath, "unknown", map[string]interface{}{"attachments": attachments, "skip_semantic": true, "extraction": "protocol_parse_failed"})
		if clientGoneDuring(ctx, err) {
			// 客户端已断开：原样返回干净 decision + 哨兵，不要用下面的 incomplete 覆写盖住它。
			return decision, err
		}
		decision.SemanticStatus = "incomplete"
		decision.SemanticReason = "protocol_parse_failed"
		decision.VerifiedContent = ""
		decision.ContentSource = ""
		decision.Action = maxSecurityAction(decision.Action, "audit")
		return decision, err
	}
	agentType, err := inferReverseProxyAgentType(req, matchReverseProxyProvider(targetHost, targetPath), body, nil)
	if err != nil {
		return reverseProxySecurityDecision{}, err
	}
	policy := inspectionscope.Default()
	if h.runtimeConfigClient != nil {
		policy = h.runtimeConfigClient.InspectionPolicy(ctx)
	}
	decision := reverseProxySecurityDecision{Body: body, Action: "allow", Allowed: true}
	groups := aimsg.SelectInspectionMessages(parsed.Messages, policy)
	for _, m := range groups {
		if m.IsLatestUser {
			decision.VerifiedContent = m.Content
			decision.ContentSource = "verified_user_input"
			break
		}
	}
	judgment := aimsg.JudgmentContext(parsed.Messages, policy)
	userTask := aimsg.LatestUserTask(parsed.Messages)
	requestKind := aimsg.AgentRequestKind(agentType, parsed.Messages)
	for _, group := range groups {
		atts := extractRequestAttachments(group.RawContent)
		if group.Content == "" && len(atts) == 0 {
			continue
		}
		extra := map[string]interface{}{"agent_type": agentType, "extraction": "protocol_source_security", "message_role": group.Role, "source_path": group.SourcePath, "inspection_is_history": group.InspectionIsHistory, "is_latest_user": group.IsLatestUser, "judgment_context": judgment, "inspection_policy_fingerprint": policy.Fingerprint()}
		if group.MessageIndex != nil {
			extra["message_index"] = *group.MessageIndex
		}
		extra["user_task"] = userTask
		if requestKind != "" {
			extra["agent_request_kind"] = requestKind
		}
		if len(atts) > 0 {
			extra["attachments"] = atts
		}
		if group.Content == "" {
			group.Content = "文件附件"
		}
		part, err := h.checkSecurityWithExtras(ctx, requestID, "/check-input/", body, group.Content, contentType, targetHost, targetPath, group.Source, extra)
		if clientGoneDuring(ctx, err) {
			// 客户端已断开：立即返回哨兵，不要吞错继续扫下一组（每组都会再打一次引擎）。
			return reverseProxySecurityDecision{Body: body, Allowed: true, Action: "allow"}, err
		}
		decision.RetryTaskIDs = append(decision.RetryTaskIDs, part.RetryTaskIDs...)
		decision.RetryUnavailable = decision.RetryUnavailable || part.RetryUnavailable
		if err != nil {
			decision.SemanticStatus = "incomplete"
			decision.SemanticReason = "security_engine_unavailable"
			decision.Action = maxSecurityAction(decision.Action, "audit")
			continue
		}
		decision.Action = maxSecurityAction(decision.Action, part.Action)
		decision.Allowed = decision.Allowed && part.Allowed
		decision.FileAttachmentRisk = decision.FileAttachmentRisk || part.FileAttachmentRisk
		decision.MaskUnavailable = decision.MaskUnavailable || part.MaskUnavailable
		for i := range part.Findings {
			if part.Findings[i].ContentSource == "" {
				part.Findings[i].ContentSource = group.Source
			}
			part.Findings[i].MessageIndex = group.MessageIndex
			part.Findings[i].MessageRole = group.Role
		}
		decision.Findings = append(decision.Findings, part.Findings...)
		if semanticStatusRank(part.SemanticStatus) > semanticStatusRank(decision.SemanticStatus) {
			decision.SemanticStatus = part.SemanticStatus
			decision.SemanticReason = part.SemanticReason
		}
	}
	// Triage must review the evidence-bearing source, not an unrelated last user.
	// Mixed-source findings need separate reviews; don't submit a misleading one.
	evidenceSource := ""
	mixed := false
	for _, finding := range decision.Findings {
		if !countsAsSecurityFinding(finding) {
			continue
		}
		if evidenceSource == "" {
			evidenceSource = finding.ContentSource
		} else if evidenceSource != finding.ContentSource {
			mixed = true
		}
	}
	if evidenceSource != "" {
		matches := 0
		for _, group := range groups {
			if group.Source == evidenceSource {
				matches++
			}
		}
		if matches > 1 {
			mixed = true
		}
	}
	if mixed {
		decision.VerifiedContent = ""
		decision.ContentSource = ""
	} else if evidenceSource != "" {
		for _, group := range groups {
			if group.Source == evidenceSource {
				decision.VerifiedContent = group.Content
				decision.ContentSource = group.Source
				if group.Source == aimsg.SourceUser {
					decision.ContentSource = "verified_user_input"
				}
				break
			}
		}
	}
	// A whole JSON protocol body cannot be replaced by masked text.
	if decision.Action == "mask" && !decision.FileAttachmentRisk {
		decision.Body = body
		decision.Allowed = true
		decision.Action = "audit" // original protocol bytes were not actually masked
	}
	return decision, nil
}
