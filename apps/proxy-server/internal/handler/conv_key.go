package handler

import (
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/aiconvo"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

// enrichAPIConversationKey 给 anthropic/openai API 形态的结构化抽取产物补 ConversationID
// （共享契约第 5 条：aiconvo.ConversationKey(tenantID, keyID, agentType, systemDigest, firstUserSHA)）。
// 正向代理无网关 key；有请求时以可信 TCP/代理来源 IP 隔离调用方，缺请求时保持旧调用契约。
// 该指纹仍为推断关联，NAT 后不同客户端必须依赖原生会话身份。约束：
//   - 网页解码器自带会话键（deepseek chat_session_id 等）时不覆盖；
//   - 无结构化消息（回退平铺/普通网页流量）不动；
//   - system 与首条 user 锚点都缺时不填，防止无关请求被同一个空锚点键归组。
//
// 在 4 个留证调用点（WriteAccessContentLog 之前）调用；检测路径不调（检测不需要会话键）。
func enrichAPIConversationKey(tenantID, agentType string, content *ExtractedContent, requests ...*http.Request) {
	if content == nil {
		return
	}
	if agentType == "openai-codex" && len(requests) > 0 && requests[0] != nil {
		req := requests[0]
		if native := aiconvo.CodexThreadKey(req.Header, tenantID, clientIPFromRequest(req)); native != "" {
			content.ConversationID = native
			return
		}
	}
	if content.ConversationID != "" || len(content.Messages) == 0 {
		return
	}
	systemText := ""
	firstUserSHA := ""
	for _, m := range content.Messages {
		if systemText == "" && m.Source == aimsg.SourceSystemPrompt {
			systemText = m.Content
		}
		if firstUserSHA == "" && m.Source == aimsg.SourceUser && strings.TrimSpace(m.Content) != "" {
			firstUserSHA = m.ContentSHA256
			if agentType == "cline" {
				if visible, status, matched := aimsg.NormalizeAgentEnvelope(m.Content); matched && status == aimsg.ParseComplete && visible != "" {
					firstUserSHA = aimsg.ContentSHA256Hex(visible)
				}
			}
		}
		if systemText != "" && firstUserSHA != "" {
			break
		}
	}
	if systemText == "" && firstUserSHA == "" {
		return
	}
	caller := ""
	if len(requests) > 0 && requests[0] != nil {
		caller = clientIPFromRequest(requests[0])
	}
	content.ConversationID = aiconvo.ConversationKey(tenantID, caller, agentType, aiconvo.SystemDigest(systemText), firstUserSHA)
}
