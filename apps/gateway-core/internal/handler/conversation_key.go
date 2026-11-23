package handler

import (
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/aiconvo"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

// computeConversationKey 计算 A 路（chat completions）请求的会话归组键（契约第 5/6 条）。
// 取首条 system 消息与首条 user 消息文本，经 aiconvo 归一化/哈希后与租户、key、agent 合成。
// 无 system（纯 user 请求）时 systemDigest 为对空串的哈希——键仍稳定；
// 无 user 消息返回空串（无法定义"会话"，计数口径回退 request_id）。
func computeConversationKey(envelope *modelrouter.RequestEnvelope, req *ChatCompletionRequest) string {
	if envelope == nil || req == nil {
		return ""
	}
	systemText, firstUser := "", ""
	for i := range req.Messages {
		t := messageText(req.Messages[i].Content)
		if t == "" {
			continue
		}
		switch strings.ToLower(req.Messages[i].Role) {
		case "system", "developer":
			if systemText == "" {
				systemText = t
			}
		case "user":
			if firstUser == "" {
				firstUser = t
				if envelope.AgentType == "cline" {
					if visible, status, matched := aimsg.NormalizeAgentEnvelope(t); matched && status == aimsg.ParseComplete && visible != "" {
						firstUser = visible
					}
				}
			}
		}
		if systemText != "" && firstUser != "" {
			break
		}
	}
	if firstUser == "" {
		return ""
	}
	return aiconvo.ConversationKey(
		envelope.TenantID,
		envelope.ClientID,
		envelope.AgentType,
		aiconvo.SystemDigest(systemText),
		aiconvo.ContentSHA256(firstUser),
	)
}
