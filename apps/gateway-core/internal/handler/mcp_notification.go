package handler

import (
	"net/http"
)

// mcpAllNotifications 判定这次 POST 是否只含通知（每条 JSON-RPC 消息都没有 id）。空列表不是通知。
// JSON-RPC 的 id 缺失 / null 都不是请求；这里沿用已解析的 mcpRPCMessage（严格解析已拒绝重复键等歧义）。
func mcpAllNotifications(msgs []mcpRPCMessage) bool {
	if len(msgs) == 0 {
		return false
	}
	for _, m := range msgs {
		if mcpMessageHasID(m) {
			return false
		}
	}
	return true
}

func mcpMessageHasID(m mcpRPCMessage) bool {
	id := string(m.ID)
	return id != "" && id != "null"
}

// mcpNotificationDownstreamStatus 把上游对通知的响应状态映射为下游状态：2xx → 202；3xx 视为上游异常 → 502；
// 4xx 透传；5xx 与其他 → 502（网关不假装通知已送达，也不把上游的 5xx 当成客户端的错）。
func mcpNotificationDownstreamStatus(upstream int) int {
	switch {
	case upstream >= 200 && upstream < 300:
		return http.StatusAccepted
	case upstream >= 400 && upstream < 500:
		return upstream
	default:
		return http.StatusBadGateway
	}
}

// writeMCPNotificationDeliveryError 写通知投递失败的下游响应：固定的脱敏 JSON，不含上游状态文本、body 或地址。
func writeMCPNotificationDeliveryError(w http.ResponseWriter, status int) {
	message := "MCP 上游拒绝了通知（通知无需响应体）"
	if status == http.StatusBadGateway {
		message = "MCP 通知投递失败（上游返回错误）"
	}
	writeMCPTransportError(w, status, "mcp_notification_not_delivered", message)
}
