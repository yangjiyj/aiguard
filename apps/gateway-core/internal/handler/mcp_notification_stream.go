package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// mcpNotificationStreamReadTimeout 限制读取「通知收到的响应流」的总时长：通知本不该有响应体，
// 更不该是长连接流；超时即截断，网关照常回 202。
const mcpNotificationStreamReadTimeout = 5 * time.Second

// discardNotificationStream 处理 L-1：只含通知的 POST，上游却回了 text/event-stream。
// 网关不把这条流转发给客户端（通知没有响应体），但必须留下痕迹：
//   - 日志：记录「通知收到了非预期的响应流」以及丢弃的消息数、其中服务端反向请求数；
//   - 反向请求（带 id 与 method 的服务端消息）按现有 server_request 口径记审计：blocked、未转发（已丢弃），
//     并替客户端向上游回一条拒绝，避免上游一直等待客户端响应；
//   - 读取有大小上限（validateAndCopyMCPSSE）与总时长上限，无限流不会拖住网关。
//
// 返回丢弃的消息数、反向请求数与要并入审计的决策。
func (h *MCPProxyHandler) discardNotificationStream(
	ctx context.Context, envelope *modelrouter.RequestEnvelope, server *mcpServerRoute, inbound *http.Request,
	resp *http.Response, callerMode agentguard.Mode, auditOnly bool,
) (messages, reverseRequests int, recorded []mcpToolCallDecision) {
	guard := h.newMCPServerRequestGuard(ctx, envelope, server, inbound, callerMode, auditOnly)
	if guard != nil {
		guard.discardAll = true
	}
	readCtx, cancel := context.WithTimeout(ctx, mcpNotificationStreamReadTimeout)
	defer cancel()
	stop := context.AfterFunc(readCtx, func() { _ = resp.Body.Close() })
	defer stop()

	transform := func(event []byte) []byte {
		payload, ok := mcpSSEEventData(event)
		if !ok {
			return nil
		}
		trimmed := bytes.TrimSpace(payload)
		var items []json.RawMessage
		switch {
		case len(trimmed) > 0 && trimmed[0] == '{':
			items = []json.RawMessage{trimmed}
		case len(trimmed) > 0 && trimmed[0] == '[':
			if err := json.Unmarshal(trimmed, &items); err != nil {
				messages++ // 无法解析的数据块也算一条被丢弃的消息
				return nil
			}
		default:
			messages++
			return nil
		}
		for _, item := range items {
			messages++
			item = bytes.TrimSpace(item)
			if methods, _, isRequest := mcpServerRequestFields(item); isRequest && len(methods) > 0 {
				reverseRequests++
				if guard != nil {
					guard.judge(item)
				}
			}
		}
		return nil // 一律丢弃
	}
	if err := copyMCPSSEEvents(io.Discard, nil, resp.Body, transform); err != nil {
		log.Printf("MCP 通知的响应流被截断（超过上限或超时）: server=%s", server.ID)
	}
	if guard != nil {
		recorded = guard.decisions()
	}
	return messages, reverseRequests, recorded
}
