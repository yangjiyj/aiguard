package handler

// W1 1.9：审批等待。
//
// 基线同步等待默认 2s（上限 10s），超时后回一条只写"已创建确认单"的 -32000，普通 MCP 客户端
// 不知道该怎么续接。现在：
//   - 超时仍是标准 JSON-RPC 错误（-32000），文案写明"待审批 + 审批通过后用相同请求重试即可
//     拿到结果"，error.data 带 reason=confirmation_pending / retryable=true / confirmation_id；
//     同一请求重试会命中同一张确认单（控制面按 invocation 去重），审批后直接领取缓存结果。
//   - 审批被拒 / 确认单过期：立即结束等待，retryable=false。
//   - 可选挂起模式 MCP_CONFIRM_WAIT_MODE=hold：请求挂住直到审批结束（上限为确认单有效期，
//     可用 MCP_CONFIRM_HOLD_MAX 再收紧）。客户端 Accept 含 text/event-stream 时改为 SSE 响应，
//     等待期间周期发送保活注释，防止中间代理因空闲断开；否则按普通 JSON 长轮询挂住。
// 默认模式（timeout）的等待时长仍由 MCP_CONFIRM_WAIT_TIMEOUT 控制，行为不变。

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

const (
	mcpConfirmWaitModeTimeout = "timeout"
	mcpConfirmWaitModeHold    = "hold"
	mcpConfirmKeepalive       = 15 * time.Second
)

// mcpConfirmationWaitMode 读取 MCP_CONFIRM_WAIT_MODE；未知值回落 timeout。
func mcpConfirmationWaitMode() string {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("MCP_CONFIRM_WAIT_MODE")), mcpConfirmWaitModeHold) {
		return mcpConfirmWaitModeHold
	}
	return mcpConfirmWaitModeTimeout
}

// mcpConfirmationWaitBudget 计算本次同步等待时长。hold 模式等到确认单过期为止，
// MCP_CONFIRM_HOLD_MAX（合法正时长）可进一步收紧。
func mcpConfirmationWaitBudget(mode string, ticket MCPConfirmationTicket, now time.Time) time.Duration {
	if mode != mcpConfirmWaitModeHold {
		return mcpConfirmationWaitTimeout()
	}
	budget := time.Duration(0)
	if !ticket.ExpiresAt.IsZero() {
		budget = ticket.ExpiresAt.Sub(now)
	}
	if limit, err := time.ParseDuration(strings.TrimSpace(os.Getenv("MCP_CONFIRM_HOLD_MAX"))); err == nil && limit > 0 && (budget <= 0 || limit < budget) {
		if ticket.ExpiresAt.IsZero() || ticket.ExpiresAt.After(now) {
			budget = limit
		}
	}
	if budget < 0 {
		return 0
	}
	return budget
}

func mcpAcceptsSSE(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept"), ",") {
		mediaType := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if strings.EqualFold(mediaType, "text/event-stream") {
			return true
		}
	}
	return false
}

// mcpConfirmationOutcomeError 把等待结果（无可领取结果体时）映射为 JSON-RPC 错误。
func mcpConfirmationOutcomeError(polled mcpConfirmationPollResult, d agentguard.Decision, policyID string) (int, string, map[string]any) {
	data := safeMCPConfirmationTicket(polled.Ticket)
	policyLabel := policyID
	if policyLabel == "" {
		policyLabel = "默认策略"
	}
	switch polled.ErrorCode {
	case "":
		data["reason"] = "confirmation_pending"
		data["retryable"] = true
		return -32000, "网关安全策略要求人工确认后方可执行该 MCP 工具调用，已创建确认单，当前待审批。" +
			"审批通过后使用相同请求重试即可获得执行结果（策略 " + policyLabel + "）", data
	case "confirmation_rejected":
		data["reason"] = polled.ErrorCode
		data["retryable"] = false
		data["error_code"] = polled.ErrorCode
		return -32000, "该 MCP 工具调用的确认单已被审批人拒绝，未执行（策略 " + policyLabel + "）", data
	case "confirmation_expired":
		data["reason"] = polled.ErrorCode
		data["retryable"] = false
		data["error_code"] = polled.ErrorCode
		return -32000, "该 MCP 工具调用的确认单已过期未审批，未执行；如仍需执行请重新发起（策略 " + policyLabel + "）", data
	default:
		data["reason"] = polled.ErrorCode
		data["retryable"] = false
		data["error_code"] = polled.ErrorCode
		return -32010, "MCP 确认执行未返回可领取结果", data
	}
}

// writeMCPConfirmationOutcome 以 JSON 写出等待结果：有结果体则原样返回，否则写 JSON-RPC 错误。
func writeMCPConfirmationOutcome(w http.ResponseWriter, id json.RawMessage, polled mcpConfirmationPollResult, d agentguard.Decision, policyID string) {
	if len(polled.Body) > 0 {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Connection", "close")
		w.WriteHeader(polled.HTTPStatus)
		_, _ = w.Write(polled.Body)
		return
	}
	code, message, data := mcpConfirmationOutcomeError(polled, d, policyID)
	writeMCPJSONRPCErrorWithData(w, id, code, message, data)
}

// writeHeldMCPConfirmationSSE 挂起模式的 SSE 形态：先发响应头，等待期间每 keepalive 发一条
// 注释行保活，结束时以单个 message 事件写出结果或 JSON-RPC 错误。
func writeHeldMCPConfirmationSSE(w http.ResponseWriter, id json.RawMessage, d agentguard.Decision, policyID string, wait func() mcpConfirmationPollResult, keepalive time.Duration) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "close")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	flush := func() {
		if flusher != nil {
			flusher.Flush()
		}
	}
	flush()
	done := make(chan mcpConfirmationPollResult, 1)
	go func() { done <- wait() }()
	ticker := time.NewTicker(keepalive)
	defer ticker.Stop()
	var polled mcpConfirmationPollResult
	for waiting := true; waiting; {
		select {
		case polled = <-done:
			waiting = false
		case <-ticker.C:
			_, _ = w.Write([]byte(": awaiting-confirmation\n\n"))
			flush()
		}
	}
	payload := polled.Body
	if len(payload) == 0 {
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		code, message, data := mcpConfirmationOutcomeError(polled, d, policyID)
		payload, _ = mcpMarshalNoEscape(map[string]any{
			"jsonrpc": "2.0", "id": id,
			"error": map[string]any{"code": code, "message": message, "data": data},
		})
	}
	var event strings.Builder
	event.WriteString("event: message\n")
	for _, line := range strings.Split(strings.TrimSpace(string(payload)), "\n") {
		event.WriteString("data: " + line + "\n")
	}
	event.WriteString("\n")
	_, _ = w.Write([]byte(event.String()))
	flush()
}
