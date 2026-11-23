package handler

// W1 1.8：服务端发起的反向请求（sampling/createMessage、elicitation/create、roots/list 等）
// 按策略允许/拒绝/审计。
//
// Streamable HTTP 下，服务端可以在 POST 响应的 SSE 流或 GET 长流里向客户端发 JSON-RPC 请求。
// 基线把它们原样透传，管理员无法约束「上游借客户端的模型/用户输入做事」。现在：
//   - 每个带 id 的服务端请求按方法名查 target_kind=method 策略（与 1.2 同一套策略、同一口径）；
//   - 防护模式且策略生效 block：该事件从客户端流中删除，网关替客户端向上游回一条标准
//     JSON-RPC 错误（-32000），上游不会因等不到响应而挂起；
//   - 未配置拒绝 / 记录模式：原样放行，留痕（tool_call_logs，展示名 <server>__method:<方法>）；
//   - 通知（无 id）、ping 与 notifications/* 不判定。
// 重复或仅大小写不同的 method 键：所有候选方法都判定，任一被拒即删除。

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

const mcpServerRequestReplyTimeout = 10 * time.Second

type mcpServerRequestGuard struct {
	h          *MCPProxyHandler
	ctx        context.Context
	envelope   *modelrouter.RequestEnvelope
	server     *mcpServerRoute
	inbound    *http.Request
	callerMode agentguard.Mode
	auditOnly  bool
	// recorded 是本次流中出现的全部服务端请求决策，流结束后并入审计。
	recorded []mcpToolCallDecision
	// discardAll：整条流会被丢弃（通知收到了非预期的响应流，L-1）。不论策略如何，反向请求一律按「已丢弃」记审计并回拒绝。
	discardAll bool
}

// newMCPServerRequestGuard：未配置策略客户端时返回 nil（与基线一致，原样透传）。
func (h *MCPProxyHandler) newMCPServerRequestGuard(ctx context.Context, envelope *modelrouter.RequestEnvelope, server *mcpServerRoute, inbound *http.Request, callerMode agentguard.Mode, auditOnly bool) *mcpServerRequestGuard {
	if h == nil || h.toolRiskClient == nil || server == nil {
		return nil
	}
	return &mcpServerRequestGuard{h: h, ctx: ctx, envelope: envelope, server: server, inbound: inbound, callerMode: callerMode, auditOnly: auditOnly}
}

// sseEvent 处理一个完整 SSE 事件：返回 nil 表示整个事件从客户端流中删除。
func (g *mcpServerRequestGuard) sseEvent(event []byte) []byte {
	if g == nil {
		return event
	}
	payload, ok := mcpSSEEventData(event)
	if !ok || !bytes.Contains(bytes.ToLower(payload), []byte("method")) {
		return event
	}
	trimmed := bytes.TrimSpace(payload)
	var items []json.RawMessage
	switch {
	case len(trimmed) > 0 && trimmed[0] == '{':
		items = []json.RawMessage{trimmed}
	case len(trimmed) > 0 && trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return event
		}
	default:
		return event
	}
	drop := false
	for _, item := range items {
		if g.judge(bytes.TrimSpace(item)) {
			drop = true
		}
	}
	if drop {
		return nil
	}
	return event
}

// judge 判定一条服务端消息；返回 true 表示需要从客户端流删除（已替客户端回错误）。
func (g *mcpServerRequestGuard) judge(item []byte) bool {
	if len(item) == 0 || item[0] != '{' {
		return false
	}
	methods, id, ok := mcpServerRequestFields(item)
	if !ok || len(methods) == 0 {
		return false
	}
	blocked := false
	var blockedBy *mcpToolCallDecision
	for _, method := range methods {
		msg := mcpRPCMessage{JSONRPC: "2.0", ID: id, Method: method}
		kind, name, judged := mcpPolicyTarget(msg)
		if !judged {
			continue
		}
		d := g.h.decideMCPNonToolTarget(g.ctx, g.envelope, g.server, msg, kind, name, g.callerMode)
		d.ServerInitiated = true
		d.Qualified = mcpTargetAuditName(g.server.Name, mcpTargetMethod, name)
		enforce := securityexit.Decide(
			securityexit.ModeFromAuditOnly(g.auditOnly),
			string(d.Decision.EffectiveDecision),
			securityexit.ToolPolicy,
		).Enforce || g.discardAll
		if enforce {
			blocked = true
			d.OutcomeStatus = "blocked"
			d.ExecutionForwarded = false
		} else {
			d.OutcomeStatus = "success"
			d.ExecutionForwarded = true
		}
		g.recorded = append(g.recorded, d)
		if enforce && blockedBy == nil {
			blockedBy = &g.recorded[len(g.recorded)-1]
		}
	}
	if !blocked {
		return false
	}
	// 同一消息里其余候选也不会被客户端看到。
	for i := range g.recorded {
		if key, ok := mcpRPCIDKey(g.recorded[i].Message.ID); ok {
			if idKey, _ := mcpRPCIDKey(id); key == idKey {
				g.recorded[i].ExecutionForwarded = false
				if g.recorded[i].OutcomeStatus == "success" {
					g.recorded[i].OutcomeStatus = "blocked"
				}
			}
		}
	}
	g.replyRejection(id, blockedBy)
	return true
}

// replyRejection 替客户端向上游回一条 JSON-RPC 错误，避免上游一直等客户端响应。
func (g *mcpServerRequestGuard) replyRejection(id json.RawMessage, d *mcpToolCallDecision) {
	policyID := ""
	method := ""
	if d != nil {
		policyID, method = d.PolicyID, d.ToolName
	}
	message := "网关安全策略拒绝了该服务端请求"
	if g.discardAll {
		message = "网关不接受通知的响应流中的服务端请求"
	}
	if method != "" {
		message += "（" + method + "）"
	}
	if policyID != "" {
		message += "，策略 " + policyID
	}
	body, err := mcpMarshalNoEscape(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": -32000, "message": message},
	})
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(g.ctx), mcpServerRequestReplyTimeout)
	defer cancel()
	synthetic := g.inbound.Clone(ctx)
	synthetic.Method = http.MethodPost
	synthetic.Body = http.NoBody
	resp, _, err := g.h.forwardMCPUpstream(ctx, g.server, synthetic, body)
	if err != nil {
		log.Printf("MCP 服务端请求拒绝回执发送失败 (server=%s): %v", g.server.ID, err)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}

// mcpServerRequestFields 取服务端消息的 id 与全部候选方法名（大小写不敏感的 method 键、
// 含重复键的每一个值）。无合法 id（通知）或不是对象时 ok=false。
func mcpServerRequestFields(item []byte) ([]string, json.RawMessage, bool) {
	dec := json.NewDecoder(bytes.NewReader(item))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, nil, false
	}
	var methods []string
	var id json.RawMessage
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, nil, false
		}
		key, _ := kt.(string)
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, nil, false
		}
		switch {
		case strings.EqualFold(key, "method"):
			var method string
			if json.Unmarshal(value, &method) == nil {
				methods = append(methods, method)
			}
		case key == "id":
			id = append(json.RawMessage(nil), value...)
		}
	}
	if _, ok := mcpRPCIDKey(id); !ok {
		return nil, nil, false
	}
	return methods, id, true
}

// mcpSSEEventData 拼接一个 SSE 事件的全部 data 行。
func mcpSSEEventData(event []byte) ([]byte, bool) {
	normalized := strings.ReplaceAll(string(event), "\r\n", "\n")
	var data []string
	for _, line := range strings.Split(normalized, "\n") {
		if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if len(data) == 0 {
		return nil, false
	}
	return []byte(strings.Join(data, "\n")), true
}

// mcpComposeSSETransforms 串联事件级处理；任一环节返回 nil（删除事件）即停止。
func mcpComposeSSETransforms(transforms ...func([]byte) []byte) func([]byte) []byte {
	var active []func([]byte) []byte
	for _, t := range transforms {
		if t != nil {
			active = append(active, t)
		}
	}
	if len(active) == 0 {
		return nil
	}
	return func(event []byte) []byte {
		for _, t := range active {
			event = t(event)
			if event == nil {
				return nil
			}
		}
		return event
	}
}

func (g *mcpServerRequestGuard) sseTransform() func([]byte) []byte {
	if g == nil {
		return nil
	}
	return g.sseEvent
}

func (rs mcpPayloadRewriters) sseTransform() func([]byte) []byte {
	if len(rs) == 0 {
		return nil
	}
	return rs.sseEvent
}

func (g *mcpServerRequestGuard) decisions() []mcpToolCallDecision {
	if g == nil {
		return nil
	}
	return g.recorded
}
