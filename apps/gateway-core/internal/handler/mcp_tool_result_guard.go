package handler

// W1 1.7：tools/call 工具返回的间接注入检测。
//
// 工具返回的文本会被客户端原样喂回模型，是间接提示注入的主要入口。网关对每条归属到
// 本次 tools/call 的 JSON-RPC result 抽取全部字符串值（按 token 遍历，重复键两份都看），
// 以 content_source=tool_result 交 security-engine 检测：
//   - 防护模式且引擎给出阻断类动作：该 result 替换为同 id 的 -32000 错误；
//   - 记录模式或非阻断动作：原样放行，只留证据；
//   - inspection failure: apply the guardrail fail policy and record a coverage gap.
// 流式响应经 copyMCPSSEEvents 按完整事件缓冲（容量上限与 validateAndCopyMCPSSE 相同），
// 结果帧完整后才检测、才写出；进度通知等其他帧不受影响。
// 未配置检测器（SetToolResultChecker 未调用）时行为与基线完全一致。

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// mcpToolResultInspectMaxBytes 单条工具返回送检文本上限；超出部分不检测并记覆盖缺口。
const mcpToolResultInspectMaxBytes = 256 << 10

// mcpToolResultSkipKeys 是二进制/枚举类字段，其值不是给模型读的自然语言，不送检。
var mcpToolResultSkipKeys = map[string]bool{"data": true, "blob": true, "mimeType": true, "type": true}

// mcpToolResultChecker 是检测工具返回所需的最小面（*RealSecurityChecker 满足）。
type mcpToolResultChecker interface {
	CheckInput(ctx context.Context, envelope *modelrouter.RequestEnvelope, content string, messageIndex int, messageRole string, contentSource string) (action string, maskedContent string, findings []SecurityFinding, err error)
}

// SetToolResultChecker 启用工具返回检测；传 nil 关闭。需在 cmd/server/main.go 接线。
func (h *MCPProxyHandler) SetToolResultChecker(checker mcpToolResultChecker) {
	if h == nil {
		return
	}
	h.toolResultChecker = checker
}

type mcpToolResultGuard struct {
	ctx       context.Context
	checker   mcpToolResultChecker
	envelope  *modelrouter.RequestEnvelope
	decisions []mcpToolCallDecision
	indexByID map[string]int
	mode      securityexit.Mode
	policy    securityexit.Policy
	serverID  string
}

// prepareMCPToolResultGuard：请求含 tools/call 且配置了检测器时构造，否则返回 nil。
func (h *MCPProxyHandler) prepareMCPToolResultGuard(ctx context.Context, envelope *modelrouter.RequestEnvelope, server *mcpServerRoute, decisions []mcpToolCallDecision, auditOnly bool) *mcpToolResultGuard {
	if h == nil || h.toolResultChecker == nil {
		return nil
	}
	indexByID := make(map[string]int)
	for i := range decisions {
		if kind := decisions[i].TargetKind; kind != "" && kind != mcpTargetTool {
			continue
		}
		if key, ok := mcpRPCIDKey(decisions[i].Message.ID); ok {
			indexByID[key] = i
		}
	}
	if len(indexByID) == 0 {
		return nil
	}
	serverID := ""
	if server != nil {
		serverID = server.ID
	}
	return &mcpToolResultGuard{
		ctx: ctx, checker: h.toolResultChecker, envelope: envelope, decisions: decisions,
		indexByID: indexByID, mode: securityexit.ModeFromAuditOnly(auditOnly), serverID: serverID,
		policy: guardrailPolicy(ctx, h.toolRiskClient),
	}
}

func (g *mcpToolResultGuard) payloadRewriter() func([]byte) []byte {
	if g == nil {
		return nil
	}
	return g.rewritePayload
}

// rewritePayload 处理一条 JSON-RPC 载荷（对象或数组）；需要拦截时替换对应 result。
func (g *mcpToolResultGuard) rewritePayload(payload []byte) []byte {
	if g == nil {
		return payload
	}
	trimmed := bytes.TrimSpace(payload)
	if len(trimmed) == 0 {
		return payload
	}
	switch trimmed[0] {
	case '{':
		if out, changed := g.rewriteObject(trimmed); changed {
			return out
		}
		return payload
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return payload
		}
		changed := false
		for i, item := range items {
			if out, ok := g.rewriteObject(bytes.TrimSpace(item)); ok {
				items[i] = out
				changed = true
			}
		}
		if !changed {
			return payload
		}
		out, err := mcpMarshalNoEscape(items)
		if err != nil {
			return payload
		}
		return out
	default:
		return payload
	}
}

func (g *mcpToolResultGuard) rewriteObject(raw []byte) ([]byte, bool) {
	if len(raw) == 0 || raw[0] != '{' {
		return nil, false
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, false
	}
	if _, isRequest := obj["method"]; isRequest {
		return nil, false
	}
	key, ok := mcpRPCIDKey(obj["id"])
	if !ok {
		return nil, false
	}
	index, ok := g.indexByID[key]
	if !ok {
		return nil, false
	}
	// 任何大小写形式的 result 键都算结果（客户端解析器可能大小写不敏感），整对象遍历送检。
	hasResult := false
	for k := range obj {
		if strings.EqualFold(k, "result") {
			hasResult = true
			break
		}
	}
	if !hasResult {
		return nil, false
	}
	text, truncated := mcpToolResultText(raw)
	d := &g.decisions[index]
	if truncated {
		outcome := securityexit.Decide(g.mode, "block", securityexit.Capacity)
		d.Decision.Evidence = append(d.Decision.Evidence, agentguard.Evidence{
			RuleID: "mcp_tool_result_truncated", Category: "coverage_gap", Length: mcpToolResultInspectMaxBytes,
		})
		log.Printf("MCP 工具返回超过送检上限，仅检测前 %d 字节 (server=%s gap=%v)", mcpToolResultInspectMaxBytes, g.serverID, outcome.Gap)
	}
	if strings.TrimSpace(text) == "" {
		return nil, false
	}
	action, _, findings, err := g.checker.CheckInput(g.ctx, g.envelope, text, 0, "tool", "tool_result")
	if err != nil {
		cause := securityexit.FailureCause(err)
		outcome := securityexit.DecideWithPolicy(g.mode, "block", cause, g.policy)
		// 客户端在工具返回检测期间断开（Esc / 中断）不是检测失败。g.ctx 是 HandlePost 里
		// context.WithTimeout(r.Context(), ...) 的派生 ctx，父 ctx 取消时 Err() 必为 Canceled；
		// 30 分钟总超时到期是 DeadlineExceeded，不算断开。
		// 数据面字节保持不变（宁可替换也不把未扫描的工具结果原样放出，哪怕连接已断），
		// 只改标签：不追加 mcp_tool_result_unverified 证据，不置 ToolResultEnforced /
		// ToolResultCapacityRejected，因此不会产生 mcp_tool_result_blocked 事件，也不会把状态码改成 503。
		clientGone := clientGoneDuring(g.ctx, err)
		if clientGone {
			log.Printf("MCP tool result inspection aborted: client disconnected (server=%s enforced=%v): %v", g.serverID, outcome.Enforce, err)
		} else {
			d.Decision.Evidence = append(d.Decision.Evidence, agentguard.Evidence{
				RuleID: "mcp_tool_result_unverified", Category: "coverage_gap",
			})
			log.Printf("MCP tool result inspection failed (server=%s gap=%v enforced=%v): %v", g.serverID, outcome.Gap, outcome.Enforce, err)
		}
		if outcome.Enforce {
			if !clientGone {
				d.ToolResultEnforced = true
				d.ToolResultCapacityRejected = cause == securityexit.Capacity
			}
			out, marshalErr := mcpMarshalNoEscape(map[string]any{
				"jsonrpc": "2.0", "id": obj["id"],
				"error": map[string]any{"code": -32000, "message": "MCP tool result could not be verified; fail-closed policy rejected it"},
			})
			return out, marshalErr == nil
		}
		return nil, false
	}
	if len(findings) == 0 && !securityexit.Blocks(action) {
		return nil, false
	}
	outcome := securityexit.Decide(g.mode, action, securityexit.RuleHit)
	for _, f := range findings {
		ruleID := f.RuleID
		if ruleID == "" {
			ruleID = f.Type
		}
		d.ToolResultFindings = append(d.ToolResultFindings, ruleID)
		if len(d.Decision.Evidence) >= mcpToolsListDropEvidenceLimit {
			continue
		}
		d.Decision.Evidence = append(d.Decision.Evidence, agentguard.Evidence{
			RuleID: ruleID, Category: f.Category, SourceField: "result",
			MaskedPreview: truncateMCPUTF8(f.RedactedEvidence, 64),
		})
	}
	if len(findings) == 0 {
		d.ToolResultFindings = append(d.ToolResultFindings, "mcp_tool_result_"+strings.ToLower(action))
	}
	d.ToolResultWouldBlock = d.ToolResultWouldBlock || securityexit.Blocks(action)
	log.Printf("MCP 工具返回命中安全检测 (server=%s action=%s enforced=%v findings=%v)", g.serverID, action, outcome.Enforce, d.ToolResultFindings)
	if !outcome.Enforce {
		return nil, false
	}
	d.ToolResultEnforced = true
	out, err := mcpMarshalNoEscape(map[string]any{
		"jsonrpc": "2.0",
		"id":      obj["id"],
		"error": map[string]any{
			"code":    -32000,
			"message": "MCP 工具返回内容命中安全检测（疑似间接注入），已被网关拦截",
		},
	})
	if err != nil {
		return nil, false
	}
	return out, true
}

// mcpRewriteSSEBody 对已完整读入内存的 SSE 响应体逐事件改写（审批重放路径用）。
func mcpRewriteSSEBody(body []byte, rewrite func([]byte) []byte) []byte {
	var out bytes.Buffer
	if err := copyMCPSSEEvents(&out, nil, bytes.NewReader(body), func(event []byte) []byte {
		return mcpRewriteSSEEvent(event, rewrite)
	}); err != nil {
		return body
	}
	return out.Bytes()
}

// mcpToolResultText 按 token 遍历整个响应对象，拼接全部字符串值（跳过二进制/枚举字段）。
// 重复键与大小写变体键的值都会被收集，避免「网关看一份、客户端读另一份」。
func mcpToolResultText(raw []byte) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var b strings.Builder
	truncated := false
	add := func(s string) {
		if truncated || s == "" {
			return
		}
		if b.Len()+len(s)+1 > mcpToolResultInspectMaxBytes {
			room := mcpToolResultInspectMaxBytes - b.Len() - 1
			if room > 0 {
				b.WriteString(truncateMCPUTF8(s, room))
				b.WriteByte('\n')
			}
			truncated = true
			return
		}
		b.WriteString(s)
		b.WriteByte('\n')
	}
	var walk func(key string) error
	walk = func(key string) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch v := tok.(type) {
		case json.Delim:
			switch v {
			case '{':
				for dec.More() {
					kt, err := dec.Token()
					if err != nil {
						return err
					}
					k, _ := kt.(string)
					if err := walk(k); err != nil {
						return err
					}
				}
				_, err = dec.Token()
				return err
			case '[':
				for dec.More() {
					if err := walk(key); err != nil {
						return err
					}
				}
				_, err = dec.Token()
				return err
			}
		case string:
			if !mcpToolResultSkipKeys[key] && key != "jsonrpc" {
				add(v)
			}
		}
		return nil
	}
	if err := walk(""); err != nil && err != io.EOF {
		// 非法 JSON：退化为整段原文送检，宁可多看不可漏看。
		b.Reset()
		truncated = len(raw) > mcpToolResultInspectMaxBytes
		b.WriteString(truncateMCPUTF8(string(raw), mcpToolResultInspectMaxBytes))
	}
	return b.String(), truncated
}
