package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

// toolFailureLoopCategory 是工具连续失败的运行事件类别。控制面据此把它归入运行告警，
// 不进入安全告警的「需行动 / 观察」。
const toolFailureLoopCategory = "agent_tool_failure_loop"

// toolFailureLoopFinding 描述“智能体反复重试同一个失败的工具”。这是运行状况，不是安全风险：
// 不计入安全命中，作为必须留证的观察写入。
func toolFailureLoopFinding(toolName string, count int) SecurityFinding {
	counts := false
	return SecurityFinding{
		Type:                    agentguard.ToolFailureLoopReason,
		Category:                toolFailureLoopCategory,
		Severity:                "low",
		RuleName:                toolName,
		RuleType:                "agentguard",
		Action:                  "audit",
		MatchedLocation:         "tool_result",
		ContentSource:           "tool_result",
		EvidenceKind:            "runtime",
		CountsAsSecurityFinding: &counts,
		RedactedEvidence:        fmt.Sprintf("%s 在窗口内失败 %d 次", toolName, count),
		Triage: map[string]any{
			"disposition":        "observation",
			"disposition_reason": toolFailureLoopCategory,
		},
	}
}

// failedToolCall 是本轮一个失败的工具调用。name 是 ToolCalls 里的原名（与出向升级查找一致），
// target 是去重键：调用编号 + 本轮之前历史的指纹。
type failedToolCall struct {
	name   string
	target string
}

// toolFailuresThisTurn 取出本轮结果里失败的工具调用，按出现顺序返回。
// “本轮”= 消息末尾之前最后一段连续的 assistant 消息块：原生 /v1/messages 把一个 tool_use 拆成
// “带 ToolCalls 的参数消息 + 只含工具名的消息”两条，Responses 路径把每个 function_call 各转成一条，
// 它们都落在同一块里。块内没有 ToolCalls（纯文字回答）则没有本轮结果。
// 本轮结果 = 块之后的 tool/function 消息；同一调用编号只算一次（多内容块的结果会拆成同编号多条）。
// target = 编号@块之前历史的指纹：客户端原样重发同一请求时键相同，会被滑窗去重；
// 下一轮历史变长、指纹不同，Gemini 跨轮合成的相同编号（call_0_0）仍会各自计数。
//
// 已知少计（只少计，不会误升级）：
//   - Responses 路径按“调用、结果、调用、结果”交错排列时，只有最后一个调用算本轮；
//   - 结果之后紧跟 assistant 预填时，本轮不计；
//   - 一个请求里首次看到多轮结果（如重启后的第一个请求）只计最后一轮。
func toolFailuresThisTurn(messages []Message) []failedToolCall {
	last := -1
	for i := len(messages) - 1; i >= 0; i-- {
		if strings.ToLower(strings.TrimSpace(messages[i].Role)) == "assistant" {
			last = i
			break
		}
	}
	if last < 0 || last == len(messages)-1 {
		return nil
	}
	start := last
	for start > 0 && strings.ToLower(strings.TrimSpace(messages[start-1].Role)) == "assistant" {
		start--
	}
	namesByID := make(map[string]string)
	for _, message := range messages[start : last+1] {
		for _, tc := range message.ToolCalls {
			id := strings.TrimSpace(tc.ID)
			if id == "" || strings.TrimSpace(tc.Function.Name) == "" {
				continue
			}
			namesByID[id] = tc.Function.Name
		}
	}
	if len(namesByID) == 0 {
		return nil
	}
	prefix := ""
	var order []failedToolCall
	failed := make(map[string]bool)
	for _, message := range messages[last+1:] {
		role := strings.ToLower(strings.TrimSpace(message.Role))
		id := strings.TrimSpace(message.ToolCallID)
		if (role != "tool" && role != "function") || id == "" {
			continue
		}
		name, ok := namesByID[id]
		if !ok || failed[id] {
			continue
		}
		if !message.ToolResultError && !agentguard.ToolResultLooksLikeFailure(messageText(message.Content)) {
			continue
		}
		if prefix == "" {
			// 前缀指纹只在出现第一个失败时算一次：绝大多数请求没有失败，不付出 O(历史大小) 的哈希开销。
			prefix = messagesFingerprint(messages[:start])
		}
		failed[id] = true
		order = append(order, failedToolCall{name: name, target: id + "@" + prefix})
	}
	return order
}

// messagesFingerprint 对一段历史算 sha256 并取前 16 个十六进制字符。
// 字段间用 0x00/0x01 分隔，避免拼接歧义。
func messagesFingerprint(messages []Message) string {
	h := sha256.New()
	field := func(b []byte) {
		h.Write(b)
		h.Write([]byte{0})
	}
	for _, m := range messages {
		switch strings.ToLower(strings.TrimSpace(m.Role)) {
		case "system", "developer":
			// 排除系统提示：客户端每次请求会重新渲染（如带当前时间），不排除的话同一轮重发会被当成新一轮。
			// 客户端截断/压缩历史后重试同一轮仍可能多计 1 次，上限很低，可接受。
			continue
		}
		field([]byte(m.Role))
		field([]byte(m.ToolCallID))
		field(m.Content)
		for _, tc := range m.ToolCalls {
			field([]byte(tc.ID))
			field([]byte(tc.Function.Name))
			field([]byte(tc.Function.Arguments))
		}
		h.Write([]byte{1})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}
