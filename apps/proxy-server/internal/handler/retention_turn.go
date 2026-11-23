package handler

import (
	"github.com/yangjiyj/aiguard/packages/shared-go/retentionfmt"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
	"github.com/yangjiyj/aiguard/packages/shared-go/aimsg"
)

// lastRetainedUserTurnIndex 返回最近一条「完整用户文本」消息的下标；没有则 -1。
// 「完整」= NormalizeAgentEnvelope 判定 ParseComplete 且正文非空——匹配但残缺的信封是歧义的，
// 不能拿原始机器内容顶替（见 aimsg.NormalizeAgentEnvelope 的契约）。
func lastRetainedUserTurnIndex(messages []ConvMessage) int {
	for index := len(messages) - 1; index >= 0; index-- {
		message := messages[index]
		if message.Source != aimsg.SourceUser {
			continue
		}
		content, status, _ := aimsg.NormalizeAgentEnvelope(message.Content)
		if status == aimsg.ParseComplete && strings.TrimSpace(content) != "" {
			return index
		}
	}
	return -1
}

func retainedUserTurnText(messages []ConvMessage) string {
	index := lastRetainedUserTurnIndex(messages)
	if index < 0 {
		return ""
	}
	content, _, _ := aimsg.NormalizeAgentEnvelope(messages[index].Content)
	return strings.TrimSpace(content)
}

// retainedRequestText 返回留证用请求文本的两部分：
//   - userText：最近一条完整用户文本，与 retainedUserTurnText 逐字节一致；
//   - toolSections：该用户消息之后尾巴里的工具段（工具结果消息各一段、助手历史里的
//     [tool_use:…] 行合成一段），每段已带【工具】前缀、内部空行已归并，前端可整段折叠。
//
// 找不到完整用户文本时两者都为空——增量式 API（只发 function_call_output）不凭空造用户消息。
func retainedRequestText(messages []ConvMessage) (string, []string) {
	index := lastRetainedUserTurnIndex(messages)
	if index < 0 {
		return "", nil
	}
	content, _, _ := aimsg.NormalizeAgentEnvelope(messages[index].Content)
	var sections []string
	for _, message := range messages[index+1:] {
		switch message.Source {
		case aimsg.SourceToolResult:
			appendRetainedToolSection(&sections, message.Content)
		case aimsg.SourceAssistantHistory:
			// 助手历史里的普通文本不重复留（响应侧已有），只捞这一轮提出的工具调用。
			var lines []string
			for _, line := range strings.Split(retentionfmt.NormalizeNewlines(message.Content), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "[tool_use:") {
					lines = append(lines, trimmed)
				}
			}
			if len(lines) > 0 {
				appendRetainedToolSection(&sections, strings.Join(lines, "\n"))
			}
		}
	}
	return strings.TrimSpace(content), sections
}

// retainedResponseToolSections 从响应原始文本里挑出模型提出的工具调用行，渲染成【工具】段。
// 只认 `[tool_use:…]` 行与带 `[tool] ` 前缀的行（后者剥掉前缀）；`[reasoning]` 行不入留证
// ——推理内容是模型私有过程，与既有 VisibleText 口径一致。
func retainedResponseToolSections(text string) []string {
	var sections []string
	for _, line := range strings.Split(retentionfmt.NormalizeNewlines(text), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[tool] ") {
			appendRetainedToolSection(&sections, strings.TrimSpace(strings.TrimPrefix(trimmed, "[tool] ")))
			continue
		}
		if strings.HasPrefix(trimmed, "[tool_use:") {
			appendRetainedToolSection(&sections, trimmed)
		}
	}
	return sections
}

func appendRetainedToolSection(sections *[]string, content string) {
	if section := retentionfmt.ToolSection(content); section != "" {
		*sections = append(*sections, section)
	}
}

// joinRetainedToolSections 把正文与工具段拼成一段留证文本：正文在前、工具段在后，段间空行分隔
// （与前端 collapseSystemSections 的分段规则对齐）。
//
// 工具尾巴超 64KB 预算时按行截断并打 ...[truncated] 标记：正文是唯一的人话证据，不能被工具
// 输出挤掉。计数在拼接前做，避免让 redactRetainedText 从尾部把标记连同证据一起砍掉。
func joinRetainedToolSections(head string, sections []string) string {
	if len(sections) == 0 {
		return head
	}
	tail := strings.Join(sections, "\n\n")
	if budget := maxAccessRetentionTextBytes - len(head) - len("\n\n"); len(tail) > budget {
		tail = truncateRetainedToolTail(tail, budget)
	}
	if strings.TrimSpace(head) == "" {
		return tail
	}
	return head + "\n\n" + tail
}

// truncateRetainedToolTail 在预算内的最后一个换行处收口：从中间切断会把一个 token（可能是密钥
// 字面值）截成两半，半截值不再匹配脱敏正则。
func truncateRetainedToolTail(tail string, budget int) string {
	const marker = "...[truncated]"
	if budget <= len(marker) {
		return marker
	}
	cut := sanitizeRetainedStorageText(tail[:budget-len(marker)])
	if end := strings.LastIndexByte(cut, '\n'); end > 0 {
		cut = cut[:end]
	}
	if strings.TrimSpace(cut) == "" {
		return marker
	}
	return cut + marker
}

func inferStructuredAgentType(messages []ConvMessage) string {
	for _, message := range messages {
		if message.Source == aimsg.SourceUser {
			if product := agentdetect.InferFromProductEnvelope(message.Content); product != "" {
				return product
			}
		}
	}
	for _, message := range messages {
		if message.Source != aimsg.SourceSystemPrompt {
			continue
		}
		if agentType := agentdetect.InferFromTrustedText(message.Content); agentType != "" {
			return agentType
		}
	}
	return ""
}

func workBuddyProxyTaskID(tenant string, messages []ConvMessage) string {
	for _, message := range messages {
		if message.Source != aimsg.SourceUser || agentdetect.InferFromProductEnvelope(message.Content) != "workbuddy" {
			continue
		}
		if workspace := retentionfmt.WorkBuddyWorkspaceFolder(message.Content); workspace != "" {
			return "run_" + hashValue(tenant + "\x00workbuddy_workspace\x00" + workspace)[:32]
		}
	}
	return ""
}
