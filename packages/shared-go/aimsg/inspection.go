package aimsg

import (
	"fmt"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

func anchorMessages(messages []ConvMessage, index int, collection string) {
	for i := range messages {
		messages[i].MessageIndex = &index
		if messages[i].SourcePath == "" {
			messages[i].SourcePath = fmt.Sprintf("/%s/%d", collection, index)
		}
	}
}

// LatestUserPosition uses the wire role/source, never the retention envelope projection.
func LatestUserPosition(messages []ConvMessage) int {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Source == SourceUser && (strings.TrimSpace(messages[i].Content) != "" || messages[i].HasAttachments) {
			return i
		}
	}
	return -1
}

// LatestUserTask keeps all user text blocks from the same original wire message.
func LatestUserTask(messages []ConvMessage) string {
	latest := LatestUserPosition(messages)
	var parts []string
	for i, m := range messages {
		if IsLatestUser(messages, i, latest) && m.Content != "" {
			parts = append(parts, m.Content)
		}
	}
	runes := []rune(strings.Join(parts, "\n"))
	if len(runes) > 4096 {
		runes = runes[:4096]
	}
	return string(runes)
}

func IsLatestUser(messages []ConvMessage, index, latest int) bool {
	if index < 0 || index >= len(messages) || latest < 0 || messages[index].Source != SourceUser {
		return false
	}
	if index == latest {
		return true
	}
	a, b := messages[index].MessageIndex, messages[latest].MessageIndex
	return a != nil && b != nil && *a == *b
}

func SelectInspectionMessages(messages []ConvMessage, policy inspectionscope.Policy) []ConvMessage {
	latest := LatestUserPosition(messages)
	selected := make([]ConvMessage, 0, len(messages))
	for i, message := range messages {
		message.InspectionIsHistory = InspectionIsHistory(messages, i, latest)
		message.IsLatestUser = IsLatestUser(messages, i, latest)
		if policy.Includes(message.Source, IsLatestUser(messages, i, latest), InspectionIsHistory(messages, i, latest)) {
			if message.Source == SourceUser && !IsLatestUser(messages, i, latest) {
				message.Source = "user_history"
			}
			selected = append(selected, message)
		}
	}
	return selected
}

func InspectionIsHistory(messages []ConvMessage, index, latest int) bool {
	m := messages[index]
	switch m.Source {
	case "user_history", SourceAssistantHistory:
		return true
	case SourceUser:
		return !IsLatestUser(messages, index, latest)
	case SourceToolResult, "rag", "rag_context", "retrieval", "retrieval_result", "web_content":
		boundary := latest
		if m.Source == SourceToolResult {
			// A long autonomous agent task can have hundreds of tool rounds
			// without another user message. Only the latest tool response batch
			// is current; previous rounds must respect the history switch.
			for i := len(messages) - 1; i > boundary; i-- {
				if messages[i].Source == SourceAssistantHistory {
					boundary = i
					break
				}
			}
		}
		if boundary < 0 {
			return false
		}
		if m.MessageIndex != nil && messages[boundary].MessageIndex != nil {
			return *m.MessageIndex < *messages[boundary].MessageIndex
		}
		return index < boundary
	default:
		return false
	}
}

// JudgmentContext is bounded quoted data. It must never be scanned as an alert target.
// Keep recent excluded messages, in wire order, without altering their provenance.
func JudgmentContext(messages []ConvMessage, policy inspectionscope.Policy) []map[string]any {
	latest := LatestUserPosition(messages)
	var context []map[string]any
	remaining := 16384
	for i := len(messages) - 1; i >= 0 && remaining > 0 && len(context) < 32; i-- {
		m := messages[i]
		if policy.Includes(m.Source, IsLatestUser(messages, i, latest), InspectionIsHistory(messages, i, latest)) || m.Content == "" {
			continue
		}
		runes := []rune(m.Content)
		truncated := len(runes) > remaining
		if truncated {
			runes = runes[:remaining]
		}
		remaining -= len(runes)
		source := m.Source
		if source == SourceUser && !IsLatestUser(messages, i, latest) {
			source = "user_history"
		}
		item := map[string]any{"content": string(runes), "content_source": source, "message_role": m.Role, "inspection_is_history": InspectionIsHistory(messages, i, latest), "alert_target": false, "truncated": truncated}
		if m.MessageIndex != nil {
			item["message_index"] = *m.MessageIndex
		}
		if m.SourcePath != "" {
			item["source_path"] = m.SourcePath
		}
		context = append(context, item)
	}
	for i, j := 0, len(context)-1; i < j; i, j = i+1, j-1 {
		context[i], context[j] = context[j], context[i]
	}
	return context
}
