package handler

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
	"strings"
)

type proxySemanticTask struct {
	Text     string
	Hash     string
	Status   string
	Complete bool
	Enabled  bool
}

type contextualSourceGroup struct {
	Message ConvMessage
	Task    proxySemanticTask
}

func proxyContextualSource(source string) bool {
	switch source {
	case "tool_result", "rag", "rag_context", "retrieval", "retrieval_result", "web", "web_content", "email", "attachment", "file_attachment", "assistant_tool_call":
		return true
	default:
		return false
	}
}

func groupSourcesWithTasks(messages []ConvMessage) []contextualSourceGroup {
	groups := make([]contextualSourceGroup, 0, 6)
	indices := map[string]int{}
	tasks := semanticTasksForSourceMessages(messages)
	for position, m := range messages {
		if strings.TrimSpace(m.Content) == "" {
			continue
		}
		task := tasks[position]
		key := m.Source
		if task.Enabled {
			key += "\x00semantic-task-v1:" + task.Status + ":" + task.Hash
		}
		if i, ok := indices[key]; ok {
			groups[i].Message.Content += "\n" + m.Content
		} else {
			indices[key] = len(groups)
			groups = append(groups, contextualSourceGroup{Message: m, Task: task})
		}
	}
	return groups
}

func semanticTasksForSourceMessages(messages []ConvMessage) []proxySemanticTask {
	tasks := semanticCausalTasksForSourceMessages(messages)
	for i, message := range messages {
		if !proxyContextualSource(message.Source) {
			tasks[i] = proxySemanticTask{}
		}
	}
	return tasks
}

func semanticCausalTasksForSourceMessages(messages []ConvMessage) []proxySemanticTask {
	tasks := make([]proxySemanticTask, len(messages))
	current := proxySemanticTask{Enabled: true, Status: "missing"}
	for position, m := range messages {
		if (m.Source == "user" || m.Source == "verified_user_input") && strings.TrimSpace(m.Content) != "" {
			current = proxySemanticTask{Text: m.Content, Hash: scanfp.SHA256Hex(m.Content), Status: "complete", Complete: true, Enabled: true}
			if len(m.Content) > 8192 {
				current.Text = ""
				current.Status = "too_large"
				current.Complete = false
			}
		}
		tasks[position] = current
	}
	return tasks
}

func populateSemanticTaskContexts(extracted *ExtractedContent) {
	tasks := semanticCausalTasksForSourceMessages(extracted.Messages)
	extracted.SemanticTaskContexts = make(map[string]proxySemanticTask, len(tasks))
	extracted.SemanticAttachmentTaskContexts = make(map[string]proxySemanticTask, len(tasks))
	for i, message := range extracted.Messages {
		task := proxySemanticTask{}
		if proxyContextualSource(message.Source) {
			task = tasks[i]
		}
		extracted.SemanticTaskContexts[semanticSourceTaskKey(message)] = task
		if key := semanticAttachmentTaskKey(message); key != "" {
			extracted.SemanticAttachmentTaskContexts[key] = tasks[i]
		}
	}
}

func semanticSourceTaskKey(message ConvMessage) string {
	key, _ := json.Marshal([]any{message.SourcePath, message.MessageIndex, message.Role, message.Source, message.Content})
	return scanfp.SHA256Hex(string(key))
}

func semanticAttachmentTaskKey(message ConvMessage) string {
	if message.MessageIndex == nil && message.SourcePath == "" {
		return ""
	}
	source := message.Source
	if source == "user_history" {
		source = "user"
	}
	key, _ := json.Marshal([]any{message.SourcePath, message.MessageIndex, message.Role, source})
	return scanfp.SHA256Hex(string(key))
}

func attachmentInspectionMessage(attachment ExtractedAttachment) ConvMessage {
	source := attachment.ContentSource
	if source == "" {
		source = "unknown"
	}
	if source == "user" && attachment.InspectionIsHistory {
		source = "user_history"
	}
	return ConvMessage{
		Source: source, Role: attachment.MessageRole, MessageIndex: attachment.MessageIndex,
		SourcePath: attachment.SourcePath, InspectionIsHistory: attachment.InspectionIsHistory,
		IsLatestUser: attachment.IsLatestUser,
	}
}

func proxyContextWithTask(base interface{}, task proxySemanticTask) map[string]interface{} {
	result := map[string]interface{}{}
	if values, ok := base.(map[string]interface{}); ok {
		for k, v := range values {
			result[k] = v
		}
	}
	// Reserved context is derived only from the decoded protocol user turns.
	for _, k := range []string{"user_task", "user_task_complete", "user_task_status", "user_task_sha256"} {
		delete(result, k)
	}
	if task.Enabled {
		result["user_task"] = task.Text
		result["user_task_complete"] = task.Complete
		result["user_task_status"] = task.Status
		result["user_task_sha256"] = task.Hash
	}
	return result
}
