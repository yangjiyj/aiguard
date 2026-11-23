package handler

import (
	"context"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/scanfp"
)

// Task context comes from protocol user turns, never labels embedded in tool text.
const maxSemanticTaskBytes = 8192

type semanticTaskContext struct {
	Text     string
	Hash     string
	Status   string
	Enabled  bool
	Complete bool
}

type semanticTaskContextKey struct{}

func (s semanticTaskContext) Scope() string {
	if !s.Enabled {
		return ""
	}
	return "semantic-task-v1:" + s.Status + ":" + s.Hash
}

func semanticTasksForMessages(messages []Message) []semanticTaskContext {
	result := make([]semanticTaskContext, len(messages))
	current := semanticTaskContext{Enabled: true, Status: "missing"}
	for i, message := range messages {
		switch strings.ToLower(strings.TrimSpace(message.Role)) {
		case "user":
			text := messageText(message.Content)
			if strings.TrimSpace(text) != "" {
				current = semanticTaskContext{Enabled: true, Hash: scanfp.SHA256Hex(text), Status: "complete", Complete: true, Text: text}
				if len(text) > maxSemanticTaskBytes {
					current.Text = ""
					current.Status = "too_large"
					current.Complete = false
				}
			}
			// File bodies keep the task at their owning turn, including explicit
			// missing/oversize state; a later request cannot authorize old files.
			if len(extractAttachments(message.Content)) > 0 {
				result[i] = current
			}
		case "tool", "function", "assistant":
			result[i] = current
		}
	}
	return result
}

func withSemanticTaskContext(ctx context.Context, task semanticTaskContext) context.Context {
	if !task.Enabled {
		return ctx
	}
	return context.WithValue(ctx, semanticTaskContextKey{}, task)
}

func semanticTaskFromContext(ctx context.Context) semanticTaskContext {
	if ctx == nil {
		return semanticTaskContext{}
	}
	task, _ := ctx.Value(semanticTaskContextKey{}).(semanticTaskContext)
	return task
}

func addSemanticTaskContext(ctx context.Context, target map[string]interface{}) {
	task := semanticTaskFromContext(ctx)
	if !task.Enabled {
		return
	}
	target["user_task"] = task.Text
	target["user_task_complete"] = task.Complete
	target["user_task_status"] = task.Status
	target["user_task_sha256"] = task.Hash
}
