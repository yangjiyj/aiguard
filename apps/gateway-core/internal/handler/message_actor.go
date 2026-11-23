package handler

import (
	"context"
	"strings"

	"github.com/yangjiyj/aiguard/packages/shared-go/agentdetect"
)

const orchestratorNoticeCandidate = "orchestrator_notice_candidate"

const orchestratorNoticePrefix = "[SYSTEM NOTIFICATION - NOT USER INPUT]"

var orchestratorNoticeRequiredClauses = []string{
	"this is an automated background-task event",
	"not a message from the user",
	"do not interpret this as user acknowledgement",
	"no human input has been received",
}

type messageActorCtxKey struct{}

// classifyMessageActor returns a context hint, not a trusted identity. Agent
// type can be inferred from caller-controlled headers, so the security engine
// may only use this value to remove an exact harmless wrapper. It must still
// scan the original content with deterministic detectors and inspect any
// content appended to the wrapper.
func classifyMessageActor(agentType, role, content string) string {
	if agentdetect.NormalizeAgentType(agentType) != "claude-code" {
		return ""
	}
	if !strings.EqualFold(strings.TrimSpace(role), "user") {
		return ""
	}
	normalized := strings.ToLower(strings.TrimSpace(content))
	if !strings.HasPrefix(normalized, strings.ToLower(orchestratorNoticePrefix)) {
		return ""
	}
	for _, clause := range orchestratorNoticeRequiredClauses {
		if !strings.Contains(normalized, clause) {
			return ""
		}
	}
	return orchestratorNoticeCandidate
}

func withMessageActor(ctx context.Context, actorType string) context.Context {
	if actorType != orchestratorNoticeCandidate {
		return ctx
	}
	return context.WithValue(ctx, messageActorCtxKey{}, actorType)
}

func messageActorFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	actorType, _ := ctx.Value(messageActorCtxKey{}).(string)
	if actorType != orchestratorNoticeCandidate {
		return ""
	}
	return actorType
}
