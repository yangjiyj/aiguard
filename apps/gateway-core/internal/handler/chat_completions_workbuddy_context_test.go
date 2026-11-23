package handler

import (
	"context"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestWriteRequestContentLogsDropsWorkBuddyContextAndKeepsHumanQuery(t *testing.T) {
	audit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{auditWriter: audit}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req-workbuddy-context",
		TenantID:  "tenant-1",
		AgentType: "workbuddy",
	}
	contextOnly := `<system-reminder data-role="user-context">
<user_info>
OS Version: darwin
Shell: /bin/zsh
Workspace Folder: /Users/yj/WorkBuddy/task
</user_info>
</system-reminder>`
	contextWithQuery := contextOnly + `
<user_query data-source="desktop">只保留这句真实问题</user_query>`

	handler.writeRequestContentLogs(context.Background(), envelope, []Message{
		{Role: "system", Content: jsonQuote("system prompt")},
		{Role: "user", Content: jsonQuote(contextOnly)},
		{Role: "user", Content: jsonQuote(contextWithQuery)},
		{Role: "user", Content: jsonQuote("普通用户问题")},
	})

	if len(audit.ContentLogWrites) != 3 {
		t.Fatalf("content log writes=%d, want 3: %#v", len(audit.ContentLogWrites), audit.ContentLogWrites)
	}
	if got := audit.ContentLogWrites[1]; got.Role != "user" || got.Content != "只保留这句真实问题" ||
		got.MessageIndex == nil || *got.MessageIndex != 2 {
		t.Fatalf("normalized WorkBuddy query write=%#v", got)
	}
	for _, write := range audit.ContentLogWrites {
		if write.Content == contextOnly || write.Content == contextWithQuery {
			t.Fatalf("internal WorkBuddy context leaked into customer content logs: %#v", write)
		}
	}
}

func TestWriteRequestContentLogsDoesNotTrustWorkBuddyEnvelopeFromOtherClients(t *testing.T) {
	audit := &MockAuditWriter{}
	handler := &ChatCompletionsHandler{auditWriter: audit}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req-untrusted-context",
		TenantID:  "tenant-1",
		AgentType: "custom-client",
	}
	content := `<system-reminder data-role="user-context">
<user_info>caller-controlled text</user_info>
</system-reminder>`

	handler.writeRequestContentLogs(context.Background(), envelope, []Message{{
		Role: "user", Content: jsonQuote(content),
	}})

	if len(audit.ContentLogWrites) != 1 || audit.ContentLogWrites[0].Content != content {
		t.Fatalf("untrusted client content must remain in retention: %#v", audit.ContentLogWrites)
	}
}
