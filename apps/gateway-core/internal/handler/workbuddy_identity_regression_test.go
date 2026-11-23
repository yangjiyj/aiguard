package handler

import (
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestWorkBuddyProductFieldPrecedesSystemMemoryAndKeepsTask(t *testing.T) {
	envelope := `<system-reminder data-role="user-context"><user_info>
Workspace Folder: /Users/test/WorkBuddy/2026-09-12-23-31-56
</user_info><product_identity>You are WorkBuddy, a powerful AI assistant.</product_identity></system-reminder><user_query>Follow-up question</user_query>`
	messages := []Message{{Role: "system", Content: jsonQuote("Tools and memory: You are Codex.")}, {Role: "user", Content: jsonQuote(envelope)}}
	info := &auth.AuthInfo{AgentType: "main", AgentDetectionSource: "client_header"}
	refineChatAgentAttribution(info, messages)
	if info.AgentType != "workbuddy" {
		t.Fatalf("misidentified %s", info.AgentType)
	}
	key, source := workBuddyEvidenceCorrelation(info.AgentType, messages)
	if key != "/Users/test/WorkBuddy/2026-09-12-23-31-56" || source != "workbuddy_workspace" {
		t.Fatalf("task key lost %q %q", key, source)
	}
	messages = append(messages, Message{Role: "assistant", Content: jsonQuote("First answer")}, Message{Role: "user", Content: jsonQuote("second question")})
	next, nextSource := workBuddyEvidenceCorrelation(info.AgentType, messages)
	if next != key || nextSource != source {
		t.Fatal("follow-up split into a new task")
	}
}

func TestWorkBuddyReverseProxyPreservesTask(t *testing.T) {
	envelope := `<system-reminder data-role="user-context"><user_info>
Workspace Folder: /Users/test/WorkBuddy/task-one
</user_info><product_identity>You are WorkBuddy, a powerful AI assistant.</product_identity></system-reminder><user_query>first</user_query>`
	messages := []Message{{Role: "system", Content: jsonQuote("You are Codex.")}, {Role: "user", Content: jsonQuote(envelope)}}
	target, _ := url.Parse("https://api.anthropic.com/v1/messages")
	req := httptest.NewRequest("POST", target.String(), nil)
	for i := 0; i < 2; i++ {
		body, _ := json.Marshal(map[string]interface{}{"messages": messages, "model": "claude-opus-5"})
		record, err := newReverseProxyAuditRecord("test", "tenant-test", target.Host, target, req, body, nil, "success", 200, 0, 0)
		expected := deriveEvidenceRunID("tenant-test", "workbuddy_workspace", "/Users/test/WorkBuddy/task-one")
		if err != nil || record.AgentType != "workbuddy" || record.EvidenceRunID != expected {
			t.Fatalf("round %d: agent=%s task=%s err=%v", i, record.AgentType, record.EvidenceRunID, err)
		}
		messages = append(messages, Message{Role: "user", Content: jsonQuote("follow-up")})
	}
}
