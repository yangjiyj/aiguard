package auditpipe

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/eventbus"
	"github.com/yangjiyj/aiguard/packages/shared-go/outbox"
	"github.com/jackc/pgx/v5/pgconn"
)

type execCall struct {
	query string
	args  []any
}

type fakeExecutor struct {
	calls []execCall
}

func (f *fakeExecutor) Exec(ctx context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	f.calls = append(f.calls, execCall{query: query, args: args})
	return pgconn.CommandTag{}, nil
}

func TestSinkProcessesContentLogEvent(t *testing.T) {
	db := &fakeExecutor{}
	sink := NewSink(db, "customer")
	messageIndex := 0
	payload := eventbus.AuditContentLogPayload{
		RequestLog:   testRequestLogSnapshot(),
		LogID:        "cl_1",
		Role:         "system",
		MessageIndex: &messageIndex,
		Content:      "You are Claude Code, Anthropic's official CLI for Claude.",
		Tokens:       7,
		CreatedAt:    time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
	}

	if err := sink.Process(context.Background(), outboxEvent(eventbus.EventTypeAuditContentLogRequested, payload)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(db.calls) != 2 {
		t.Fatalf("expected content insert plus agent type backfill, got %d calls", len(db.calls))
	}
	if !strings.Contains(db.calls[0].query, "INSERT INTO content_logs") {
		t.Fatalf("first query should insert content log: %s", db.calls[0].query)
	}
	if db.calls[0].args[17] != "cl_1" || db.calls[0].args[19] != "system" || db.calls[0].args[21] != 7 {
		t.Fatalf("unexpected content args: %#v", db.calls[0].args)
	}
	requestLogID, ok := db.calls[0].args[0].(string)
	if !ok || !strings.HasPrefix(requestLogID, "log_") {
		t.Fatalf("fallback request log id = %#v", db.calls[0].args[0])
	}
	if entropy := strings.TrimPrefix(requestLogID, "log_"); len(entropy) < 24 {
		t.Fatalf("fallback request log id %q has only %d hex chars of entropy, want at least 24", requestLogID, len(entropy))
	}
	gotIndex, ok := db.calls[0].args[25].(*int)
	if !ok || gotIndex == nil || *gotIndex != 0 || !strings.Contains(db.calls[0].query, "message_index") {
		t.Fatalf("content log anchor was not persisted: query=%s args=%#v", db.calls[0].query, db.calls[0].args)
	}
	if !strings.Contains(db.calls[0].query, "proxy_access_type_resolved") {
		t.Fatalf("fallback request log insert should write proxy_access_type_resolved:\n%s", db.calls[0].query)
	}
	if db.calls[0].args[24] != "llm" {
		t.Fatalf("model_id 非空的兜底行应判 llm, got %#v", db.calls[0].args[24])
	}
	if !strings.Contains(db.calls[0].query, "environment_scope") || db.calls[0].args[26] != "customer" {
		t.Fatalf("trusted deployment scope must contain an old explicit event scope: query=%s args=%#v", db.calls[0].query, db.calls[0].args)
	}
	if !strings.Contains(db.calls[1].query, "UPDATE request_logs") || db.calls[1].args[0] != "claude-code" {
		t.Fatalf("second query should backfill agent type, got %#v", db.calls[1])
	}
}

func TestSinkContentLogWithoutModelStaysNormalPublic(t *testing.T) {
	db := &fakeExecutor{}
	sink := NewSink(db, "customer")
	snapshot := testRequestLogSnapshot()
	snapshot.ModelID = ""
	snapshot.EnvironmentScope = ""
	payload := eventbus.AuditContentLogPayload{
		RequestLog: snapshot,
		LogID:      "cl_2",
		Role:       "user",
		Content:    "普通请求",
		CreatedAt:  time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
	}

	if err := sink.Process(context.Background(), outboxEvent(eventbus.EventTypeAuditContentLogRequested, payload)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(db.calls) == 0 {
		t.Fatal("expected content insert call")
	}
	if db.calls[0].args[24] != "normal_public" {
		t.Fatalf("model_id 为空的兜底行应保持 normal_public, got %#v", db.calls[0].args[24])
	}
	gotIndex, ok := db.calls[0].args[25].(*int)
	if !ok || gotIndex != nil {
		t.Fatalf("unanchored output/content must keep message_index NULL, got %#v", db.calls[0].args[25])
	}
	if got := db.calls[0].args[26]; got != "customer" {
		t.Fatalf("blank event scope must use trusted deployment fallback, got %#v", got)
	}
}

func TestSinkProcessesSecurityEvent(t *testing.T) {
	db := &fakeExecutor{}
	sink := NewSink(db, "customer")
	payload := eventbus.AuditSecurityEventPayload{
		RequestLog:     testRequestLogSnapshot(),
		EventID:        "evt_1",
		EventType:      "data_security",
		Severity:       "high",
		RuleID:         "rule_bah_001",
		ActionTaken:    "block",
		MatchedSummary: map[string]any{"summary": "病案号外发拦截"},
		CreatedAt:      time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
	}

	if err := sink.Process(context.Background(), outboxEvent(eventbus.EventTypeAuditSecurityEventWrite, payload)); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if len(db.calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(db.calls))
	}
	if !strings.Contains(db.calls[0].query, "INSERT INTO security_events") {
		t.Fatalf("query should insert security event: %s", db.calls[0].query)
	}
	if db.calls[0].args[17] != "evt_1" || db.calls[0].args[18] != "data_security" || db.calls[0].args[20] != "rule_bah_001" {
		t.Fatalf("unexpected security args: %#v", db.calls[0].args)
	}
	if !strings.Contains(db.calls[0].args[22].(string), "病案号外发拦截") {
		t.Fatalf("matched summary not marshaled: %#v", db.calls[0].args[22])
	}
	if !strings.Contains(db.calls[0].query, "proxy_access_type_resolved") {
		t.Fatalf("fallback request log insert should write proxy_access_type_resolved:\n%s", db.calls[0].query)
	}
	if db.calls[0].args[26] != "llm" {
		t.Fatalf("model_id 非空的兜底行应判 llm, got %#v", db.calls[0].args[26])
	}
	if got := db.calls[0].args[31]; got != "customer" {
		t.Fatalf("security fallback request scope = %#v, want deployment customer", got)
	}
}

func TestWriteSecurityEventMaterializesPrincipalAndConversationKey(t *testing.T) {
	db := &fakeExecutor{}
	s := NewSink(db, "customer")
	snapshot := testRequestLogSnapshot()
	snapshot.UserID = "" // user_id 空 → principal 应回退 client_id
	snapshot.ClientID = "caller_abc"
	snapshot.SourceIP = "10.1.1.1"
	payload := eventbus.AuditSecurityEventPayload{
		RequestLog:        snapshot,
		EventID:           "evt_1",
		EventType:         "security_check",
		Severity:          "high",
		EffectiveSeverity: "high",
		ClassKey:          "semantic_instruction_override",
		ActionTaken:       "security_audit",
		MatchedSummary:    map[string]any{},
		ConversationKey:   "ck_ff",
		CreatedAt:         time.Now(),
	}
	if err := s.writeSecurityEvent(context.Background(), payload); err != nil {
		t.Fatal(err)
	}
	if len(db.calls) != 1 {
		t.Fatalf("expected 1 exec, got %d", len(db.calls))
	}
	args := db.calls[0].args
	// principal_key = $28（user_id 空 → client_id），conversation_key = $29
	if got := args[27]; got != "caller_abc" {
		t.Fatalf("principal_key 应为 client_id, got %v", got)
	}
	if got := args[28]; got != "ck_ff" {
		t.Fatalf("conversation_key 应透传, got %v", got)
	}
	if !strings.Contains(db.calls[0].query, "effective_severity") || !strings.Contains(db.calls[0].query, "class_key") {
		t.Fatalf("security event sink should write lifecycle columns:\n%s", db.calls[0].query)
	}
	if got := args[29]; got != "high" {
		t.Fatalf("effective_severity 应透传, got %v", got)
	}
	if got := args[30]; got != "semantic_instruction_override" {
		t.Fatalf("class_key 应透传, got %v", got)
	}
}

func outboxEvent(eventType string, payload any) outbox.Event {
	raw, _ := json.Marshal(payload)
	return outbox.Event{ID: "evt_outbox_1", Type: eventType, TenantID: "tenant_1", RequestID: "req_1", Payload: raw, Attempts: 1}
}

func testRequestLogSnapshot() eventbus.RequestLogSnapshot {
	return eventbus.RequestLogSnapshot{
		RequestID:        "req_1",
		TenantID:         "tenant_1",
		ProjectID:        "project_1",
		UserID:           "user_1",
		ClientID:         "client_1",
		EnvironmentScope: "home",
		ProviderID:       "provider_1",
		ModelID:          "model_1",
		SessionID:        "session_1",
		AgentType:        "",
		EndpointType:     "chat",
		TraceID:          "trace_1",
		CreatedAt:        time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
	}
}

func TestSinkContentBackfillIgnoresUntrustedRoles(t *testing.T) {
	for _, tc := range []struct{ role, content, want string }{
		{"user", "dify 工作流和 Codex 怎么选", ""},
		{"assistant", "You are Claude Code", ""},
		{"tool", "openai codex", ""},
		{"developer", "You are Claude Code, Anthropic's official CLI for Claude.", "claude-code"},
	} {
		db := &fakeExecutor{}
		sink := NewSink(db, "customer")
		messageIndex := 0
		payload := eventbus.AuditContentLogPayload{
			RequestLog: testRequestLogSnapshot(), LogID: "cl_r", Role: tc.role, MessageIndex: &messageIndex,
			Content: tc.content, Tokens: 1, CreatedAt: time.Date(2026, 6, 19, 10, 0, 0, 0, time.UTC),
		}
		if err := sink.Process(context.Background(), outboxEvent(eventbus.EventTypeAuditContentLogRequested, payload)); err != nil {
			t.Fatal(err)
		}
		got := ""
		if len(db.calls) == 2 {
			got, _ = db.calls[1].args[0].(string)
		}
		if got != tc.want {
			t.Fatalf("role=%s backfilled %q, want %q (calls=%d)", tc.role, got, tc.want, len(db.calls))
		}
	}
}
