package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// mockExecResult implements execResult for testing
type mockExecResult struct {
	rowsAffected int64
}

func TestRoutingDecisionMarshalFailureFallsBackToMinimalSafeDecision(t *testing.T) {
	decision := &modelrouter.RoutingDecision{ModelRouteV2: &modelrouter.ModelRouteDecisionV2{SchemaVersion: 2, RequestedModel: "gpt-5.4 Authorization: Bearer model-token"}}
	raw := marshalRoutingDecisionForAudit(decision, func(any) ([]byte, error) { return nil, fmt.Errorf("secret serializer detail") })
	if len(raw) == 0 || strings.Contains(string(raw), "model-token") || strings.Contains(string(raw), "serializer detail") || !strings.Contains(string(raw), "serialization_failed") || !strings.Contains(string(raw), "gpt-5.4") {
		t.Fatalf("unsafe/missing fallback: %s", raw)
	}
}

func (m *mockExecResult) RowsAffected() int64 {
	return m.rowsAffected
}

// mockDBExecutor implements dbExecutor for testing RealAuditWriter
type mockDBExecutor struct {
	recalcCalls [][2]string
	recalcError error
	execCalls   int
	execError   error
	execResult  *mockExecResult
	queries     []string
	args        [][]interface{}
	// failFirstExec 只让第一次 Exec 失败（用于验证批量写入失败后的逐条回退）。
	failFirstExec error
}

func (m *mockDBExecutor) RecalculateSecurityOccurrences(ctx context.Context, tenantID, eventID string) error {
	m.recalcCalls = append(m.recalcCalls, [2]string{tenantID, eventID})
	return m.recalcError
}

func (m *mockDBExecutor) Exec(ctx context.Context, query string, args ...interface{}) (execResult, error) {
	m.execCalls++
	m.queries = append(m.queries, query)
	m.args = append(m.args, args)
	if m.failFirstExec != nil && m.execCalls == 1 {
		return nil, m.failFirstExec
	}
	if m.execError != nil {
		return nil, m.execError
	}
	if m.execResult != nil {
		return m.execResult, nil
	}
	return &mockExecResult{rowsAffected: 1}, nil
}

// mockTokenIncrementer implements tokenIncrementer for testing RealAuditWriter
type mockTokenIncrementer struct {
	incrementCalls []struct {
		ProjectID    string
		InputTokens  int64
		OutputTokens int64
	}
}

func (m *mockTokenIncrementer) IncrementTokenUsage(ctx context.Context, projectID string, inputTokens, outputTokens int64) error {
	m.incrementCalls = append(m.incrementCalls, struct {
		ProjectID    string
		InputTokens  int64
		OutputTokens int64
	}{projectID, inputTokens, outputTokens})
	return nil
}

// === Tests for RealAuditWriter.FinalizeRequestLog ===

func TestRealAuditWriter_WriteContentLog_EnsuresParentRequestLog(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{
		db:      mockDB,
		limiter: &mockTokenIncrementer{},
	}

	envelope := &modelrouter.RequestEnvelope{
		RequestID:    "req-123",
		TenantID:     "tenant-123",
		ProjectID:    "proj-123",
		UserID:       "user-123",
		ClientID:     "key-123",
		ProviderID:   "provider-123",
		ModelID:      "model-123",
		SessionID:    "session-123",
		AgentType:    "claude-code",
		EndpointType: "chat",
	}

	writer.WriteContentLog(context.Background(), envelope, "user", "hello", 3)

	if mockDB.execCalls != 1 {
		t.Fatalf("Expected 1 DB Exec call, got %d", mockDB.execCalls)
	}
	for index, prefix := range map[int]string{0: "log_", 11: "cl_"} {
		id, ok := mockDB.args[0][index].(string)
		if !ok {
			t.Fatalf("audit id arg[%d] is %T, want string", index, mockDB.args[0][index])
		}
		if !strings.HasPrefix(id, prefix) {
			t.Fatalf("audit id %q missing prefix %q", id, prefix)
		}
		if entropy := strings.TrimPrefix(id, prefix); len(entropy) < 24 {
			t.Fatalf("audit id %q has only %d hex chars of entropy, want at least 24", id, len(entropy))
		}
	}
	query := mockDB.queries[0]
	if !strings.Contains(query, "INSERT INTO request_logs") {
		t.Fatalf("content log write should ensure parent request log exists, query was: %s", query)
	}
	if !strings.Contains(query, "INSERT INTO content_logs") {
		t.Fatalf("content log write should insert content log, query was: %s", query)
	}
	if !strings.Contains(query, "SELECT $12, parent.id") || strings.Contains(query, "request_log.request_id") || !strings.Contains(query, "SELECT rl.id FROM request_logs rl") {
		t.Fatalf("content log must link to the persisted request_logs.id used by the content evidence foreign key, query was: %s", query)
	}
	if !strings.Contains(query, "RETURNING id") {
		t.Fatalf("content log CTE must return the persisted request log id, query was: %s", query)
	}
	// 父行已存在时不得 DO UPDATE：每条消息都会把同一行 request_logs 整行重写一次。
	if strings.Contains(query, "ON CONFLICT (request_id) DO UPDATE") || !strings.Contains(query, "ON CONFLICT (request_id) DO NOTHING") {
		t.Fatalf("content log must not rewrite an existing parent request log, query was: %s", query)
	}
}

func TestRealAuditWriterWriteContentLogAnchoredPersistsMessageIndex(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-anchor", TenantID: "tenant-1", ProjectID: "project-1"}

	writer.WriteContentLogAnchored(context.Background(), envelope, "user", "first", 0, 0)

	if !strings.Contains(mockDB.queries[0], "message_index") || !strings.Contains(mockDB.queries[0], "$30") {
		t.Fatalf("anchored insert must persist message_index: %s", mockDB.queries[0])
	}
	got, ok := mockDB.args[0][29].(*int)
	if !ok || got == nil || *got != 0 {
		t.Fatalf("message index arg = %#v, want pointer to zero", mockDB.args[0][29])
	}
}

func TestRealAuditWriterRecordsIdempotentSecurityOccurrence(t *testing.T) {
	mockDB := &mockDBExecutor{}
	writer := &RealAuditWriter{db: mockDB}
	envelope := &modelrouter.RequestEnvelope{
		RequestID:       "req-repeat-2",
		TenantID:        "tenant-1",
		UserID:          "user-2",
		ConversationKey: "conv-2",
	}

	if err := writer.RecordSecurityEventOccurrence(
		context.Background(), envelope, "evt-first", "context-key",
	); err != nil {
		t.Fatalf("record occurrence: %v", err)
	}
	if mockDB.execCalls != 1 {
		t.Fatalf("expected one durable insert/update, got %d execs", mockDB.execCalls)
	}
	if len(mockDB.recalcCalls) != 1 || mockDB.recalcCalls[0] != [2]string{envelope.TenantID, "evt-first"} {
		t.Fatalf("counter recalculation scope = %#v", mockDB.recalcCalls)
	}
	firstQuery := mockDB.queries[0]
	if !strings.Contains(firstQuery, "INSERT INTO security_event_occurrences") ||
		!strings.Contains(firstQuery, "ON CONFLICT (tenant_id, representative_event_id, request_id) DO NOTHING") ||
		!strings.Contains(firstQuery, "occurrence_count = ag.occurrence_count + 1") {
		t.Fatalf("occurrence SQL lost idempotency or group bump: %s", firstQuery)
	}
	if got := mockDB.args[0][1]; got != "evt-first" {
		t.Fatalf("representative event arg = %#v", got)
	}
	if got := mockDB.args[0][2]; got != envelope.RequestID {
		t.Fatalf("request id arg = %#v", got)
	}
}

func TestRealAuditWriterFinalizePersistsTTFTWithoutResponseBody(t *testing.T) {
	mockDB := &mockDBExecutor{}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	ttft := int64(123)
	env := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", ProviderID: "p", ModelID: "m", UpstreamTTFTMs: &ttft}
	writer.FinalizeRequestLog(context.Background(), env, nil, "completed", 200, 500, nil)
	if len(mockDB.queries) != 1 || !strings.Contains(mockDB.queries[0], "upstream_ttft_ms") {
		t.Fatalf("TTFT column absent: %v", mockDB.queries)
	}
	found := false
	for _, arg := range mockDB.args[0] {
		if value, ok := arg.(*int64); ok && value == env.UpstreamTTFTMs {
			found = true
		}
	}
	if !found {
		t.Fatalf("TTFT pointer absent from args: %#v", mockDB.args[0])
	}
}

func TestRealAuditWriterSanitizesRoutingDecisionBeforePersistence(t *testing.T) {
	mockDB := &mockDBExecutor{}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	env := &modelrouter.RequestEnvelope{RequestID: "r-safe", TenantID: "t", RoutingDecision: &modelrouter.RoutingDecision{GovernorOverride: map[string]any{"prompt": "private", "safe": "ok"}}}
	writer.FinalizeRequestLog(context.Background(), env, nil, "completed", 200, 1, nil)
	for _, arg := range mockDB.args[0] {
		if raw, ok := arg.([]byte); ok && strings.Contains(string(raw), "routing") {
			_ = raw
		}
		if raw, ok := arg.([]byte); ok && strings.Contains(string(raw), "private") {
			t.Fatalf("secret persisted: %s", raw)
		}
	}
}

func TestRealAuditWriter_RequestLogWritesResolvedAccessType(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{
		db:      mockDB,
		limiter: &mockTokenIncrementer{},
	}
	envelope := &modelrouter.RequestEnvelope{
		RequestID:    "req-resolved-access-type",
		TenantID:     "tenant-123",
		ProjectID:    "proj-123",
		ProviderID:   "provider-123",
		ModelID:      "model-123",
		EndpointType: "chat",
	}

	writer.EnsureRequestLog(context.Background(), envelope)
	writer.FinalizeRequestLog(context.Background(), envelope, nil, "success", 200, 100, nil)

	if len(mockDB.queries) != 2 {
		t.Fatalf("expected ensure and finalize queries, got %d", len(mockDB.queries))
	}
	for _, query := range mockDB.queries {
		if !strings.Contains(query, "proxy_access_type_resolved") {
			t.Fatalf("request log query should write proxy_access_type_resolved:\n%s", query)
		}
	}
	if !strings.Contains(mockDB.queries[1], "proxy_access_type_resolved = EXCLUDED.proxy_access_type_resolved") {
		t.Fatalf("finalize upsert should refresh resolved access type:\n%s", mockDB.queries[1])
	}
}

func TestRealAuditWriter_RequestLogAllowsEarlyFailureWithoutRoute(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{
		db:      mockDB,
		limiter: &mockTokenIncrementer{},
	}
	envelope := &modelrouter.RequestEnvelope{
		RequestID:    "req-invalid-json",
		TenantID:     "tenant-123",
		ProjectID:    "proj-123",
		ProviderID:   "",
		ModelID:      "",
		EndpointType: "responses",
	}

	writer.EnsureRequestLog(context.Background(), envelope)
	writer.FinalizeRequestLog(context.Background(), envelope, nil, "invalid_request", 400, 37_400, nil)

	if len(mockDB.queries) != 2 {
		t.Fatalf("expected ensure and finalize queries, got %d", len(mockDB.queries))
	}
	if !strings.Contains(mockDB.queries[0], "NULLIF($7, '')") ||
		!strings.Contains(mockDB.queries[0], "NULLIF($8, '')") {
		t.Fatalf("ensure must persist empty provider/model as NULL:\n%s", mockDB.queries[0])
	}
	if !strings.Contains(mockDB.queries[1], "NULLIF($6, '')") ||
		!strings.Contains(mockDB.queries[1], "NULLIF($7, '')") {
		t.Fatalf("finalize must persist empty provider/model as NULL:\n%s", mockDB.queries[1])
	}
}

func TestRequestOutcomeDimensionsKeepUpstreamAndDeliveryIndependent(t *testing.T) {
	upstream, delivery, billing, cancel := requestOutcomeDimensions("stream_aborted", http.StatusOK)
	if upstream != "success" || delivery != "aborted" || billing != "unknown" || cancel != "none" {
		t.Fatalf("outcomes=%q/%q/%q/%q", upstream, delivery, billing, cancel)
	}
	upstream, delivery, _, cancel = requestOutcomeDimensions("client_canceled", 0)
	if upstream != "canceled" || delivery != "client_canceled" || cancel != "client_canceled" {
		t.Fatalf("cancel outcomes=%q/%q/%q", upstream, delivery, cancel)
	}
}

// Ensure chat completions traffic is stamped proxy_mode='chat_completion',
// not the column default 'reverse'. Regression guard for the UI mislabel
// where Claude Code / OpenCode requests were shown as 反向代理.
func TestRealAuditWriter_RequestLogStampsChatCompletionProxyMode(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{
		db:      mockDB,
		limiter: &mockTokenIncrementer{},
	}
	envelope := &modelrouter.RequestEnvelope{
		RequestID:    "req-chat-completion-mode",
		TenantID:     "tenant-123",
		ProjectID:    "proj-123",
		ProviderID:   "provider-123",
		ModelID:      "model-123",
		EndpointType: "chat",
	}

	writer.EnsureRequestLog(context.Background(), envelope)
	writer.FinalizeRequestLog(context.Background(), envelope, nil, "success", 200, 100, nil)
	writer.WriteContentLog(context.Background(), envelope, "user", "hello", 3)

	if len(mockDB.queries) < 2 {
		t.Fatalf("expected at least ensure + finalize queries, got %d", len(mockDB.queries))
	}
	for i, query := range mockDB.queries {
		// 2.9.22：EnsureRequestLog 的 proxy_mode 改为参数（运行故障自建的日志记 runtime_fault），
		// 普通请求的参数仍是 chat_completion；其余语句照旧写字面量。
		if strings.Contains(query, "'chat_completion'") || (i == 0 && argsContainString(mockDB.args[0], "chat_completion")) {
			continue
		}
		t.Fatalf("query[%d] must stamp proxy_mode='chat_completion', got:\n%s", i, query)
	}
}

func TestRealAuditWriter_WriteContentLog_BackfillsAgentTypeFromContent(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{
		db:      mockDB,
		limiter: &mockTokenIncrementer{},
	}

	envelope := &modelrouter.RequestEnvelope{
		RequestID:    "req-claude-code",
		TenantID:     "tenant-123",
		ProjectID:    "proj-123",
		UserID:       "user-123",
		EndpointType: "chat",
	}

	writer.WriteContentLog(context.Background(), envelope, "system", "You are Claude Code, Anthropic's official CLI for Claude.", 0)

	if mockDB.execCalls != 2 {
		t.Fatalf("Expected content insert plus agent_type backfill, got %d DB Exec calls", mockDB.execCalls)
	}
	if !strings.Contains(mockDB.queries[1], "UPDATE request_logs") || !strings.Contains(mockDB.queries[1], "agent_type") {
		t.Fatalf("second query should backfill request_logs.agent_type, query was: %s", mockDB.queries[1])
	}
	if got := mockDB.args[1][0]; got != "claude-code" {
		t.Fatalf("expected inferred agent type claude-code, got %v", got)
	}
}

func TestRealAuditWriter_BackfillAgentTypeUpgradesGenericOnly(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}

	writer.BackfillRequestAgentType(context.Background(), "tenant-123", "req-123", "claude-code")

	if mockDB.execCalls != 1 {
		t.Fatalf("exec calls = %d, want 1", mockDB.execCalls)
	}
	query := mockDB.queries[0]
	for _, want := range []string{"agent_type IN ('agent-tool-call', 'vscode')", "$1 NOT IN ('agent-tool-call', 'vscode')"} {
		if !strings.Contains(query, want) {
			t.Fatalf("upgrade query missing %q:\n%s", want, query)
		}
	}
}

func TestRealAuditWriter_BackfillAgentTypeUpgradesWeakRuntimeIdentity(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}

	writer.BackfillRequestAgentType(context.Background(), "tenant-123", "req-123", "openai-codex")

	if mockDB.execCalls != 1 {
		t.Fatalf("exec calls = %d, want 1", mockDB.execCalls)
	}
	query := mockDB.queries[0]
	if !strings.Contains(query, "agent_type IN ('agent-tool-call', 'vscode')") {
		t.Fatalf("strong content identity must replace weak runtime identity:\n%s", query)
	}
}

func TestRealAuditWriter_EnsurePersistsEvidenceRunAttribution(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req-run", TenantID: "tenant-1", AgentType: "openai-codex",
		AgentRuntime: "vscode", AgentDetectionSource: "content", AgentDetectionConfidence: 0.98,
		EvidenceRunID: "run_abc", EvidenceRunSource: "responses_prompt_cache_key",
	}
	writer.EnsureRequestLog(context.Background(), envelope)
	for _, column := range []string{"agent_runtime", "agent_detection_source", "agent_detection_confidence", "evidence_run_id", "evidence_run_source"} {
		if !strings.Contains(mockDB.queries[0], column) {
			t.Fatalf("ensure query missing %s", column)
		}
	}
}

func TestRealAuditWriter_FinalizeLetsToolCausalityReplaceWeakPromptCacheHint(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req-run", TenantID: "tenant-1", ProjectID: "project-1",
		EvidenceRunID: "run_tool", EvidenceRunSource: chatToolCallEvidenceSource,
	}

	writer.FinalizeRequestLog(context.Background(), envelope, nil, "success", 200, 1, nil)

	if mockDB.execCalls != 1 {
		t.Fatalf("exec calls=%d, want 1", mockDB.execCalls)
	}
	query := mockDB.queries[0]
	for _, want := range []string{
		"request_logs.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')",
		"EXCLUDED.evidence_run_source = 'chat_tool_call_id'",
		"THEN EXCLUDED.evidence_run_id",
	} {
		if !strings.Contains(query, want) {
			t.Fatalf("finalize query cannot upgrade weak correlation; missing %q:\n%s", want, query)
		}
	}
}

func TestRealAuditWriter_DBError_NoTokenIncrement(t *testing.T) {
	mockDB := &mockDBExecutor{execError: errors.New("db connection failed")}
	mockToken := &mockTokenIncrementer{}

	writer := &RealAuditWriter{
		db:      mockDB,
		limiter: mockToken,
	}

	envelope := &modelrouter.RequestEnvelope{
		RequestID: "test-123",
		ProjectID: "proj-123",
	}

	resp := ChatCompletionResponse{
		Usage: Usage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
	}
	respBody, _ := json.Marshal(resp)

	writer.FinalizeRequestLog(context.Background(), envelope, respBody, "success", 200, 100, nil)

	// DB Exec was attempted
	if mockDB.execCalls != 1 {
		t.Errorf("Expected 1 DB Exec call, got %d", mockDB.execCalls)
	}

	// Token increment must NOT be called on DB error
	if len(mockToken.incrementCalls) != 0 {
		t.Errorf("Expected 0 token increment calls on DB error, got %d", len(mockToken.incrementCalls))
	}
}

func TestRealAuditWriter_ZeroRowsAffected_NoTokenIncrement(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 0}}
	mockToken := &mockTokenIncrementer{}

	writer := &RealAuditWriter{
		db:      mockDB,
		limiter: mockToken,
	}

	envelope := &modelrouter.RequestEnvelope{
		RequestID: "test-123",
		ProjectID: "proj-123",
	}

	resp := ChatCompletionResponse{
		Usage: Usage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
	}
	respBody, _ := json.Marshal(resp)

	writer.FinalizeRequestLog(context.Background(), envelope, respBody, "success", 200, 100, nil)

	// DB Exec was called
	if mockDB.execCalls != 1 {
		t.Errorf("Expected 1 DB Exec call, got %d", mockDB.execCalls)
	}

	// Token increment must NOT be called when RowsAffected=0
	if len(mockToken.incrementCalls) != 0 {
		t.Errorf("Expected 0 token increment calls when RowsAffected=0, got %d", len(mockToken.incrementCalls))
	}
}

func TestRealAuditWriter_Success_WithTokens_TokenIncrementCalled(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	mockToken := &mockTokenIncrementer{}

	writer := &RealAuditWriter{
		db:      mockDB,
		limiter: mockToken,
	}

	envelope := &modelrouter.RequestEnvelope{
		RequestID: "test-123",
		ProjectID: "proj-123",
	}

	resp := ChatCompletionResponse{
		Usage: Usage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
	}
	respBody, _ := json.Marshal(resp)

	writer.FinalizeRequestLog(context.Background(), envelope, respBody, "success", 200, 100, nil)

	// DB Exec was called
	if mockDB.execCalls != 1 {
		t.Errorf("Expected 1 DB Exec call, got %d", mockDB.execCalls)
	}

	// Token increment must be called with correct values
	if len(mockToken.incrementCalls) != 1 {
		t.Errorf("Expected 1 token increment call on success, got %d", len(mockToken.incrementCalls))
	}

	call := mockToken.incrementCalls[0]
	if call.ProjectID != "proj-123" {
		t.Errorf("Expected ProjectID 'proj-123', got '%s'", call.ProjectID)
	}
	if call.InputTokens != 100 {
		t.Errorf("Expected InputTokens 100, got %d", call.InputTokens)
	}
	if call.OutputTokens != 50 {
		t.Errorf("Expected OutputTokens 50, got %d", call.OutputTokens)
	}
}

func TestRealAuditWriter_NativeResponsesUsage_IncrementsTokens(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	mockToken := &mockTokenIncrementer{}
	writer := &RealAuditWriter{db: mockDB, limiter: mockToken}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "native-response-usage",
		ProjectID: "proj-native",
	}
	respBody := []byte(`{"id":"resp_1","object":"response","status":"completed","usage":{"input_tokens":17,"output_tokens":9,"total_tokens":26}}`)

	writer.FinalizeRequestLog(context.Background(), envelope, respBody, "success", 200, 100, nil)

	if len(mockToken.incrementCalls) != 1 {
		t.Fatalf("expected one token increment, got %d", len(mockToken.incrementCalls))
	}
	call := mockToken.incrementCalls[0]
	if call.ProjectID != "proj-native" || call.InputTokens != 17 || call.OutputTokens != 9 {
		t.Fatalf("native usage increment=%+v", call)
	}
	if len(mockDB.args) == 0 {
		t.Fatal("request log update was not executed")
	}
}

func TestRealAuditWriter_EmptyResponseBody_NoTokenIncrement(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	mockToken := &mockTokenIncrementer{}

	writer := &RealAuditWriter{
		db:      mockDB,
		limiter: mockToken,
	}

	envelope := &modelrouter.RequestEnvelope{
		RequestID: "test-123",
		ProjectID: "proj-123",
	}

	// Empty response body - no tokens to parse
	writer.FinalizeRequestLog(context.Background(), envelope, nil, "error", 500, 100, nil)

	// DB Exec was called
	if mockDB.execCalls != 1 {
		t.Errorf("Expected 1 DB Exec call, got %d", mockDB.execCalls)
	}

	// Token increment must NOT be called when resp is empty
	if len(mockToken.incrementCalls) != 0 {
		t.Errorf("Expected 0 token increment calls for empty response, got %d", len(mockToken.incrementCalls))
	}
}

func TestRealAuditWriter_UnparseableBody_NoTokenIncrement(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	mockToken := &mockTokenIncrementer{}

	writer := &RealAuditWriter{
		db:      mockDB,
		limiter: mockToken,
	}

	envelope := &modelrouter.RequestEnvelope{
		RequestID: "test-123",
		ProjectID: "proj-123",
	}

	// Invalid JSON body
	invalidBody := []byte(`{"invalid json`)

	writer.FinalizeRequestLog(context.Background(), envelope, invalidBody, "success", 200, 100, nil)

	// DB Exec was called
	if mockDB.execCalls != 1 {
		t.Errorf("Expected 1 DB Exec call, got %d", mockDB.execCalls)
	}

	// Token increment must NOT be called when body can't be parsed
	// (TotalTokens will be 0 from empty ChatCompletionResponse)
	if len(mockToken.incrementCalls) != 0 {
		t.Errorf("Expected 0 token increment calls for unparseable body, got %d", len(mockToken.incrementCalls))
	}
}

func TestRealAuditWriter_ZeroTokens_NoTokenIncrement(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	mockToken := &mockTokenIncrementer{}

	writer := &RealAuditWriter{
		db:      mockDB,
		limiter: mockToken,
	}

	envelope := &modelrouter.RequestEnvelope{
		RequestID: "test-123",
		ProjectID: "proj-123",
	}

	// Response with zero tokens (e.g., error response from provider)
	resp := ChatCompletionResponse{
		Usage: Usage{
			PromptTokens:     0,
			CompletionTokens: 0,
			TotalTokens:      0,
		},
	}
	respBody, _ := json.Marshal(resp)

	writer.FinalizeRequestLog(context.Background(), envelope, respBody, "error", 500, 100, nil)

	// DB Exec was called
	if mockDB.execCalls != 1 {
		t.Errorf("Expected 1 DB Exec call, got %d", mockDB.execCalls)
	}

	// Token increment must NOT be called when TotalTokens=0
	if len(mockToken.incrementCalls) != 0 {
		t.Errorf("Expected 0 token increment calls when TotalTokens=0, got %d", len(mockToken.incrementCalls))
	}
}

func TestRealAuditWriter_FinalizeRequestLogLeavesLegacyCostFieldsUntouched(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-no-legacy-cost", ProjectID: "proj-123", ModelID: "model-123"}
	respBody, _ := json.Marshal(ChatCompletionResponse{Usage: Usage{PromptTokens: 1_000_000, CompletionTokens: 500_000, TotalTokens: 1_500_000}})

	writer.FinalizeRequestLog(context.Background(), envelope, respBody, "success", 200, 100, nil)

	if len(mockDB.queries) != 1 {
		t.Fatalf("audit writes = %d, want 1", len(mockDB.queries))
	}
	if strings.Contains(mockDB.queries[0], "total_cost") || strings.Contains(mockDB.queries[0], "cost_meta_json") {
		t.Fatalf("new request log writes must not touch legacy cost columns: %s", mockDB.queries[0])
	}
	for _, arg := range mockDB.args[0] {
		if _, isLegacyCost := arg.(*float64); isLegacyCost {
			t.Fatalf("new request log writes must not bind a legacy cost value: %#v", mockDB.args[0])
		}
	}
}

// === P2-1 验收：security_events.rule_id 顶层列填充（命中自定义规则可被 WHERE rule_id 查到） ===

func TestRealAuditWriter_WriteSecurityEvent_PopulatesTopLevelRuleIDForCustomRule(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}

	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req_bah_1",
		TenantID:  "tenant_default",
		ProjectID: "proj_1",
		UserID:    "user_1",
	}
	findings := []SecurityFinding{
		{
			Type:               "custom",
			Category:           "medical_id",
			Severity:           "high",
			MatchedTextPreview: "BA****34 (sha256:deadbeef)",
			RuleID:             "rule_bah_001",
			Confidence:         0.9,
		},
	}

	writer.WriteSecurityEvent(context.Background(), envelope, findings, "block", "病案号外发拦截")

	if mockDB.execCalls != 1 {
		t.Fatalf("expected 1 Exec call, got %d", mockDB.execCalls)
	}
	// rule_id 是第 8 个位置参数（$8）-> args 下标 7
	if got := mockDB.args[0][7]; got != "rule_bah_001" {
		t.Fatalf("expected top-level rule_id column = rule_bah_001, got %v", got)
	}
}

func TestRealAuditWriter_WriteSecurityEvent_LeavesRuleIDEmptyForBuiltinOnly(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}

	envelope := &modelrouter.RequestEnvelope{RequestID: "req_b", TenantID: "t", ProjectID: "p", UserID: "u"}
	// 内置规则命中：其 rule_id 不是 rules(id) 中的行，写入 FK 列会违反外键约束，必须保持空。
	findings := []SecurityFinding{
		{
			Type:               "secret",
			Category:           "password",
			Severity:           "critical",
			MatchedTextPreview: "<REDACTED sha256:abcd1234>",
			RuleID:             "secret-password",
			Confidence:         0.95,
		},
	}

	writer.WriteSecurityEvent(context.Background(), envelope, findings, "block", "secret blocked")

	if got := mockDB.args[0][7]; got != "" {
		t.Fatalf("expected top-level rule_id column empty for builtin-only findings (FK safety), got %v", got)
	}
}

func TestRealAuditWriter_WriteSecurityEvent_PopulatesRuleIDForBoundBuiltinPolicy(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req_bound", TenantID: "t", ProjectID: "p", UserID: "u"}
	findings := []SecurityFinding{{
		Type: "secret", Category: "plain_password", Severity: "critical",
		RuleID: "rule_bound_uuid", PolicyCode: "builtin.data_leak.password",
		SourceRuleID: "secret-password", Action: "block",
	}}

	writer.WriteSecurityEvent(context.Background(), envelope, findings, "block", "bound builtin")

	if got := mockDB.args[0][7]; got != "rule_bound_uuid" {
		t.Fatalf("top-level rule_id=%v want rule_bound_uuid", got)
	}
}

func TestRealAuditWriter_WriteSecurityEvent_MaterializesLifecycleFieldsForSemanticAttack(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req_semantic", TenantID: "t", ProjectID: "p", UserID: "u"}
	observationOnly := false
	findings := []SecurityFinding{
		{
			Type:                    "prompt_injection",
			Category:                "keyword_classic_injection_en",
			Severity:                "medium",
			RuleID:                  "rule_5dd088f4",
			Confidence:              0.85,
			CountsAsSecurityFinding: &observationOnly,
		},
		{
			Type:       "semantic_attack",
			Category:   "semantic_instruction_override",
			Severity:   "high",
			RuleID:     "semantic_instruction_override",
			Confidence: 0.95,
		},
	}

	writer.WriteSecurityEvent(context.Background(), envelope, findings, "security_audit_only", "semantic hit")

	if mockDB.execCalls != 1 {
		t.Fatalf("expected 1 Exec call, got %d", mockDB.execCalls)
	}
	if !strings.Contains(mockDB.queries[0], "effective_severity") || !strings.Contains(mockDB.queries[0], "class_key") {
		t.Fatalf("security_events insert must materialize lifecycle columns, query:\n%s", mockDB.queries[0])
	}
	if len(mockDB.args[0]) < 15 {
		t.Fatalf("expected lifecycle field args in security_events insert, got %d args: %#v", len(mockDB.args[0]), mockDB.args[0])
	}
	if got := mockDB.args[0][13]; got != "high" {
		t.Fatalf("effective_severity arg=%v, want high", got)
	}
	if got := mockDB.args[0][14]; got != "semantic_instruction_override" {
		t.Fatalf("class_key arg=%v, want semantic_instruction_override", got)
	}
}

// === P2-2 验收：文件维度安全事件 event_type 分桶 + FK 安全（rule_id NULL） ===

// 红线场景：仅上送文件/图片（伪装可执行文件）命中，type=="file"。
// 期望：顶层 event_type 归为 "file_security"（供安全事件页按维度过滤/闭环），
// 且文件规则 id（不在 rules 表）绝不写入 rule_id 外键列。
func TestRealAuditWriter_WriteSecurityEvent_FileFindingUsesFileSecurityEventType(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}

	envelope := &modelrouter.RequestEnvelope{RequestID: "req_file_1", TenantID: "t", ProjectID: "p", UserID: "u"}
	findings := []SecurityFinding{
		{
			Type:               "file",
			Category:           "file_disguised_executable",
			Severity:           "critical",
			MatchedTextPreview: "sha256:deadbeefdeadbeef name=cat.png declared=image/png real=application/x-dosexec size=128",
			RuleID:             "file-disguised-exec",
			RuleType:           "file_fingerprint",
			Action:             "block",
			RedactedEvidence:   "sha256:deadbeefdeadbeef name=cat.png declared=image/png real=application/x-dosexec size=128",
		},
	}

	writer.WriteSecurityEvent(context.Background(), envelope, findings, "block", "伪装可执行文件外发拦截")

	if mockDB.execCalls != 1 {
		t.Fatalf("expected 1 Exec call, got %d", mockDB.execCalls)
	}
	// event_type 是第 6 个位置参数（$6）-> args 下标 5
	if got := mockDB.args[0][5]; got != "file_security" {
		t.Fatalf("expected event_type=file_security for pure-file finding, got %v", got)
	}
	// 红线：文件命中的 rule_id（file-disguised-exec）不在 rules 表 -> 顶层 FK 列必须为空。
	if got := mockDB.args[0][7]; got != "" {
		t.Fatalf("expected top-level rule_id empty for file finding (FK safety), got %v", got)
	}
}

// 混合命中（文本/密钥 + 文件）必须维持既有 "security_check" 分桶，零回归；
// 文件维度仍完整保留在 matched_summary.findings[] 中，不丢失。
func TestRealAuditWriter_WriteSecurityEvent_MixedKeepsSecurityCheckEventType(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}

	envelope := &modelrouter.RequestEnvelope{RequestID: "req_mix_1", TenantID: "t", ProjectID: "p", UserID: "u"}
	findings := []SecurityFinding{
		{Type: "secret", Category: "password", Severity: "critical", RuleID: "secret-password"},
		{Type: "file", Category: "file_archive", Severity: "low", RuleID: "file-archive", Action: "audit"},
	}

	writer.WriteSecurityEvent(context.Background(), envelope, findings, "block", "mixed")

	if got := mockDB.args[0][5]; got != "security_check" {
		t.Fatalf("expected event_type=security_check when any non-file finding present, got %v", got)
	}
}

// === P2-3 验收：数据安全维度安全事件 event_type 分桶（data_security）+ 全序优先级 ===
// 全序优先级：内置(agent/pii/secret/code_config) > 自定义(custom) > 文件(file)。
// 内置维持既有 "security_check"（零回归）；自定义敏感数据归 "data_security"；纯文件归 "file_security"。

// 命中客户自定义敏感数据规则（type=="custom"）：顶层 event_type 归 "data_security"，
// 供安全事件页按"数据安全"维度过滤与处置闭环；自定义 rule_id 是 rules(id) 行，FK 安全，仍写顶层列。
func TestRealAuditWriter_WriteSecurityEvent_CustomSensitiveDataUsesDataSecurityEventType(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}

	envelope := &modelrouter.RequestEnvelope{RequestID: "req_ds_1", TenantID: "t", ProjectID: "p", UserID: "u"}
	findings := []SecurityFinding{
		{
			Type:               "custom",
			Category:           "medical_id",
			Severity:           "high",
			MatchedTextPreview: "BA****34 (sha256:deadbeef)",
			RuleID:             "rule_bah_001",
			Action:             "block",
			Confidence:         0.9,
		},
	}

	writer.WriteSecurityEvent(context.Background(), envelope, findings, "block", "病案号外发拦截")

	if mockDB.execCalls != 1 {
		t.Fatalf("expected 1 Exec call, got %d", mockDB.execCalls)
	}
	// event_type 是第 6 个位置参数（$6）-> args 下标 5
	if got := mockDB.args[0][5]; got != "data_security" {
		t.Fatalf("expected event_type=data_security for custom sensitive-data finding, got %v", got)
	}
	// 自定义规则 id 在 rules 表，FK 安全：顶层 rule_id 列仍须填充以支持按规则查事件。
	if got := mockDB.args[0][7]; got != "rule_bah_001" {
		t.Fatalf("expected top-level rule_id=rule_bah_001 for custom finding, got %v", got)
	}
}

// 自定义 + 文件混合：自定义优先于文件，归 "data_security"（锁定 custom > file 优先级）。
func TestRealAuditWriter_WriteSecurityEvent_CustomPlusFileStaysDataSecurity(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}

	envelope := &modelrouter.RequestEnvelope{RequestID: "req_ds_2", TenantID: "t", ProjectID: "p", UserID: "u"}
	findings := []SecurityFinding{
		{Type: "custom", Category: "medical_id", Severity: "high", RuleID: "rule_bah_001", Action: "block"},
		{Type: "file", Category: "file_archive", Severity: "low", RuleID: "file-archive", Action: "audit"},
	}

	writer.WriteSecurityEvent(context.Background(), envelope, findings, "block", "自定义+文件")

	if got := mockDB.args[0][5]; got != "data_security" {
		t.Fatalf("expected event_type=data_security when custom present (custom > file), got %v", got)
	}
}

// 内置 + 自定义混合：内置维持既有 "security_check"（零回归，锁定 builtin > custom 优先级）。
// 内置 secret/pii 沿用既有内容安全事件语义，既有看板分桶不被自定义命中改写；
// 自定义命中仍完整保留在 matched_summary.findings[] 中，不丢失。
func TestRealAuditWriter_WriteSecurityEvent_BuiltinPlusCustomStaysSecurityCheck(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}

	envelope := &modelrouter.RequestEnvelope{RequestID: "req_ds_3", TenantID: "t", ProjectID: "p", UserID: "u"}
	findings := []SecurityFinding{
		{Type: "secret", Category: "password", Severity: "critical", RuleID: "secret-password"},
		{Type: "custom", Category: "medical_id", Severity: "high", RuleID: "rule_bah_001", Action: "block"},
	}

	writer.WriteSecurityEvent(context.Background(), envelope, findings, "block", "内置+自定义")

	if got := mockDB.args[0][5]; got != "security_check" {
		t.Fatalf("expected event_type=security_check when any builtin finding present (builtin > custom), got %v", got)
	}
}

// === P1-D 验收：security_events 写入物化 principal_key / conversation_key（契约6） ===

func TestRealAuditWriter_WriteSecurityEvent_MaterializesPrincipalAndConversationKey(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB}
	envelope := &modelrouter.RequestEnvelope{
		RequestID: "req_pk_1", TenantID: "t", ProjectID: "p",
		UserID: "user_1", ClientID: "key_abc", SourceIP: "10.0.0.9",
		ConversationKey: "ck_deadbeefdeadbeefdeadbeefdeadbeef",
	}
	writer.WriteSecurityEvent(context.Background(), envelope, []SecurityFinding{{Type: "secret", Category: "openai_key", Severity: "critical"}}, "security_audit", "s")
	// principal_key 是第 12 个位置参数($12) -> args 下标 11；conversation_key $13 -> 下标 12
	if got := mockDB.args[0][11]; got != "user_1" {
		t.Fatalf("principal_key 应取 user_id 优先, got %v", got)
	}
	if got := mockDB.args[0][12]; got != "ck_deadbeefdeadbeefdeadbeefdeadbeef" {
		t.Fatalf("conversation_key 应透传 envelope, got %v", got)
	}
}

func TestPrincipalKeyFromEnvelopeCoalesceOrder(t *testing.T) {
	cases := []struct {
		env  *modelrouter.RequestEnvelope
		want string
	}{
		{&modelrouter.RequestEnvelope{UserID: "u", ClientID: "c", SourceIP: "1.2.3.4"}, "u"},
		{&modelrouter.RequestEnvelope{ClientID: "c", SourceIP: "1.2.3.4"}, "c"},
		{&modelrouter.RequestEnvelope{SourceIP: "1.2.3.4"}, "1.2.3.4"},
		{&modelrouter.RequestEnvelope{}, ""},
		{nil, ""},
	}
	for i, c := range cases {
		if got := principalKeyFromEnvelope(c.env); got != c.want {
			t.Fatalf("case %d: want %q got %q", i, c.want, got)
		}
	}
}

func TestOccurrenceCounterRecalculationOnlyAfterDurableInsert(t *testing.T) {
	for _, insertFails := range []bool{false, true} {
		db := &mockDBExecutor{recalcError: errors.New("recalc unavailable")}
		if insertFails {
			db.execError = errors.New("insert unavailable")
		}
		writer := &RealAuditWriter{db: db}
		err := writer.RecordSecurityEventOccurrence(context.Background(), &modelrouter.RequestEnvelope{TenantID: "t", RequestID: "r"}, "e", "c")
		if insertFails {
			if err == nil || len(db.recalcCalls) != 0 {
				t.Fatalf("failed insert must not recalculate: err=%v calls=%v", err, db.recalcCalls)
			}
		} else if err != nil || len(db.recalcCalls) != 1 {
			t.Fatalf("durable occurrence must survive best-effort recalc error: err=%v calls=%v", err, db.recalcCalls)
		}
	}
}

func TestRealAuditWriter_ContentBackfillIgnoresUntrustedRoles(t *testing.T) {
	cases := []struct {
		role, content, want string
	}{
		{"user", "帮我评估一下 dify 工作流和 Codex 的区别", ""},
		{"assistant", "You are Claude Code", ""},
		{"tool", "openai codex output", ""},
		{"system", "You are Claude Code, Anthropic's official CLI for Claude.", "claude-code"},
		{"developer", "You are Claude Code, Anthropic's official CLI for Claude.", "claude-code"},
	}
	for _, tc := range cases {
		mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
		writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
		envelope := &modelrouter.RequestEnvelope{RequestID: "req-role", TenantID: "tenant-123", ProjectID: "proj-123", UserID: "user-123", EndpointType: "chat"}
		writer.WriteContentLog(context.Background(), envelope, tc.role, tc.content, 0)
		got := ""
		if mockDB.execCalls == 2 {
			got, _ = mockDB.args[1][0].(string)
		} else if mockDB.execCalls != 1 {
			t.Fatalf("role=%s exec calls=%d", tc.role, mockDB.execCalls)
		}
		if got != tc.want {
			t.Fatalf("single path role=%s: backfilled %q, want %q", tc.role, got, tc.want)
		}
	}
}

func TestRealAuditWriter_BatchContentBackfillIgnoresUntrustedRoles(t *testing.T) {
	mockDB := &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer := &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-batch-role", TenantID: "tenant-123", ProjectID: "proj-123", UserID: "user-123", EndpointType: "chat"}
	writer.WriteContentLogsBatch(context.Background(), envelope, []ContentLogEntry{
		{Role: "user", Content: "dify 和 Codex 对比", MessageIndex: 0},
		{Role: "assistant", Content: "You are Claude Code", MessageIndex: 1},
	})
	for i, q := range mockDB.queries {
		if strings.Contains(q, "UPDATE request_logs") && strings.Contains(q, "agent_detection_source = 'content'") {
			t.Fatalf("untrusted roles must not backfill agent_type (query %d, args %v)", i, mockDB.args[i])
		}
	}
	mockDB = &mockDBExecutor{execResult: &mockExecResult{rowsAffected: 1}}
	writer = &RealAuditWriter{db: mockDB, limiter: &mockTokenIncrementer{}}
	writer.WriteContentLogsBatch(context.Background(), envelope, []ContentLogEntry{
		{Role: "user", Content: "dify 和 Codex 对比", MessageIndex: 0},
		{Role: "system", Content: "You are Claude Code, Anthropic's official CLI for Claude.", MessageIndex: 1},
	})
	found := false
	for i, q := range mockDB.queries {
		if strings.Contains(q, "agent_detection_source = 'content'") && mockDB.args[i][0] == "claude-code" {
			found = true
		}
	}
	if !found {
		t.Fatalf("system assertion should still backfill claude-code; queries=%d", len(mockDB.queries))
	}
}
