package handler

import (
	"fmt"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestChatToolEvidenceCorrelationPersistsCausalRunWithoutFalseMerges(t *testing.T) {
	db, ctx, tenantID, projectID, providerID, modelID := setupAuditWriterNullUserFixture(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	userA, userB := "user_chain_a_"+suffix, "user_chain_b_"+suffix
	if _, err := db.Exec(ctx, `
		INSERT INTO users (id, tenant_id, username) VALUES
			($1, $3, $1), ($2, $3, $2)
	`, userA, userB, tenantID); err != nil {
		t.Fatalf("seed users: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, `DELETE FROM request_logs WHERE tenant_id = $1`, tenantID)
		_, _ = db.Exec(ctx, `DELETE FROM users WHERE tenant_id = $1 AND id IN ($2, $3)`, tenantID, userA, userB)
	})

	writer := &RealAuditWriter{db: &realDBExecutor{pool: db}}
	newEnvelope := func(requestID, userID, sourceIP string) *modelrouter.RequestEnvelope {
		envelope := &modelrouter.RequestEnvelope{
			RequestID: requestID, TenantID: tenantID, EnvironmentScope: "customer",
			ProjectID: projectID, UserID: userID, ClientID: "key-chain-" + suffix,
			ProviderID: providerID, Provider: "openai", ModelID: modelID, Model: "test-model",
			EndpointType: "chat", SourceIP: sourceIP, AgentType: "openai-codex", AgentRuntime: "vscode",
		}
		initializeChatToolEvidenceSubject(envelope)
		return envelope
	}
	persist := func(envelope *modelrouter.RequestEnvelope) {
		t.Helper()
		writer.EnsureRequestLog(ctx, envelope)
		writer.FinalizeRequestLog(ctx, envelope, nil, "success", 200, 1, nil)
	}

	const callA = "fc_0e7bdc5f225517c0016a993fac715487d1b3d9cbdb35f365ca"
	const callB = "fc_03e21e3ef612be14016a993fc2b7ac87d1a34e600e538e9e7c"
	const callC = "fc_0d46ed3cf7348039016a993fd3f36487d192ad481b23dbc8c0"
	tools := []ToolDef{{Type: "function", Function: ToolFunc{Name: "ToolSearch"}}}
	initial := Message{Role: "user", Content: jsonQuote("可以了啊没")}
	firstRequest := &ChatCompletionRequest{Tools: tools, Messages: []Message{initial}}
	first := newEnvelope("req_chain_1_"+suffix, userA, "192.0.2.10")
	first.EvidenceRunID = deriveEvidenceRunID(tenantID, "responses_prompt_cache_key_candidate", "weak-cache-key")
	first.EvidenceRunSource = "responses_prompt_cache_key_candidate"
	first.EvidenceRunPrefixHash = chatToolMessagePrefixHash(firstRequest, len(firstRequest.Messages))
	writer.EnsureRequestLog(ctx, first)
	bindChatToolEvidenceFromResponse(first, []byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"`+callA+`","type":"function","function":{"name":"ToolSearch","arguments":"{}"}}]}}]}`))
	writer.FinalizeRequestLog(ctx, first, nil, "success", 200, 1, nil)

	proposalA := Message{Role: "assistant", ToolCalls: []ToolCall{{ID: callA, Type: "function", Function: ToolCallFunc{Name: "ToolSearch"}}}}
	resultA := Message{Role: "tool", ToolCallID: callA, Content: jsonQuote("result-a")}
	proposalB := Message{Role: "assistant", ToolCalls: []ToolCall{{ID: callB, Type: "function", Function: ToolCallFunc{Name: "ToolSearch"}}}}
	resultB := Message{Role: "tool", ToolCallID: callB, Content: jsonQuote("result-b")}
	proposalC := Message{Role: "assistant", ToolCalls: []ToolCall{{ID: callC, Type: "function", Function: ToolCallFunc{Name: "ToolSearch"}}}}
	resultC := Message{Role: "tool", ToolCallID: callC, Content: jsonQuote("result-c")}
	chainMessages := [][]Message{
		{initial, proposalA, resultA},
		{initial, proposalA, resultA, proposalB, resultB},
		{initial, proposalA, resultA, proposalB, resultB, proposalC, resultC},
	}
	for index, messages := range chainMessages {
		envelope := newEnvelope(fmt.Sprintf("req_chain_%d_%s", index+2, suffix), userA, "192.0.2.10")
		bindChatToolEvidenceFromRequest(envelope, &ChatCompletionRequest{Tools: tools, Messages: messages})
		persist(envelope)
	}

	var physical, logical int
	var source string
	if err := db.QueryRow(ctx, `
		SELECT COUNT(*)::int, COUNT(DISTINCT evidence_run_id)::int, MIN(evidence_run_source)
		FROM request_logs
		WHERE tenant_id = $1 AND request_id LIKE $2
	`, tenantID, "req_chain_%_"+suffix).Scan(&physical, &logical, &source); err != nil {
		t.Fatalf("query causal chain: %v", err)
	}
	if physical != 4 || logical != 1 || source != chatToolCallEvidenceSource {
		t.Fatalf("causal chain persisted physical=%d logical=%d source=%q, want 4/1/%q", physical, logical, source, chatToolCallEvidenceSource)
	}

	// Repeating the same user text is not correlation evidence, even for two
	// users sharing the same API key, project, source, provider, model, and agent.
	for index, userID := range []string{userA, userB} {
		envelope := newEnvelope(fmt.Sprintf("req_repeat_%d_%s", index, suffix), userID, "192.0.2.20")
		bindChatToolEvidenceFromRequest(envelope, &ChatCompletionRequest{Messages: []Message{initial}})
		persist(envelope)
	}
	if err := db.QueryRow(ctx, `
		SELECT COUNT(DISTINCT COALESCE(NULLIF(evidence_run_id, ''), request_id))::int
		FROM request_logs WHERE tenant_id = $1 AND request_id LIKE $2
	`, tenantID, "req_repeat_%_"+suffix).Scan(&logical); err != nil {
		t.Fatalf("query repeated text rows: %v", err)
	}
	if logical != 2 {
		t.Fatalf("two users repeating one sentence collapsed into %d task(s)", logical)
	}

	pair := func(userText string) *ChatCompletionRequest {
		return &ChatCompletionRequest{Tools: tools, Messages: []Message{
			{Role: "user", Content: jsonQuote(userText)}, proposalA, resultA,
		}}
	}
	differentPrincipalA := newEnvelope("req_principal_a_"+suffix, userA, "192.0.2.30")
	differentPrincipalB := newEnvelope("req_principal_b_"+suffix, userA, "192.0.2.31")
	bindChatToolEvidenceFromRequest(differentPrincipalA, pair("same prefix"))
	bindChatToolEvidenceFromRequest(differentPrincipalB, pair("same prefix"))
	if differentPrincipalA.EvidenceRunID == differentPrincipalB.EvidenceRunID {
		t.Fatal("different source principals shared a tool-derived run")
	}
	persist(differentPrincipalA)
	persist(differentPrincipalB)

	differentPrefixA := newEnvelope("req_prefix_a_"+suffix, userA, "192.0.2.40")
	differentPrefixB := newEnvelope("req_prefix_b_"+suffix, userA, "192.0.2.40")
	bindChatToolEvidenceFromRequest(differentPrefixA, pair("prefix A"))
	bindChatToolEvidenceFromRequest(differentPrefixB, pair("prefix B"))
	if differentPrefixA.EvidenceRunID == differentPrefixB.EvidenceRunID {
		t.Fatal("same tool id without the same transcript prefix shared a run")
	}
	persist(differentPrefixA)
	persist(differentPrefixB)
}
