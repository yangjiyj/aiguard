package handler

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestResponsesEvidenceCorrelationPrefersStableClientMetadataOverPromptCacheKey(t *testing.T) {
	req := &ResponsesRequest{
		PromptCacheKey: "codex-thread-secret",
		ClientMetadata: map[string]interface{}{"thread_id": "thread-secondary", "client": "codex"},
	}
	key, source := responsesEvidenceCorrelation(req)
	if key != "thread-secondary" || source != "responses_client_thread_id" {
		t.Fatalf("correlation=(%q,%q)", key, source)
	}
}

func TestResponsesEvidenceCorrelationMarksPromptCacheKeyAsCandidate(t *testing.T) {
	key, source := responsesEvidenceCorrelation(&ResponsesRequest{PromptCacheKey: "codex-cache-key"})
	if key != "codex-cache-key" || source != "responses_prompt_cache_key_candidate" {
		t.Fatalf("correlation=(%q,%q)", key, source)
	}
}

func TestResponsesEvidenceCorrelationUsesStableClientMetadata(t *testing.T) {
	req := &ResponsesRequest{ClientMetadata: map[string]interface{}{
		"client": "codex", "thread_id": "thread-42",
	}}
	key, source := responsesEvidenceCorrelation(req)
	if key != "thread-42" || source != "responses_client_thread_id" {
		t.Fatalf("correlation=(%q,%q)", key, source)
	}
}

func TestResponsesEvidenceCorrelationRejectsNonUniqueMetadata(t *testing.T) {
	key, source := responsesEvidenceCorrelation(&ResponsesRequest{
		ClientMetadata: map[string]interface{}{"client": "codex"},
	})
	if key != "" || source != "" {
		t.Fatalf("non-unique metadata must not group requests: (%q,%q)", key, source)
	}
}

func TestWorkBuddyEvidenceCorrelationUsesWorkspaceFolder(t *testing.T) {
	messages := []Message{{
		Role:    "user",
		Content: json.RawMessage(`"<system-reminder>\n<user_info>\nWorkspace Folder: /Users/yj/WorkBuddy/2026-08-24-22-46-33\n</user_info>\n</system-reminder>\n<user_query>修复留证</user_query>"`),
	}}
	key, source := workBuddyEvidenceCorrelation("workbuddy", messages)
	if key != "/Users/yj/WorkBuddy/2026-08-24-22-46-33" || source != "workbuddy_workspace" {
		t.Fatalf("unexpected WorkBuddy evidence correlation: key=%q source=%q", key, source)
	}
}

func TestWorkBuddyEvidenceCorrelationRejectsOtherAgentsAndMissingWorkspace(t *testing.T) {
	messages := []Message{{Role: "user", Content: json.RawMessage(`"Workspace Folder: /tmp/task"`)}}
	if key, source := workBuddyEvidenceCorrelation("openai-codex", messages); key != "" || source != "" {
		t.Fatalf("other agent must not use WorkBuddy workspace correlation: key=%q source=%q", key, source)
	}
	if key, source := workBuddyEvidenceCorrelation("workbuddy", []Message{{Role: "user", Content: json.RawMessage(`"<user_query>只有问题</user_query>"`)}}); key != "" || source != "" {
		t.Fatalf("missing workspace must stay unlinked: key=%q source=%q", key, source)
	}
}

func TestEvidenceRunIDIsTenantScopedAndDoesNotLeakCorrelationKey(t *testing.T) {
	a := deriveEvidenceRunID("tenant-a", "responses_prompt_cache_key", "raw-secret-key")
	b := deriveEvidenceRunID("tenant-b", "responses_prompt_cache_key", "raw-secret-key")
	if a == b || !strings.HasPrefix(a, "run_") || len(a) != 36 {
		t.Fatalf("unexpected run ids: %q %q", a, b)
	}
	if strings.Contains(a, "raw-secret-key") {
		t.Fatalf("run id leaked raw key: %q", a)
	}
}

func chatToolTestEnvelope() *modelrouter.RequestEnvelope {
	envelope := &modelrouter.RequestEnvelope{
		TenantID: "tenant-a", EnvironmentScope: "customer", UserID: "user-a",
		ClientID: "key-a", ProjectID: "project-a", SourceIP: "192.0.2.10",
		ProviderID: "provider-a", Provider: "openai", ModelID: "model-a", Model: "gpt-5",
		EndpointType: "chat", AgentType: "openai-codex", AgentRuntime: "vscode",
	}
	initializeChatToolEvidenceSubject(envelope)
	return envelope
}

func TestChatToolEvidenceCorrelationKeepsCumulativeToolChainTogether(t *testing.T) {
	const callA = "fc_0e7bdc5f225517c0016a993fac715487d1b3d9cbdb35f365ca"
	const callB = "fc_03e21e3ef612be14016a993fc2b7ac87d1a34e600e538e9e7c"
	const callC = "fc_0d46ed3cf7348039016a993fd3f36487d192ad481b23dbc8c0"
	initial := Message{Role: "user", Content: json.RawMessage(`"可以了啊没"`)}
	firstRequest := &ChatCompletionRequest{Tools: []ToolDef{{Type: "function", Function: ToolFunc{Name: "ToolSearch"}}}, Messages: []Message{initial}}
	first := chatToolTestEnvelope()
	first.EvidenceRunPrefixHash = chatToolMessagePrefixHash(firstRequest, len(firstRequest.Messages))
	bindChatToolEvidenceFromRequest(first, firstRequest)
	if first.EvidenceRunID != "" {
		t.Fatalf("ordinary user input must stay unlinked, got %q", first.EvidenceRunID)
	}
	bindChatToolEvidenceFromResponse(first, []byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"`+callA+`","type":"function","function":{"name":"ToolSearch","arguments":"{}"}}]}}]}`))
	if first.EvidenceRunID == "" || first.EvidenceRunSource != chatToolCallEvidenceSource {
		t.Fatalf("first proposed call did not establish a run: %+v", first)
	}

	proposalA := Message{Role: "assistant", ToolCalls: []ToolCall{{ID: callA, Type: "function", Function: ToolCallFunc{Name: "ToolSearch"}}}}
	resultA := Message{Role: "tool", ToolCallID: callA, Content: json.RawMessage(`"result-a"`)}
	proposalB := Message{Role: "assistant", ToolCalls: []ToolCall{{ID: callB, Type: "function", Function: ToolCallFunc{Name: "ToolSearch"}}}}
	resultB := Message{Role: "tool", ToolCallID: callB, Content: json.RawMessage(`"result-b"`)}
	proposalC := Message{Role: "assistant", ToolCalls: []ToolCall{{ID: callC, Type: "function", Function: ToolCallFunc{Name: "ToolSearch"}}}}
	resultC := Message{Role: "tool", ToolCallID: callC, Content: json.RawMessage(`"result-c"`)}
	for step, messages := range [][]Message{
		{initial, proposalA, resultA},
		{initial, proposalA, resultA, proposalB, resultB},
		{initial, proposalA, resultA, proposalB, resultB, proposalC, resultC},
	} {
		next := chatToolTestEnvelope()
		bindChatToolEvidenceFromRequest(next, &ChatCompletionRequest{Tools: firstRequest.Tools, Messages: messages})
		if next.EvidenceRunID != first.EvidenceRunID {
			t.Fatalf("step %d run=%q, want root run %q", step+2, next.EvidenceRunID, first.EvidenceRunID)
		}
	}
}

func TestChatToolEvidenceCorrelationUsesOneAnchorForParallelResults(t *testing.T) {
	const callA = "call_0123456789abcdef_parallel_a"
	const callB = "call_0123456789abcdef_parallel_b"
	initial := Message{Role: "user", Content: json.RawMessage(`"parallel task"`)}
	request := &ChatCompletionRequest{
		Tools:    []ToolDef{{Type: "function", Function: ToolFunc{Name: "worker"}}},
		Messages: []Message{initial},
	}
	first := chatToolTestEnvelope()
	first.EvidenceRunPrefixHash = chatToolMessagePrefixHash(request, len(request.Messages))
	bindChatToolEvidenceFromResponse(first, []byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"`+callA+`","type":"function","function":{"name":"worker","arguments":"{\"n\":1}"}},{"id":"`+callB+`","type":"function","function":{"name":"worker","arguments":"{\"n\":2}"}}]}}]}`))
	if first.EvidenceRunID == "" {
		t.Fatal("parallel proposal did not establish a run")
	}

	nextRequest := &ChatCompletionRequest{Tools: request.Tools, Messages: []Message{
		initial,
		{Role: "assistant", ToolCalls: []ToolCall{
			{ID: callA, Type: "function", Function: ToolCallFunc{Name: "worker", Arguments: `{"n":1}`}},
			{ID: callB, Type: "function", Function: ToolCallFunc{Name: "worker", Arguments: `{"n":2}`}},
		}},
		{Role: "tool", ToolCallID: callB, Content: json.RawMessage(`"B finished first"`)},
	}}
	next := chatToolTestEnvelope()
	bindChatToolEvidenceFromRequest(next, nextRequest)
	if next.EvidenceRunID != first.EvidenceRunID {
		t.Fatalf("B-first parallel result run=%q, want batch anchor run=%q", next.EvidenceRunID, first.EvidenceRunID)
	}
}

func TestChatToolEvidenceCorrelationRejectsSiblingAfterParallelAnchorReplay(t *testing.T) {
	const callA = "call_0123456789abcdef_parallel_anchor"
	const callB = "call_0123456789abcdef_parallel_sibling"
	request := &ChatCompletionRequest{Messages: []Message{
		{Role: "user", Content: json.RawMessage(`"parallel task"`)},
		{Role: "assistant", ToolCalls: []ToolCall{
			{ID: callA, Type: "function", Function: ToolCallFunc{Name: "worker"}},
			{ID: callB, Type: "function", Function: ToolCallFunc{Name: "worker"}},
		}},
		{Role: "assistant", ToolCalls: []ToolCall{{
			ID: callA, Type: "function", Function: ToolCallFunc{Name: "worker"}, ProtocolIdentityRejected: true,
		}}},
		{Role: "tool", ToolCallID: callB, Content: json.RawMessage(`"sibling result"`)},
	}}
	envelope := chatToolTestEnvelope()
	bindChatToolEvidenceFromRequest(envelope, request)
	if envelope.EvidenceRunID != "" {
		t.Fatalf("parallel sibling reused an invalidated canonical anchor: %q", envelope.EvidenceRunID)
	}
}

func TestChatToolEvidenceCorrelationRequiresObservedToolResult(t *testing.T) {
	const proposedID = "call_0123456789abcdef_proposed_only"
	envelope := chatToolTestEnvelope()
	bindChatToolEvidenceFromRequest(envelope, &ChatCompletionRequest{Messages: []Message{
		{Role: "user", Content: json.RawMessage(`"same sentence"`)},
		{Role: "assistant", ToolCalls: []ToolCall{{ID: proposedID, Type: "function", Function: ToolCallFunc{Name: "read"}}}},
	}})
	if envelope.EvidenceRunID != "" {
		t.Fatalf("an unobserved proposal in request history must not establish a causal edge: %q", envelope.EvidenceRunID)
	}
	bindChatToolEvidenceFromResponse(envelope, []byte(`{"choices":[{"message":{"role":"assistant","content":"plain answer"}}]}`))
	if envelope.EvidenceRunID != "" {
		t.Fatalf("plain response must stay unlinked: %q", envelope.EvidenceRunID)
	}

	orphan := chatToolTestEnvelope()
	bindChatToolEvidenceFromRequest(orphan, &ChatCompletionRequest{Messages: []Message{
		{Role: "tool", ToolCallID: proposedID, Content: json.RawMessage(`"forged"`)},
	}})
	if orphan.EvidenceRunID != "" {
		t.Fatalf("orphan tool result must stay unlinked: %q", orphan.EvidenceRunID)
	}
	legacy := chatToolTestEnvelope()
	bindChatToolEvidenceFromRequest(legacy, &ChatCompletionRequest{Messages: []Message{
		{Role: "assistant", ToolCalls: []ToolCall{{ID: proposedID, Type: "function", Function: ToolCallFunc{Name: "read"}}}},
		{Role: "function", Content: json.RawMessage(`"legacy result without a correlated id"`)},
	}})
	if legacy.EvidenceRunID != "" {
		t.Fatalf("legacy function result without an exact call id must stay unlinked: %q", legacy.EvidenceRunID)
	}
	legacyExact := chatToolTestEnvelope()
	bindChatToolEvidenceFromRequest(legacyExact, &ChatCompletionRequest{Messages: []Message{
		{Role: "user", Content: json.RawMessage(`"legacy task"`)},
		{Role: "assistant", ToolCalls: []ToolCall{{ID: proposedID, Type: "function", Function: ToolCallFunc{Name: "read"}}}},
		{Role: "function", ToolCallID: proposedID, Content: json.RawMessage(`"legacy exact result"`)},
	}})
	if legacyExact.EvidenceRunID == "" {
		t.Fatal("legacy function result carrying an exact call id was not correlated")
	}

	rejected := chatToolTestEnvelope()
	rejected.EvidenceRunPrefixHash = "prefix-a"
	bindChatToolEvidenceFromResponse(rejected, []byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call_0123456789abcdef_rejected","_jjdguard_protocol_identity_rejected":true}]}}]}`))
	if rejected.EvidenceRunID != "" {
		t.Fatalf("protocol-rejected proposal must stay unlinked: %q", rejected.EvidenceRunID)
	}
}

func TestChatToolEvidenceCorrelationDoesNotGroupRepeatedTextWithoutToolEvidence(t *testing.T) {
	for _, userID := range []string{"user-a", "user-b"} {
		envelope := chatToolTestEnvelope()
		envelope.UserID = userID
		initializeChatToolEvidenceSubject(envelope)
		bindChatToolEvidenceFromRequest(envelope, &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: json.RawMessage(`"可以了啊没"`)}}})
		if envelope.EvidenceRunID != "" {
			t.Fatalf("user %s repeated text was grouped without tool causality: %q", userID, envelope.EvidenceRunID)
		}
	}
}

func TestChatToolEvidenceCorrelationSeparatesEveryStrictSubjectDimension(t *testing.T) {
	const callID = "call_0123456789abcdef_same_full_text"
	base := chatToolTestEnvelope()
	bindChatToolEvidence(base, "prefix-a", callID)
	if base.EvidenceRunID == "" {
		t.Fatal("baseline run id is empty")
	}

	tests := map[string]func(*modelrouter.RequestEnvelope){
		"tenant":    func(e *modelrouter.RequestEnvelope) { e.TenantID = "tenant-b" },
		"scope":     func(e *modelrouter.RequestEnvelope) { e.EnvironmentScope = "test" },
		"user":      func(e *modelrouter.RequestEnvelope) { e.UserID = "user-b" },
		"client":    func(e *modelrouter.RequestEnvelope) { e.ClientID = "key-b" },
		"project":   func(e *modelrouter.RequestEnvelope) { e.ProjectID = "project-b" },
		"source ip": func(e *modelrouter.RequestEnvelope) { e.SourceIP = "192.0.2.11" },
		"provider":  func(e *modelrouter.RequestEnvelope) { e.ProviderID = "provider-b" },
		"model":     func(e *modelrouter.RequestEnvelope) { e.ModelID = "model-b" },
		"agent":     func(e *modelrouter.RequestEnvelope) { e.AgentType = "cline" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := chatToolTestEnvelope()
			mutate(candidate)
			initializeChatToolEvidenceSubject(candidate)
			bindChatToolEvidence(candidate, "prefix-a", callID)
			if candidate.EvidenceRunID == base.EvidenceRunID {
				t.Fatalf("changed %s shared run %q", name, candidate.EvidenceRunID)
			}
		})
	}
}

func TestChatToolEvidenceCorrelationUsesFullIDAndPreservesNativeKeys(t *testing.T) {
	prefix := "call_0123456789abcdef_" + strings.Repeat("x", 128)
	a, b := chatToolTestEnvelope(), chatToolTestEnvelope()
	bindChatToolEvidence(a, "prefix-a", prefix+"A")
	bindChatToolEvidence(b, "prefix-a", prefix+"B")
	if a.EvidenceRunID == b.EvidenceRunID {
		t.Fatalf("tool ids differing after a long common prefix were truncated: %q", a.EvidenceRunID)
	}

	native := chatToolTestEnvelope()
	native.EvidenceRunID, native.EvidenceRunSource = "run_native", "client_thread_id"
	bindChatToolEvidence(native, "prefix-a", "call_0123456789abcdef_forged")
	bindChatToolEvidenceFromResponse(native, []byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"call-response"}]}}]}`))
	if native.EvidenceRunID != "run_native" || native.EvidenceRunSource != "client_thread_id" {
		t.Fatalf("tool correlation overrode native evidence: %+v", native)
	}

	session := chatToolTestEnvelope()
	session.SessionID = "session-native"
	bindChatToolEvidence(session, "prefix-a", "call_0123456789abcdef_session")
	if session.EvidenceRunID != "" {
		t.Fatalf("tool correlation overrode native session: %+v", session)
	}

	differentPrefix := chatToolTestEnvelope()
	bindChatToolEvidence(differentPrefix, "prefix-b", prefix+"A")
	if differentPrefix.EvidenceRunID == a.EvidenceRunID {
		t.Fatalf("same tool id with a different transcript prefix shared run %q", a.EvidenceRunID)
	}
	short := chatToolTestEnvelope()
	bindChatToolEvidence(short, "prefix-a", "call_1")
	if short.EvidenceRunID != "" {
		t.Fatalf("reusable low-entropy tool id must stay unlinked: %q", short.EvidenceRunID)
	}
	controlled := chatToolTestEnvelope()
	bindChatToolEvidence(controlled, "prefix-a", "call_0123456789abc\ndef_control")
	if controlled.EvidenceRunID != "" {
		t.Fatalf("tool id containing controls must stay unlinked: %q", controlled.EvidenceRunID)
	}

	weak := chatToolTestEnvelope()
	weak.EvidenceRunID, weak.EvidenceRunSource = "run_weak", "responses_prompt_cache_key_candidate"
	bindChatToolEvidence(weak, "prefix-a", prefix+"A")
	if weak.EvidenceRunID != a.EvidenceRunID || weak.EvidenceRunSource != chatToolCallEvidenceSource {
		t.Fatalf("strong tool evidence did not replace weak prompt-cache hint: %+v", weak)
	}
}

func TestChatToolEvidenceCorrelationRejectsConflictingCallIdentity(t *testing.T) {
	const callID = "call_0123456789abcdef_conflict"
	request := &ChatCompletionRequest{Messages: []Message{
		{Role: "user", Content: json.RawMessage(`"task"`)},
		{Role: "assistant", ToolCalls: []ToolCall{
			{ID: callID, Type: "function", Function: ToolCallFunc{Name: "read", Arguments: `{}`}},
			{ID: callID, Type: "function", Function: ToolCallFunc{Name: "delete", Arguments: `{}`}},
		}},
		{Role: "tool", ToolCallID: callID, Content: json.RawMessage(`"result"`)},
	}}
	envelope := chatToolTestEnvelope()
	bindChatToolEvidenceFromRequest(envelope, request)
	if envelope.EvidenceRunID != "" {
		t.Fatalf("conflicting request identity must stay unlinked: %q", envelope.EvidenceRunID)
	}

	envelope.EvidenceRunPrefixHash = "prefix-a"
	bindChatToolEvidenceFromResponse(envelope, []byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"`+callID+`","type":"function","function":{"name":"read","arguments":"{}"}},{"id":"`+callID+`","type":"function","function":{"name":"delete","arguments":"{}"}}]}}]}`))
	if envelope.EvidenceRunID != "" {
		t.Fatalf("conflicting response identity must stay unlinked: %q", envelope.EvidenceRunID)
	}
}

func TestChatToolEvidenceCorrelationRejectsLaterAmbiguousReplay(t *testing.T) {
	const callID = "call_0123456789abcdef_replayed"
	valid := ToolCall{ID: callID, Type: "function", Function: ToolCallFunc{Name: "read", Arguments: `{}`}}
	for name, replay := range map[string][]ToolCall{
		"duplicate":    {valid, valid},
		"rejected":     {{ID: callID, Type: "function", Function: ToolCallFunc{Name: "read"}, ProtocolIdentityRejected: true}},
		"missing name": {{ID: callID, Type: "function"}},
	} {
		t.Run(name, func(t *testing.T) {
			request := &ChatCompletionRequest{Messages: []Message{
				{Role: "user", Content: json.RawMessage(`"task"`)},
				{Role: "assistant", ToolCalls: []ToolCall{valid}},
				{Role: "assistant", ToolCalls: replay},
				{Role: "tool", ToolCallID: callID, Content: json.RawMessage(`"ambiguous result"`)},
			}}
			envelope := chatToolTestEnvelope()
			bindChatToolEvidenceFromRequest(envelope, request)
			if envelope.EvidenceRunID != "" {
				t.Fatalf("later %s replay reused an earlier proposal: %q", name, envelope.EvidenceRunID)
			}
		})
	}
}

func TestShouldPrepareChatToolEvidenceSkipsUnrelatedAndNativeRequests(t *testing.T) {
	toolRequest := &ChatCompletionRequest{Tools: []ToolDef{{Type: "function", Function: ToolFunc{Name: "read"}}}}
	if !shouldPrepareChatToolEvidence(chatToolTestEnvelope(), toolRequest) {
		t.Fatal("unlinked agent tool request must prepare correlation evidence")
	}
	if shouldPrepareChatToolEvidence(chatToolTestEnvelope(), &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: json.RawMessage(`"large ordinary request"`)}}}) {
		t.Fatal("ordinary request must not copy and hash the full transcript")
	}
	noAgent := chatToolTestEnvelope()
	noAgent.AgentType = ""
	initializeChatToolEvidenceSubject(noAgent)
	if shouldPrepareChatToolEvidence(noAgent, toolRequest) {
		t.Fatal("unidentified traffic must not prepare agent correlation")
	}
	native := chatToolTestEnvelope()
	native.EvidenceRunID, native.EvidenceRunSource = "run_native", "responses_client_thread_id"
	if shouldPrepareChatToolEvidence(native, toolRequest) {
		t.Fatal("native run identity must bypass transcript hashing")
	}
	native = chatToolTestEnvelope()
	native.SessionID = "session-native"
	if shouldPrepareChatToolEvidence(native, toolRequest) {
		t.Fatal("native session identity must bypass transcript hashing")
	}
	weak := chatToolTestEnvelope()
	weak.EvidenceRunID, weak.EvidenceRunSource = "run_weak", "responses_prompt_cache_key_candidate"
	if !shouldPrepareChatToolEvidence(weak, toolRequest) {
		t.Fatal("weak prompt-cache hint must allow stronger causal evidence")
	}
}

func TestChatToolEvidenceProcessHashesAreNotSerialized(t *testing.T) {
	envelope := chatToolTestEnvelope()
	envelope.EvidenceRunPrefixHash = "prefix-secret"
	encoded, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "EvidenceRunSubjectHash") || strings.Contains(string(encoded), "EvidenceRunPrefixHash") || strings.Contains(string(encoded), "prefix-secret") {
		t.Fatalf("process-only evidence hashes escaped into JSON: %s", encoded)
	}
}

func TestNativeResponsesCustomToolCorrelationUsesSameCausalAnchor(t *testing.T) {
	const callID = "call_0123456789abcdef_native_custom"
	tools := []ResponsesTool{{Type: "custom", Name: "shell_command", Description: "run a command"}}
	converter := &ResponsesHandler{}
	firstRequest, err := converter.convertToChatRequest(&ResponsesRequest{
		Model: "gpt-5", Input: "inspect status", Tools: tools,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !firstRequest.ToolCorrelationCandidate || firstRequest.ToolCorrelationContextHash == "" {
		t.Fatalf("native custom tool context was lost: %+v", firstRequest)
	}
	first := chatToolTestEnvelope()
	first.EndpointType = "responses"
	initializeChatToolEvidenceSubject(first)
	first.EvidenceRunPrefixHash = chatToolMessagePrefixHash(firstRequest, len(firstRequest.Messages))
	view, err := nativeResponsesSecurityView([]byte(`{"id":"resp_1","output":[{"id":"ctc_1","type":"custom_tool_call","call_id":"` + callID + `","name":"shell_command","input":"pwd"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	bindChatToolEvidenceFromResponse(first, view)
	if first.EvidenceRunID == "" {
		t.Fatal("native custom tool proposal did not establish a run")
	}

	historyRequest, err := converter.convertToChatRequest(&ResponsesRequest{
		Model: "gpt-5", Tools: tools,
		Input: []interface{}{
			map[string]interface{}{"role": "user", "content": "inspect status"},
			map[string]interface{}{"type": "custom_tool_call", "call_id": callID, "name": "shell_command", "input": "pwd"},
			map[string]interface{}{"type": "custom_tool_call_output", "call_id": callID, "output": "ok"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	next := chatToolTestEnvelope()
	next.EndpointType = "responses"
	initializeChatToolEvidenceSubject(next)
	bindChatToolEvidenceFromRequest(next, historyRequest)
	if next.EvidenceRunID != first.EvidenceRunID {
		t.Fatalf("native custom result run=%q, want proposed run=%q", next.EvidenceRunID, first.EvidenceRunID)
	}
}
