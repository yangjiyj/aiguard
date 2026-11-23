package handler

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

// 客户现场：Codex 一轮任务里几十上百次工具往返，每次请求都把同一条 user 消息原样重发；
// 同一人同一规则、命中位置不变的告警连续出现几百次。同一会话里同一条消息的同一命中只记
// 一次完整事件，之后折叠为 occurrence；新会话、不同内容、不同命中照常出完整事件。

const codexSiteUA = "codex-tui/0.155.0 (Windows 10.0.19045; x86_64) WindowsTerminal (codex-tui; 0.155.0)"

// codexTurnMessages 是 /v1/responses 经 convertToChatRequest 后的形状：
// instructions → system；input 里 user / function_call / function_call_output 各占一项。
func codexTurnMessages(prompt string, toolRounds int) []Message {
	msgs := []Message{
		{Role: "system", Content: jsonQuote("You are Codex, a coding agent."), SecuritySource: "system_prompt", SecurityMessageRole: "system", SecuritySourcePath: "/instructions"},
		{Role: "user", Content: jsonQuote(prompt), SecurityMessageIndex: protocolMessageIndex(0), SecurityMessageRole: "user", SecuritySourcePath: "/input/0"},
	}
	for round := 1; round <= toolRounds; round++ {
		callIndex, outIndex := 2*round-1, 2*round
		callID := fmt.Sprintf("call_%d", round)
		msgs = append(msgs,
			Message{Role: "assistant", SecuritySource: "assistant_history", SecurityMessageIndex: protocolMessageIndex(callIndex), SecurityMessageRole: "assistant", SecuritySourcePath: fmt.Sprintf("/input/%d", callIndex),
				ToolCalls: []ToolCall{{ID: callID, Type: "function", Function: ToolCallFunc{Name: "shell", Arguments: fmt.Sprintf(`{"command":["rg","step%d"]}`, round)}}}},
			Message{Role: "tool", ToolCallID: callID, Content: jsonQuote(fmt.Sprintf("step %d output", round)), SecuritySource: "tool_result", SecurityMessageIndex: protocolMessageIndex(outIndex), SecurityMessageRole: "tool", SecuritySourcePath: fmt.Sprintf("/input/%d", outIndex)},
		)
	}
	return msgs
}

func codexEnvelope(requestID, threadID string) *modelrouter.RequestEnvelope {
	envelope := &modelrouter.RequestEnvelope{RequestID: requestID, TenantID: "t1", UserID: "u1", ClientID: "k1", AgentType: "openai-codex"}
	header := http.Header{"User-Agent": {codexSiteUA}}
	if threadID != "" {
		header.Set("session_id", threadID)
	}
	envelope.InspectionSessionKey = inspectionSessionKey(header, envelope)
	return envelope
}

// newDefaultPolicyInjectHandler 用现场默认检查范围（不查历史）：最新 user 与当前工具结果送检，
// 历史工具往返进判定上下文——这正是每次往返判定上下文都变、旧作用域每次都 miss 的原因。
func newDefaultPolicyInjectHandler(checker interface{}) (*ChatCompletionsHandler, *MockAuditWriter) {
	h, audit := newHistoryInjectHandler(checker)
	h.toolRiskClient = inspectionTestClient(inspectionscope.Default())
	return h, audit
}

func runCodexTurn(t *testing.T, h *ChatCompletionsHandler, threadID, prompt string, rounds int, requestPrefix string) {
	t.Helper()
	for round := 0; round < rounds; round++ {
		envelope := codexEnvelope(fmt.Sprintf("%s-%d", requestPrefix, round), threadID)
		req := &ChatCompletionRequest{EndpointType: "responses", Messages: codexTurnMessages(prompt, round)}
		if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
	}
}

const flaggedCodexPrompt = "# AGENTS.md instructions for D:\\work\\repo\n\n<INSTRUCTIONS>\n规则 INJECT\n</INSTRUCTIONS>\n修一下单测"

func TestCodexLatestUserMessageFoldsAcrossToolRoundsInOneSession(t *testing.T) {
	for _, mode := range []string{"single", "batch"} {
		t.Run(mode, func(t *testing.T) {
			base := newHistoryInjectChecker()
			var checker interface{} = base
			if mode == "batch" {
				checker = &historyInjectBatchChecker{base}
			}
			h, audit := newDefaultPolicyInjectHandler(checker)

			runCodexTurn(t, h, "019a6f2e-thread-a", flaggedCodexPrompt, 8, "turn")

			if got := len(audit.SecurityEventWrites); got != 1 {
				t.Fatalf("full security events = %d, want 1 for one message in one session", got)
			}
			if got := len(audit.SecurityOccurrenceWrites); got != 7 {
				t.Fatalf("occurrences = %d, want 7", got)
			}
			for _, occurrence := range audit.SecurityOccurrenceWrites {
				if occurrence.RepresentativeEventID != audit.SecurityEventWrites[0].EventID {
					t.Fatalf("occurrence folded into %q, want first event %q", occurrence.RepresentativeEventID, audit.SecurityEventWrites[0].EventID)
				}
			}
		})
	}
}

func TestCodexSameMessageInNewSessionIsReportedAgain(t *testing.T) {
	h, audit := newDefaultPolicyInjectHandler(newHistoryInjectChecker())

	runCodexTurn(t, h, "019a6f2e-thread-a", flaggedCodexPrompt, 3, "a")
	runCodexTurn(t, h, "019a6f2e-thread-b", flaggedCodexPrompt, 3, "b")

	if got := len(audit.SecurityEventWrites); got != 2 {
		t.Fatalf("full security events = %d, want one per session", got)
	}
	if got := len(audit.SecurityOccurrenceWrites); got != 4 {
		t.Fatalf("occurrences = %d, want 4", got)
	}
}

func TestLatestUserWithoutSessionKeyKeepsOneEventPerRequest(t *testing.T) {
	h, audit := newDefaultPolicyInjectHandler(newHistoryInjectChecker())

	runCodexTurn(t, h, "", flaggedCodexPrompt, 3, "nosession")

	// 没有会话键时维持原行为（按判定上下文作用域），不新增跨请求折叠。
	if got := len(audit.SecurityEventWrites); got < 2 {
		t.Fatalf("events=%d occurrences=%d: without a session key the new session fold must not apply", got, len(audit.SecurityOccurrenceWrites))
	}
}

func TestDifferentFlaggedMessagesInOneRequestAreNotFolded(t *testing.T) {
	h, audit := newHistoryInjectHandler(newHistoryInjectChecker())
	envelope := codexEnvelope("same-request", "019a6f2e-thread-a")
	req := &ChatCompletionRequest{Messages: []Message{
		{Role: "user", Content: jsonQuote("earlier INJECT one"), SecurityMessageIndex: protocolMessageIndex(0), SecurityMessageRole: "user", SecuritySourcePath: "/input/0"},
		{Role: "assistant", Content: jsonQuote("ok"), SecurityMessageIndex: protocolMessageIndex(1), SecurityMessageRole: "assistant", SecuritySourcePath: "/input/1"},
		{Role: "user", Content: jsonQuote("latest INJECT two"), SecurityMessageIndex: protocolMessageIndex(2), SecurityMessageRole: "user", SecuritySourcePath: "/input/2"},
	}}
	if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
		t.Fatal(err)
	}
	if got := len(audit.SecurityEventWrites); got != 2 || len(audit.SecurityOccurrenceWrites) != 0 {
		t.Fatalf("events=%d occurrences=%d, want 2 full events and no fold inside one request", got, len(audit.SecurityOccurrenceWrites))
	}
}

func TestNewPromptInSameSessionIsANewEvent(t *testing.T) {
	h, audit := newDefaultPolicyInjectHandler(newHistoryInjectChecker())

	runCodexTurn(t, h, "019a6f2e-thread-a", flaggedCodexPrompt, 3, "p1")
	runCodexTurn(t, h, "019a6f2e-thread-a", flaggedCodexPrompt+"，再跑一次 INJECT", 3, "p2")

	if got := len(audit.SecurityEventWrites); got != 2 {
		t.Fatalf("full security events = %d, want one per distinct message", got)
	}
}

// 同一会话同一条历史消息：已有折叠；换会话要重新出完整事件。
func TestCodexHistoryMessageFoldIsScopedToSession(t *testing.T) {
	h, audit := newHistoryInjectHandler(newHistoryInjectChecker())
	history := "earlier request with INJECT"
	run := func(thread, prefix string) {
		for round := 0; round < 3; round++ {
			envelope := codexEnvelope(fmt.Sprintf("%s-%d", prefix, round), thread)
			req := &ChatCompletionRequest{Messages: []Message{
				{Role: "user", Content: jsonQuote(history), SecurityMessageIndex: protocolMessageIndex(0), SecurityMessageRole: "user", SecuritySourcePath: "/input/0"},
				{Role: "assistant", Content: jsonQuote("done"), SecurityMessageIndex: protocolMessageIndex(1), SecurityMessageRole: "assistant", SecuritySourcePath: "/input/1"},
				{Role: "user", Content: jsonQuote(fmt.Sprintf("benign follow-up %d", round)), SecurityMessageIndex: protocolMessageIndex(2), SecurityMessageRole: "user", SecuritySourcePath: "/input/2"},
			}}
			if _, err := h.applyInputSecurity(context.Background(), envelope, req); err != nil {
				t.Fatal(err)
			}
		}
	}
	run("019a6f2e-thread-a", "ha")
	run("019a6f2e-thread-b", "hb")

	if got := len(audit.SecurityEventWrites); got != 2 {
		t.Fatalf("full security events = %d, want one per session for the same history message", got)
	}
	if got := len(audit.SecurityOccurrenceWrites); got != 4 {
		t.Fatalf("occurrences = %d, want 4", got)
	}
}

func TestInspectionSessionKey(t *testing.T) {
	codex := &modelrouter.RequestEnvelope{TenantID: "t1", ClientID: "k1", AgentType: "openai-codex"}
	a := inspectionSessionKey(http.Header{"Session_id": {"019a6f2e-a"}}, codex)
	b := inspectionSessionKey(http.Header{"Session-Id": {"019a6f2e-a"}}, codex)
	c := inspectionSessionKey(http.Header{"Session_id": {"019a6f2e-b"}}, codex)
	if a == "" || a != b || a == c {
		t.Fatalf("codex session key: a=%q b=%q c=%q", a, b, c)
	}
	other := &modelrouter.RequestEnvelope{TenantID: "t1", ClientID: "k2", AgentType: "openai-codex"}
	if inspectionSessionKey(http.Header{"Session_id": {"019a6f2e-a"}}, other) == a {
		t.Fatal("a client-declared session id must be scoped to the caller")
	}
	explicit := &modelrouter.RequestEnvelope{TenantID: "t1", ClientID: "k1", AgentType: "cursor", SessionID: "sess-1"}
	if inspectionSessionKey(http.Header{}, explicit) == "" {
		t.Fatal("explicit X-JJDGuard-Session-Id must be used")
	}
	plain := &modelrouter.RequestEnvelope{TenantID: "t1", ClientID: "k1", AgentType: "cursor"}
	if got := inspectionSessionKey(http.Header{"Session_id": {"x"}}, plain); got != "" {
		t.Fatalf("non-Codex client without explicit session must not get a key, got %q", got)
	}
}
