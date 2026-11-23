package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// gateRecordingAuditWriter 记录写入器层闸门 writerPersists 对每次写入的判定和事件 stage，
// 用来守住“观察事件必须带留证标记、stage 为 tool”。
type gateRecordingAuditWriter struct {
	*MockAuditWriter
	persists []bool
	stages   []string
}

func (w *gateRecordingAuditWriter) WriteSecurityEvent(ctx context.Context, envelope *modelrouter.RequestEnvelope, findings []SecurityFinding, actionTaken, summary string) {
	w.persists = append(w.persists, writerPersists(ctx, findings, actionTaken))
	w.stages = append(w.stages, securityEventStageFromContext(ctx))
	w.MockAuditWriter.WriteSecurityEvent(ctx, envelope, findings, actionTaken, summary)
}

type toolFailureTestRig struct {
	h       *ChatCompletionsHandler
	gate    *gateRecordingAuditWriter
	written [][]SecurityFinding
	env     *modelrouter.RequestEnvelope
}

func newToolFailureRig(threshold int) *toolFailureTestRig {
	rig := &toolFailureTestRig{
		env: &modelrouter.RequestEnvelope{TenantID: "t1", ProjectID: "p1", UserID: "u1", SessionID: "s1", RequestID: "r1"},
	}
	mock := &MockAuditWriter{OnSecurityEvent: func(_ string, findings []SecurityFinding) {
		rig.written = append(rig.written, findings)
	}}
	rig.gate = &gateRecordingAuditWriter{MockAuditWriter: mock}
	rig.h = &ChatCompletionsHandler{
		auditWriter:            rig.gate,
		agentGuardToolFailures: agentguard.NewToolFailureWindow(10*time.Minute, threshold),
	}
	return rig
}

func (r *toolFailureTestRig) record(history []Message) {
	r.h.recordToolResultFailures(context.Background(), r.env, history)
}

func (r *toolFailureTestRig) count(tool string) int {
	return r.h.agentGuardToolFailures.Count(agentGuardActorKey(r.env), tool, time.Now())
}

var (
	toolFailedContent = json.RawMessage(`"{\"is_error\": true, \"content\": \"boom\"}"`)
	toolOKContent     = json.RawMessage(`"ok"`)
)

func assistantCall(id, name string) Message {
	return Message{Role: "assistant", ToolCalls: []ToolCall{{ID: id, Function: ToolCallFunc{Name: name}}}}
}

func toolResult(id string, content json.RawMessage) Message {
	return Message{Role: "tool", ToolCallID: id, Content: content}
}

func TestToolFailureLoopWrittenOnceAsRuntimeObservationAtThreshold(t *testing.T) {
	rig := newToolFailureRig(3)
	var history []Message
	for round := 1; round <= 3; round++ {
		id := fmt.Sprintf("call-%d", round)
		history = append(history, assistantCall(id, "Bash"), toolResult(id, toolFailedContent))
		rig.record(history)
		if round < 3 && len(rig.written) != 0 {
			t.Fatalf("round %d must not reach the threshold yet: %+v", round, rig.written)
		}
	}
	if len(rig.written) != 1 || len(rig.written[0]) != 1 {
		t.Fatalf("the third round must write exactly one event with one finding, got %+v", rig.written)
	}
	if got := rig.count("Bash"); got != 3 {
		t.Fatalf("a growing session must count 3, not 1+2+3; got %d", got)
	}
	finding := rig.written[0][0]
	if finding.CountsAsSecurityFinding == nil || *finding.CountsAsSecurityFinding {
		t.Fatalf("tool failure loop must not count as a security finding: %+v", finding)
	}
	if finding.Category != toolFailureLoopCategory || finding.EvidenceKind != "runtime" || finding.Severity != "low" {
		t.Fatalf("unexpected finding shape: %+v", finding)
	}
	if finding.RuleName != "Bash" || finding.RedactedEvidence != "Bash 在窗口内失败 3 次" {
		t.Fatalf("evidence must name the tool and count: %+v", finding)
	}
	if !hasRetainedObservations([]SecurityFinding{finding}) {
		t.Fatal("the runtime observation must pass the writer's retained-observation gate")
	}
	if len(rig.gate.persists) != 1 || !rig.gate.persists[0] {
		t.Fatalf("writer gate must persist the observation event (needs withRetainedObservationEvent), got %v", rig.gate.persists)
	}
	if len(rig.gate.stages) != 1 || rig.gate.stages[0] != "tool" {
		t.Fatalf("event stage must be tool, got %v", rig.gate.stages)
	}
}

func TestToolFailureLoopIgnoresOldFailuresAfterRestart(t *testing.T) {
	rig := newToolFailureRig(2)
	var history []Message
	for i := 1; i <= 6; i++ {
		id := fmt.Sprintf("old-%d", i)
		history = append(history, assistantCall(id, "Bash"), toolResult(id, toolFailedContent))
	}
	history = append(history, assistantCall("new-1", "Bash"), toolResult("new-1", toolFailedContent))
	rig.record(history)
	if got := rig.count("Bash"); got != 1 {
		t.Fatalf("only this turn's failure may be counted after a restart, got %d", got)
	}
	if len(rig.written) != 0 {
		t.Fatalf("no event expected, got %+v", rig.written)
	}
}

func TestToolFailureLoopCountsMultiBlockResultOnce(t *testing.T) {
	rig := newToolFailureRig(5)
	rig.record([]Message{
		assistantCall("call-1", "Bash"),
		toolResult("call-1", toolOKContent),
		toolResult("call-1", toolFailedContent),
	})
	if got := rig.count("Bash"); got != 1 {
		t.Fatalf("an error in the second block must count once, got %d", got)
	}
	rig.record([]Message{
		assistantCall("call-2", "Bash"),
		toolResult("call-2", toolFailedContent),
		toolResult("call-2", toolFailedContent),
	})
	if got := rig.count("Bash"); got != 2 {
		t.Fatalf("two failing blocks of one call must still count once, got %d total", got)
	}
}

func TestToolFailureLoopDetectsRepeatedSyntheticCallIDsAcrossRounds(t *testing.T) {
	rig := newToolFailureRig(2)
	var history []Message
	for round := 1; round <= 2; round++ {
		history = append(history, assistantCall("call_0_0", "Bash"), toolResult("call_0_0", toolFailedContent))
		rig.record(history)
	}
	if len(rig.written) != 1 {
		t.Fatalf("repeated synthetic ids must not hide a real retry loop, got %d events", len(rig.written))
	}
}

func TestToolFailureLoopUsesThisTurnsToolName(t *testing.T) {
	rig := newToolFailureRig(1)
	rig.record([]Message{
		assistantCall("call_0_0", "Read"),
		toolResult("call_0_0", toolOKContent),
		assistantCall("call_0_0", "Bash"),
		toolResult("call_0_0", toolFailedContent),
	})
	if len(rig.written) != 1 || rig.written[0][0].RuleName != "Bash" {
		t.Fatalf("expected one event for Bash, got %+v", rig.written)
	}
}

func TestToolFailureLoopIgnoresTrailingAssistantMessage(t *testing.T) {
	rig := newToolFailureRig(1)
	rig.record([]Message{
		assistantCall("call-1", "Bash"),
		toolResult("call-1", toolFailedContent),
		assistantCall("call-2", "Bash"),
	})
	if got := rig.count("Bash"); got != 0 || len(rig.written) != 0 {
		t.Fatalf("a history ending with an assistant message has no new results; count=%d events=%+v", got, rig.written)
	}
}

func TestToolFailuresThisTurnSkipsNamelessAndUnknownCalls(t *testing.T) {
	got := toolFailuresThisTurn([]Message{
		{Role: "assistant", ToolCalls: []ToolCall{
			{ID: "a", Function: ToolCallFunc{Name: ""}},
			{ID: "b", Function: ToolCallFunc{Name: " Read "}},
		}},
		toolResult("a", toolFailedContent),
		toolResult("zzz", toolFailedContent),
		toolResult("b", toolFailedContent),
	})
	if len(got) != 1 || got[0].name != " Read " {
		t.Fatalf("expected the raw name \" Read \" (matches the escalation lookup), got %+v", got)
	}
}

const toolFailureText = `{"is_error": true, "content": "boom"}`

// nativeToolRounds 构造真实的 /v1/messages 请求体：每轮 assistant 一个 tool_use，随后 user 一个 tool_result。
func nativeToolRounds(t *testing.T, rounds int, resultText string) []Message {
	t.Helper()
	return nativeToolResultRounds(t, rounds, resultText, false)
}

// nativeToolResultRounds 同 nativeToolRounds，isError 为真时 tool_result 带 is_error:true（Claude Code 的失败结果）。
func nativeToolResultRounds(t *testing.T, rounds int, resultText string, isError bool) []Message {
	t.Helper()
	messages := []map[string]any{{"role": "user", "content": "go"}}
	for i := 1; i <= rounds; i++ {
		id := fmt.Sprintf("toolu_%d", i)
		messages = append(messages,
			map[string]any{"role": "assistant", "content": []any{
				map[string]any{"type": "tool_use", "id": id, "name": "Bash", "input": map[string]any{"command": fmt.Sprintf("make %d", i)}},
			}},
			map[string]any{"role": "user", "content": []any{
				nativeToolResultBlock(id, resultText, isError),
			}},
		)
	}
	raw, err := json.Marshal(map[string]any{"model": "claude-opus-5", "max_tokens": 32, "messages": messages})
	if err != nil {
		t.Fatal(err)
	}
	doc, err := parseNativeMessagesDocument(raw)
	if err != nil {
		t.Fatal(err)
	}
	return doc.request.Messages
}

func nativeToolResultBlock(id, text string, isError bool) map[string]any {
	block := map[string]any{"type": "tool_result", "tool_use_id": id, "content": text}
	if isError {
		block["is_error"] = true
	}
	return block
}

// Claude Code 命令失败时的 tool_result：is_error:true，正文是“Exit code 1”加命令输出，不含任何文本失败标记。
const claudeCodeExitText = "Exit code 1\nmake: *** [all] Error 2"

func TestToolFailureLoopCountsNativeIsErrorResults(t *testing.T) {
	rig := newToolFailureRig(3)
	for round := 1; round <= 3; round++ {
		rig.record(nativeToolResultRounds(t, round, claudeCodeExitText, true))
	}
	if len(rig.written) != 1 || rig.count("Bash") != 3 {
		t.Fatalf("is_error results must count: events=%d count=%d", len(rig.written), rig.count("Bash"))
	}
	// 同样的正文没有 is_error：文本判定保持保守，不算失败。
	plain := newToolFailureRig(3)
	plain.record(nativeToolResultRounds(t, 1, claudeCodeExitText, false))
	if plain.count("Bash") != 0 {
		t.Fatalf("without is_error the text alone is not a failure, got %d", plain.count("Bash"))
	}
}

// /v1/messages 转成 chat 再走上游的路径（anthropicMessageToOpenAIValidated）同样要带上 is_error。
func TestToolFailureLoopCountsConvertedIsErrorResults(t *testing.T) {
	converted, err := anthropicMessageToOpenAIValidated(AnthropicRequestMessage{Role: "user", Content: []interface{}{
		map[string]interface{}{"type": "tool_result", "tool_use_id": "toolu_1", "content": claudeCodeExitText, "is_error": true},
	}})
	if err != nil {
		t.Fatal(err)
	}
	rig := newToolFailureRig(5)
	rig.record(append([]Message{assistantCall("toolu_1", "Bash")}, converted...))
	if rig.count("Bash") != 1 {
		t.Fatalf("converted is_error result must count once, got %d", rig.count("Bash"))
	}
	// 失败标记是内部字段：转成 chat 的消息序列化后不能多出任何布尔字段。
	if raw, _ := json.Marshal(converted); strings.Contains(string(raw), "is_error") || strings.Contains(string(raw), "true") {
		t.Fatalf("the internal failure flag must not reach the upstream chat body: %s", raw)
	}
}

func TestToolFailureLoopWorksOnNativeMessagesPath(t *testing.T) {
	rig := newToolFailureRig(3)
	for round := 1; round <= 3; round++ {
		rig.record(nativeToolRounds(t, round, toolFailureText))
		if round < 3 && len(rig.written) != 0 {
			t.Fatalf("round %d must not reach the threshold: %+v", round, rig.written)
		}
	}
	if len(rig.written) != 1 || rig.count("Bash") != 3 {
		t.Fatalf("native path: want 1 event and Count=3, got events=%d count=%d", len(rig.written), rig.count("Bash"))
	}
}

func TestToolFailureLoopCountsParallelResponsesCalls(t *testing.T) {
	// Responses 路径把每个 function_call 转成单独一条 assistant 消息（chat_completions.go convertToChatRequest）。
	req := &ResponsesRequest{Input: []interface{}{
		map[string]interface{}{"role": "user", "content": "go"},
		map[string]interface{}{"type": "function_call", "call_id": "A", "name": "Bash", "arguments": `{"c":1}`},
		map[string]interface{}{"type": "function_call", "call_id": "B", "name": "Read", "arguments": `{"p":1}`},
		map[string]interface{}{"type": "function_call_output", "call_id": "A", "output": toolFailureText},
		map[string]interface{}{"type": "function_call_output", "call_id": "B", "output": toolFailureText},
	}}
	chat, err := (&ResponsesHandler{}).convertToChatRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	rig := newToolFailureRig(5)
	rig.record(chat.Messages)
	if rig.count("Bash") != 1 || rig.count("Read") != 1 {
		t.Fatalf("both parallel calls must count: Bash=%d Read=%d", rig.count("Bash"), rig.count("Read"))
	}
}

func TestToolFailureLoopIgnoresIdenticalResendOfTheSameRequest(t *testing.T) {
	rig := newToolFailureRig(5)
	history := []Message{
		{Role: "user", Content: json.RawMessage(`"go"`)},
		assistantCall("call-1", "Bash"),
		toolResult("call-1", toolFailedContent),
	}
	for i := 0; i < 5; i++ {
		rig.record(history)
	}
	if got := rig.count("Bash"); got != 1 || len(rig.written) != 0 {
		t.Fatalf("client retries of the same request must count once; count=%d events=%d", got, len(rig.written))
	}
}

func TestToolFailureLoopIgnoresOldResultsAfterPlainTextAnswer(t *testing.T) {
	rig := newToolFailureRig(1)
	rig.record([]Message{
		assistantCall("X", "Bash"),
		toolResult("X", toolFailedContent),
		{Role: "assistant", Content: json.RawMessage(`"done"`)},
		{Role: "user", Content: json.RawMessage(`"继续"`)},
	})
	if rig.count("Bash") != 0 || len(rig.written) != 0 {
		t.Fatalf("results before a text answer are old; count=%d events=%+v", rig.count("Bash"), rig.written)
	}
}

func TestToolFailureLoopResendIgnoresChangingSystemPrompt(t *testing.T) {
	rig := newToolFailureRig(5)
	for i := 0; i < 5; i++ {
		rig.record([]Message{
			{Role: "system", Content: json.RawMessage(fmt.Sprintf(`"now=12:0%d"`, i))},
			{Role: "user", Content: json.RawMessage(`"go"`)},
			assistantCall("call-1", "Bash"),
			toolResult("call-1", toolFailedContent),
		})
	}
	if got := rig.count("Bash"); got != 1 || len(rig.written) != 0 {
		t.Fatalf("resends with a re-rendered system prompt must count once; count=%d events=%d", got, len(rig.written))
	}
}

// 已知限制：Responses 路径按“调用、结果、调用、结果”交错排列时，只有最后一个调用算本轮，
// 前一个少计（只少计，不会误升级）。这里钉住当前行为。
func TestToolFailureLoopKnownLimitInterleavedResponsesCountsOnlyLastCall(t *testing.T) {
	rig := newToolFailureRig(5)
	rig.record([]Message{
		{Role: "user", Content: json.RawMessage(`"go"`)},
		assistantCall("A", "Read"),
		toolResult("A", toolFailedContent),
		assistantCall("B", "Bash"),
		toolResult("B", toolFailedContent),
	})
	if rig.count("Read") != 0 || rig.count("Bash") != 1 {
		t.Fatalf("known limitation changed: Read=%d Bash=%d", rig.count("Read"), rig.count("Bash"))
	}
}
