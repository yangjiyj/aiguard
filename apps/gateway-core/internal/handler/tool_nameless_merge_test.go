package handler

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

func decodeToolCalls(t *testing.T, acc *liveStreamAccumulator) []ToolCall {
	t.Helper()
	body, err := acc.responseBody("req-1")
	if err != nil {
		t.Fatal(err)
	}
	var resp ChatCompletionResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Choices) == 0 {
		t.Fatalf("no choices: %s", body)
	}
	return resp.Choices[0].Message.ToolCalls
}

// 同一 index 的后续增量每块换新 id 且不带 name：必须并进已有工具，只产生 1 个工具，参数按顺序拼接。
func TestStreamAccumulatorMergesPerChunkNewIDDeltasIntoExistingTool(t *testing.T) {
	acc := newLiveStreamAccumulator()
	acc.observeEvent(relay.StreamEvent{Type: relay.EventToolCallStart, Index: 0, ToolCall: &relay.ToolCall{ID: "a", Name: "write_file", Index: 0}})
	for i, id := range []string{"b", "c", "d", "e"} {
		acc.observeEvent(relay.StreamEvent{Type: relay.EventToolArgumentsDelta, Index: 0,
			ToolCall: &relay.ToolCall{ID: id, Index: 0}, Delta: string(rune('1' + i))})
	}
	calls := decodeToolCalls(t, acc)
	if len(calls) != 1 {
		t.Fatalf("want 1 tool, got %d: %+v", len(calls), calls)
	}
	if calls[0].Function.Name != "write_file" || calls[0].ID != "a" || calls[0].Function.Arguments != "1234" {
		t.Fatalf("merged tool wrong: %+v", calls[0])
	}
}

// 真并行的多个工具调用 index 各不相同，各自独立，不被合并。
func TestStreamAccumulatorKeepsParallelToolCallsWithDifferentIndexesSeparate(t *testing.T) {
	acc := newLiveStreamAccumulator()
	for i, name := range []string{"read_file", "bash", "web_fetch"} {
		id := string(rune('a' + i))
		// StreamEvent.Index 是 choice 下标；工具下标在 ToolCall.Index。
		acc.observeEvent(relay.StreamEvent{Type: relay.EventToolCallStart, Index: 0, ToolCall: &relay.ToolCall{ID: id, Name: name, Index: i}})
		acc.observeEvent(relay.StreamEvent{Type: relay.EventToolArgumentsDelta, Index: 0, ToolCall: &relay.ToolCall{ID: id + "x", Index: i}, Delta: "{}"})
	}
	calls := decodeToolCalls(t, acc)
	if len(calls) != 3 {
		t.Fatalf("want 3 parallel tools, got %d: %+v", len(calls), calls)
	}
	for i, name := range []string{"read_file", "bash", "web_fetch"} {
		if calls[i].Function.Name != name || calls[i].Function.Arguments != "{}" {
			t.Fatalf("tool %d wrong: %+v", i, calls[i])
		}
	}
}

// 同 index、新块带 name 且换了 id：仍视为新的工具调用（不被误并）。
func TestStreamAccumulatorKeepsSameIndexNewNamedToolSeparate(t *testing.T) {
	acc := newLiveStreamAccumulator()
	acc.observeEvent(relay.StreamEvent{Type: relay.EventToolCallStart, Index: 0, ToolCall: &relay.ToolCall{ID: "a", Name: "bash", Index: 0}})
	acc.observeEvent(relay.StreamEvent{Type: relay.EventToolCallStart, Index: 0, ToolCall: &relay.ToolCall{ID: "b", Name: "read_file", Index: 0}})
	if calls := decodeToolCalls(t, acc); len(calls) != 2 {
		t.Fatalf("want 2 tools, got %d: %+v", len(calls), calls)
	}
}

// 兜底：同一 请求+choice+位置 的无名工具只上报一次；换请求/choice/位置各自再报一次。
func TestShouldReportNamelessToolOncePerRequestChoicePosition(t *testing.T) {
	t.Setenv(toolAuditNamelessUnknownEnv, "")
	client := NewToolRiskClient("http://127.0.0.1:1", "secret")
	env := &modelrouter.RequestEnvelope{RequestID: "req-1", TenantID: "t"}
	if !client.shouldReportNamelessTool(env, 0, "choice-0|call_1") {
		t.Fatal("first report must pass")
	}
	for i := 0; i < 50; i++ {
		if client.shouldReportNamelessTool(env, 0, "choice-0|call_1") {
			t.Fatal("duplicate nameless tool must not be reported again")
		}
	}
	if !client.shouldReportNamelessTool(env, 1, "choice-0|call_1") {
		t.Fatal("different choice must report")
	}
	if !client.shouldReportNamelessTool(env, 0, "choice-0|call_2") {
		t.Fatal("different position must report")
	}
	if !client.shouldReportNamelessTool(&modelrouter.RequestEnvelope{RequestID: "req-2", TenantID: "t"}, 0, "choice-0|call_1") {
		t.Fatal("different request must report")
	}
}

// 开关 UAG_TOOL_AUDIT_NAMELESS_UNKNOWN：默认开；off 时恢复旧行为——无名工具不上报（不发请求）。
func TestNamelessUnknownSwitchOffSkipsReporting(t *testing.T) {
	for _, off := range []string{"off", "OFF", "false", "0"} {
		t.Run(off, func(t *testing.T) {
			t.Setenv(toolAuditNamelessUnknownEnv, off)
			server, captured := strictControlPlane(t)
			client := NewToolRiskClient(server.URL, "secret")
			env := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t"}
			if client.shouldReportNamelessTool(env, 0, "p") {
				t.Fatal("switch off: nameless tool must not be reported")
			}
			if err := client.LogToolCall(context.Background(), env, ToolAuditLogPayload{ToolName: "  "}); err != nil {
				t.Fatalf("switch off must be silent, got %v", err)
			}
			if captured.last() != nil {
				t.Fatalf("switch off: request must not be sent: %v", captured.last())
			}
			// 有名工具不受开关影响。
			if err := client.LogToolCall(context.Background(), env, ToolAuditLogPayload{ToolName: "bash", ToolType: "system"}); err != nil || captured.last() == nil {
				t.Fatalf("named tool must still be reported: err=%v", err)
			}
		})
	}
}

func TestNamelessUnknownSwitchDefaultsOn(t *testing.T) {
	for _, v := range []string{"", "on", "true", "1", "garbage"} {
		t.Setenv(toolAuditNamelessUnknownEnv, v)
		if !toolAuditNamelessUnknownEnabled() {
			t.Fatalf("value %q should keep the switch on", v)
		}
	}
}
