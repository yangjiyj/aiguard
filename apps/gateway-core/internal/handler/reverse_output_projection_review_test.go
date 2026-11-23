package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestReviewRootFOutputUsesActualProtocolToolPayload(t *testing.T) {
	for _, tc := range []struct {
		kind, field string
		value       interface{}
	}{
		{"custom_tool_call", "input", "credential-canary"},
		{"computer_call", "action", map[string]interface{}{"type": "type", "text": "credential-canary"}},
		{"local_shell_call", "action", map[string]interface{}{"type": "exec", "command": []string{"printf", "credential-canary"}}},
	} {
		t.Run(tc.kind, func(t *testing.T) {
			item := map[string]interface{}{"id": "call1", "type": tc.kind, "arguments": "benign-decoy", tc.field: tc.value}
			wire, err := json.Marshal(map[string]interface{}{"output": []interface{}{item}})
			if err != nil {
				t.Fatal(err)
			}
			text, _ := extractReverseProxyLLMOutput("/v1/responses", "application/json", wire)
			if !strings.Contains(text, "credential-canary") {
				t.Fatalf("%s actual %s payload was masked by unrelated arguments: %q", tc.kind, tc.field, text)
			}
			itemWire, _ := json.Marshal(map[string]interface{}{"type": "response.output_item.done", "item": item})
			capture := &streamInspectionCapture{path: "/v1/responses"}
			_, _ = capture.Write([]byte(fmt.Sprintf("event: response.output_item.done\ndata: %s\n\n", itemWire)))
			if !strings.Contains(capture.InspectionText(), "credential-canary") {
				t.Fatalf("stream actual %s payload hidden: %q", tc.field, capture.InspectionText())
			}
		})
	}
}

func TestReviewRootFStructuredToolJSONSingleCharacterEscape(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	for _, tc := range []struct{ name, path, body string }{
		{"chat string JSON", "/v1/chat/completions", `{"choices":[{"message":{"content":"safe","tool_calls":[{"function":{"arguments":"{\"token\":\"\\u0063redential-canary\"}"}}]}}]}`},
		{"Anthropic object", "/v1/messages", `{"content":[{"type":"tool_use","input":{"token":"\u0063redential-canary"}}]}`},
		{"Responses action", "/v1/responses", `{"output":[{"id":"call1","type":"computer_call","action":{"type":"type","text":"\u0063redential-canary"}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, ok := extractReverseProxyLLMOutput(tc.path, "application/json", []byte(tc.body))
			if !ok || !strings.Contains(text, "credential-canary") {
				t.Fatalf("decoded tool value absent from known-protocol projection: %q", text)
			}
			if !strings.Contains(text, `\u0063`) {
				t.Fatalf("raw argument evidence discarded: %q", text)
			}
			engine, _ := captureEngine(t, func(p map[string]interface{}) string {
				if strings.Contains(p["content"].(string), "credential-canary") {
					return `{"action":"block","findings":[]}`
				}
				return `{"action":"allow","findings":[]}`
			})
			defer engine.Close()
			h := newStructuredTestHandler(engine)
			d, err := h.checkResponseSecurityStructured(context.Background(), "escaped-tool", []byte(tc.body), "application/json", "api.openai.com", tc.path)
			if err != nil || d.Allowed {
				t.Fatalf("single-character JSON escape bypassed DLP: decision=%+v error=%v", d, err)
			}
		})
	}
}

func reviewRootFReasoningFrame(kind string, index int, value string) string {
	field := "summary_index"
	if strings.HasPrefix(kind, "response.reasoning_text") {
		field = "content_index"
	}
	p := map[string]interface{}{"type": kind, "item_id": "reason1", "output_index": 0, field: index}
	if strings.HasSuffix(kind, ".delta") {
		p["delta"] = value
	} else {
		p["text"] = value
	}
	raw, _ := json.Marshal(p)
	return fmt.Sprintf("event: %s\ndata: %s\n\n", kind, raw)
}

func TestReviewRootFReasoningPartsRemainIndependentAndRetainRiskyDeltas(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	for _, tc := range []struct {
		name, first, middle string
		middleIndex         int
	}{
		{"separate summary parts", "response.reasoning_summary_text", "response.reasoning_summary_text", 1},
		{"separate text parts", "response.reasoning_text", "response.reasoning_text", 1},
		{"separate text and summary streams", "response.reasoning_text", "response.reasoning_summary_text", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := reviewRootFReasoningFrame(tc.first+".delta", 0, "credential-") +
				reviewRootFReasoningFrame(tc.middle+".delta", tc.middleIndex, "benign") +
				reviewRootFReasoningFrame(tc.first+".delta", 0, "canary") +
				reviewRootFReasoningFrame(tc.first+".done", 0, "benign final") +
				"event: response.completed\ndata: " + `{"type":"response.completed","response":{"output":[{"id":"reason1","type":"reasoning","summary":[{"type":"summary_text","text":"benign final"},{"type":"summary_text","text":"benign"}],"content":[{"type":"reasoning_text","text":"benign final"},{"type":"reasoning_text","text":"benign"}]}]}}` + "\n\n"
			capture := &streamInspectionCapture{path: "/v1/responses"}
			_, _ = capture.Write([]byte(body))
			text, reason := capture.Finish(false)
			if reason != "" || !strings.Contains(text, "credential-canary") {
				t.Fatalf("independent reasoning stream was corrupted or erased: text=%q reason=%q", text, reason)
			}
			if !capture.HoldUntilComplete() {
				t.Fatal("reasoning output must keep native frames held")
			}
			h, route, _, _ := reverseHardeningFixture(t, "/v1/responses", "text/event-stream", body, reverseHardeningEngine, failClosedClient(t, false, false))
			w := reverseHardeningForward(t, h, route, http.MethodGet, "")
			if strings.Contains(w.Body.String(), "credential-") || !strings.Contains(w.Body.String(), "output_security_blocked") {
				t.Fatalf("independent reasoning leak escaped holdback: %s", w.Body.String())
			}
		})
	}
}

func TestReviewRootFStructuredToolDepthLimitUsesFailurePolicy(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	deep := strings.Repeat(`{"next":`, 65) + `{"token":"\u0063redential-canary"}` + strings.Repeat("}", 65)
	body := `{"choices":[{"message":{"tool_calls":[{"function":{"arguments":` + fmt.Sprintf("%q", deep) + `}}]}}]}`
	for _, tc := range []struct {
		name           string
		record, closed bool
	}{{"Protect closed", false, true}, {"Protect open", false, false}, {"Record closed", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			h, route, audit, _ := reverseHardeningFixture(t, "/v1/chat/completions", "application/json", body, reverseHardeningEngine, failClosedClient(t, tc.record, tc.closed))
			w := reverseHardeningForward(t, h, route, http.MethodGet, "")
			want := http.StatusOK
			if tc.closed && !tc.record {
				want = http.StatusServiceUnavailable
			}
			if w.Code != want {
				t.Fatalf("JSON projection limit ignored failure mode: code=%d want=%d body=%s", w.Code, want, w.Body.String())
			}
			if len(audit.records) != 1 || audit.records[0].OutputSemanticStatus != "incomplete" {
				t.Fatalf("JSON projection limit must record a coverage gap: %+v", audit.records)
			}
		})
	}
}

func TestReviewRootFWhitespaceAuxiliaryDeltasCountTowardBound(t *testing.T) {
	capture := &streamInspectionCapture{path: "/v1/chat/completions"}
	fragment := strings.Repeat(" ", 1024*1024)
	wire, _ := json.Marshal(map[string]interface{}{"choices": []interface{}{map[string]interface{}{"delta": map[string]string{"reasoning_content": fragment}}}})
	frame := []byte(fmt.Sprintf("data: %s\n\n", wire))
	for i := 0; i < 10; i++ {
		_, _ = capture.Write(frame)
	}
	if capture.reason != "output_text_limit_exceeded" {
		t.Fatalf("whitespace auxiliary output bypassed cumulative bound: reason=%q text_bytes=%d auxiliary_bytes=%d", capture.reason, len(capture.Text()), len(capture.auxiliary.String()))
	}
}

func TestFReviewIncompleteToolDeltaCannotHideDecodedTerminalArguments(t *testing.T) {
	const secret = "canary-test-secret-fixture"
	var escaped strings.Builder
	for _, r := range secret {
		fmt.Fprintf(&escaped, "\\u%04x", r)
	}
	var output reverseAuxiliaryOutput
	output.addTool("tool_call", `{"body":"benign partial`, true)
	terminal := `{"body":"` + escaped.String() + `"}`
	output.addTool("tool_call", terminal, false)
	text, reason := output.inspectionText()
	if !strings.Contains(text, `{"body":"benign partial`) || !strings.Contains(text, terminal) {
		t.Fatalf("raw snapshots were lost: %q", text)
	}
	if !strings.Contains(text, secret) {
		t.Fatalf("prior partial JSON prevented terminal tool decoding: text=%q reason=%s", text, reason)
	}
}

func TestFReviewResponsesReasoningSummaryPartCannotDisappearAtCompletion(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	const secret = "canary-test-secret-fixture"
	for _, kind := range []string{"response.reasoning_summary_part.added", "response.reasoning_summary_part.done"} {
		t.Run(kind, func(t *testing.T) {
			first := fmt.Sprintf("event: %s\ndata: ", kind) + fmt.Sprintf(`{"type":%q,"item_id":"reason1","output_index":0,"summary_index":0,"part":{"type":"summary_text","text":%q}}`, kind, secret) + "\n\n"
			last := "event: response.completed\ndata: " + `{"type":"response.completed","response":{"output":[{"id":"reason1","type":"reasoning","summary":[{"type":"summary_text","text":"benign final"}]}]}}` + "\n\n"
			capture := &streamInspectionCapture{path: "/v1/responses"}
			if _, err := capture.Write([]byte(first)); err != nil {
				t.Fatal(err)
			}
			if !capture.HoldUntilComplete() || !strings.Contains(capture.InspectionText(), secret) {
				t.Fatalf("native reasoning part was not held or inspected: hold=%t text=%q", capture.HoldUntilComplete(), capture.InspectionText())
			}
			if _, err := capture.Write([]byte(last)); err != nil {
				t.Fatal(err)
			}
			text, reason := capture.Finish(false)
			if reason != "" || !strings.Contains(text, secret) || !strings.Contains(text, "benign final") {
				t.Fatalf("terminal snapshot erased native reasoning part: text=%q reason=%s", text, reason)
			}
			text, ok, reason := extractReverseProxyLLMOutputInspection("/v1/responses", "text/event-stream", []byte(first+last), false)
			if !ok || reason != "" || !strings.Contains(text, secret) {
				t.Fatalf("captured native reasoning part not inspected: text=%q ok=%t reason=%s", text, ok, reason)
			}
			body := strings.ReplaceAll(first+last, secret, "credential-canary")
			h, route, _, _ := reverseHardeningFixture(t, "/v1/responses", "text/event-stream", body, reverseHardeningEngine, failClosedClient(t, false, false))
			w := reverseHardeningForward(t, h, route, http.MethodGet, "")
			if strings.Contains(w.Body.String(), "credential-canary") || !strings.Contains(w.Body.String(), "output_security_blocked") {
				t.Fatalf("native reasoning summary part escaped holdback: %s", w.Body.String())
			}
		})
	}
}
