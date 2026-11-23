package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Codex 0.163 在 input 里放 {"type":"additional_tools","role":"developer","tools":[...]}：
// 带 role 但没有 content。安全回填不能给这类条目凭空加 content，否则上游报
// Unknown parameter: 'input[0].content'。
func TestNativeResponsesMaskKeepsNonMessageItemsUntouched(t *testing.T) {
	upstream := []byte(`{"id":"resp_native","object":"response","status":"completed","model":"gpt-5.6","output":[],"usage":{"input_tokens":1,"output_tokens":0,"total_tokens":1}}`)
	for _, action := range []string{"", "mask"} {
		security := &MockSecurityChecker{InputAction: action, InputMasked: "[MASKED]"}
		caller := &MockProviderCaller{CallResponse: upstream}
		handler := newNativeResponsesTestHandler(caller, security, &MockAuditWriter{}, true)
		body := []byte(`{"model":"gpt-5.6-sol","input":[` +
			`{"type":"additional_tools","id":"at_1","role":"developer","tools":[{"type":"function","name":"f","parameters":{}}]},` +
			`{"type":"message","id":"m1","role":"developer","content":[{"type":"input_text","text":"dev"}]},` +
			`{"type":"reasoning","id":"rs_1","summary":[]},` +
			`{"type":"message","id":"m2","role":"user","content":[{"type":"input_text","text":"secret-input"}]}],` +
			`"store":false,"unknown":{"keep":true}}`)

		w := httptest.NewRecorder()
		handler.Handler().ServeHTTP(w, nativeResponsesRequest(t, body))
		if w.Code != http.StatusOK || len(caller.CallCalls) != 1 {
			t.Fatalf("action=%q status=%d calls=%d body=%s", action, w.Code, len(caller.CallCalls), w.Body.String())
		}
		var sent struct {
			Input []map[string]any `json:"input"`
		}
		if err := json.Unmarshal(caller.CallCalls[0], &sent); err != nil {
			t.Fatal(err)
		}
		for _, item := range sent.Input {
			typ, _ := item["type"].(string)
			if (typ == "additional_tools" || typ == "reasoning") && item["content"] != nil {
				t.Fatalf("action=%q 非消息条目被塞入 content: %s", action, caller.CallCalls[0])
			}
		}
		if action == "mask" && strings.Contains(string(caller.CallCalls[0]), "secret-input") {
			t.Fatalf("mask 未生效: %s", caller.CallCalls[0])
		}
	}
}
