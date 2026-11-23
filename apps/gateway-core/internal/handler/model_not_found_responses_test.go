package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func newAliasNativeResponsesHandler(caller *MockProviderCaller, security *MockSecurityChecker) *ResponsesHandler {
	resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
		ID: "model-native", ProviderID: "provider-native", ModelName: "openai/gpt-5.6-sol", AliasFrom: "gpt-5.6-sol",
		UpstreamModelID: "gpt-5.6", ProviderType: "openai",
		ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true,
	}}
	factory := &MockProviderAdapterFactory{MockProviderCaller: caller}
	return NewResponsesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, security, &MockAuditWriter{}, factory, nil, nil)
}

// 简写名补全成全名后，原生 Responses 请求体不能被有损重建：图片/文件块、大整数原样保留，
// 只有 model 被改成全名。
func TestNativeResponsesAliasKeepsRequestBodyByteForByteExceptModel(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	caller := &MockProviderCaller{CallResponse: []byte(`{"id":"resp_1","object":"response","status":"completed","model":"gpt-5.6","output":[],"usage":{"input_tokens":1,"output_tokens":0,"total_tokens":1}}`)}
	h := newAliasNativeResponsesHandler(caller, &MockSecurityChecker{})
	body := []byte(`{"model":"gpt-5.6-sol","input":[{"role":"user","content":[{"type":"input_text","text":"look"},{"type":"input_image","image_url":"data:image/png;base64,AAEC"},{"type":"input_file","file_id":"file_abc"}]}],"seed":9007199254740993123456789}`)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, nativeResponsesRequest(t, body))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(caller.CallCalls) != 1 {
		t.Fatalf("upstream calls=%d", len(caller.CallCalls))
	}
	var sent map[string]json.RawMessage
	if err := json.Unmarshal(caller.CallCalls[0], &sent); err != nil {
		t.Fatal(err)
	}
	if string(sent["model"]) != `"openai/gpt-5.6-sol"` {
		t.Fatalf("upstream model=%s want the full name", sent["model"])
	}
	var original map[string]json.RawMessage
	_ = json.Unmarshal(body, &original)
	if string(sent["input"]) != string(original["input"]) {
		t.Fatalf("input was rebuilt lossy:\n got=%s\nwant=%s", sent["input"], original["input"])
	}
	if string(sent["seed"]) != "9007199254740993123456789" {
		t.Fatalf("number lost precision: %s", sent["seed"])
	}
}

// 对照：安全检查确实改写了内容时，重建路径照常生效（简写名不能让脱敏失效）。
func TestNativeResponsesAliasStillAppliesInputMasking(t *testing.T) {
	t.Setenv("UAG_ROUTING_DISABLED", "true")
	caller := &MockProviderCaller{CallResponse: []byte(`{"id":"resp_1","object":"response","status":"completed","model":"gpt-5.6","output":[],"usage":{"input_tokens":1,"output_tokens":0,"total_tokens":1}}`)}
	security := &MockSecurityChecker{InputAction: "mask", InputMasked: "MASKED-TEXT"}
	h := newAliasNativeResponsesHandler(caller, security)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"my secret value"}`)))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if len(caller.CallCalls) != 1 {
		t.Fatalf("upstream calls=%d", len(caller.CallCalls))
	}
	var sent struct {
		Model string `json:"model"`
		Input string `json:"input"`
	}
	if err := json.Unmarshal(caller.CallCalls[0], &sent); err != nil {
		t.Fatal(err)
	}
	if sent.Input != "MASKED-TEXT" || strings.Contains(string(caller.CallCalls[0]), "my secret value") {
		t.Fatalf("masking not applied: %s", caller.CallCalls[0])
	}
	if sent.Model != "openai/gpt-5.6-sol" {
		t.Fatalf("model=%q", sent.Model)
	}
}
