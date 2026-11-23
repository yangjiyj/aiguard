package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 遥测端点免送检:request_decoder == "telemetry" 的端点承载的是客户端打点/计数,
// 对其做 DLP/命令检测只会产出误报(Copilot telemetry 曾单端点刷出数千条
// illegal_system_command);免检只跳过 CheckInput/CheckOutput 送检,留证照常。

func TestIsScanExemptRequestDefaultsToTelemetryOnly(t *testing.T) {
	t.Setenv("PROXY_TELEMETRY_SCAN_EXEMPT", "")
	cases := []struct {
		decoder string
		want    bool
	}{
		{"telemetry", true},
		{"chat", false},
		{"copilot", false},
		{"web_support", false},
		{"", false},
	}
	for _, tt := range cases {
		if got := isScanExemptRequest(tt.decoder); got != tt.want {
			t.Fatalf("isScanExemptRequest(%q) = %v, want %v", tt.decoder, got, tt.want)
		}
	}
}

func TestIsScanExemptRequestEnvEscapeHatch(t *testing.T) {
	// PROXY_TELEMETRY_SCAN_EXEMPT 默认开启,仅显式 false/0 关闭(一键回退口)。
	for _, off := range []string{"false", "0", " FALSE "} {
		t.Setenv("PROXY_TELEMETRY_SCAN_EXEMPT", off)
		if isScanExemptRequest("telemetry") {
			t.Fatalf("PROXY_TELEMETRY_SCAN_EXEMPT=%q 时 telemetry 不应免检", off)
		}
	}
	for _, on := range []string{"true", "1", "TRUE"} {
		t.Setenv("PROXY_TELEMETRY_SCAN_EXEMPT", on)
		if !isScanExemptRequest("telemetry") {
			t.Fatalf("PROXY_TELEMETRY_SCAN_EXEMPT=%q 时 telemetry 应免检", on)
		}
	}
}

func TestCopilotTelemetryEndpointIsScanExempt(t *testing.T) {
	t.Setenv("PROXY_TELEMETRY_SCAN_EXEMPT", "")
	requestDecoder, _ := detectLLMDecoders("telemetry.individual.githubcopilot.com", "/telemetry")
	if requestDecoder != "telemetry" {
		t.Fatalf("detectLLMDecoders(telemetry.individual.githubcopilot.com) request = %q, want telemetry", requestDecoder)
	}
	if !isScanExemptRequest(requestDecoder) {
		t.Fatal("Copilot 遥测端点应免送检")
	}

	// 真对话端点绝不免检:免检范围只锚定 telemetry decoder,不按 host 放宽。
	requestDecoder, _ = detectLLMDecoders("api.individual.githubcopilot.com", "/responses")
	if isScanExemptRequest(requestDecoder) {
		t.Fatalf("Copilot 对话端点(decoder=%q)不应免检", requestDecoder)
	}
}

func TestChatGPTTelemetryExemptionIsExactAndDoesNotCoverConversation(t *testing.T) {
	for _, tc := range []struct {
		host, path string
		exempt     bool
	}{
		{"chatgpt.com", "/ces/v1/rgstr", true},
		{"chat.openai.com", "/v1/rgstr", true},
		{"chatgpt.com", "/ces/v1/rgstr/conversation", false},
		{"chatgpt.com", "/backend-api/f/conversation", false},
		{"chatgpt.com", "/backend-api/files", false},
		{"api.openai.com", "/v1/chat/completions", false},
		{"not-chatgpt.example", "/ces/v1/rgstr", false},
	} {
		decoder, _ := detectLLMDecoders(tc.host, tc.path)
		if got := isScanExemptRequest(decoder); got != tc.exempt {
			t.Errorf("%s %s exempt=%v want=%v", tc.host, tc.path, got, tc.exempt)
		}
	}
}

func TestChatGPTTelemetryHTTPDoesNotBecomeJSONDetectionFailure(t *testing.T) {
	calls := 0
	engine := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer engine.Close()
	client := NewSecurityClientWithSecret(engine.URL, "synthetic-test-secret")
	// Production enables the durable path. No queue operation should be reached.
	client.inspectionQueue = &InspectionQueue{}
	h := &ProxyHandler{whitelistChecker: successfulEmptyWhitelistChecker(), securityClient: client, transport: fileDLPTestRoundTripper(func(r *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "compressed telemetry fixture" {
			t.Fatal("telemetry body changed")
		}
		return &http.Response{StatusCode: 204, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
	})}
	req := httptest.NewRequest("POST", "http://chatgpt.com/ces/v1/rgstr", strings.NewReader("compressed telemetry fixture"))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	h.handleHTTP(response, req)
	if calls != 0 || response.Code != 204 {
		t.Fatalf("telemetry wrongly inspected: calls=%d status=%d", calls, response.Code)
	}
}
