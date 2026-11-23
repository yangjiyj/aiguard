package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 审查意见 4：T13 授权拒绝是授权事实，不是检测（D10“授权不动”），与 2.9.21 一致：全局观察留痕
// 不管它，只看端点模式；观察留痕只钳制检测类结论。
func TestDecide2922T13DenialIgnoresGlobalRecordMode(t *testing.T) {
	for _, tc := range []struct{ endpointMode, want string }{{"block", "block"}, {"monitor", "audit"}} {
		t.Run(tc.endpointMode, func(t *testing.T) {
			f := &t16DecideFixture{allow: map[string]bool{"tool_execute": true, "network_connect": false}}
			server := f.server(t)
			defer server.Close()
			g := &AgentEndpointGateway{controlURL: server.URL, secret: "internal-test-secret", client: server.Client(),
				toolClient: &ToolRiskClient{controlPlaneURL: server.URL, internalAPISecret: "internal-test-secret", httpClient: server.Client()}}
			g.runtime = endpointRuntimeClient2922(t, true)
			body := `{"endpoint_id":"endpoint-1","session_id":"session-1","prompt_id":"prompt-1","tool_use_id":"call-1",` +
				`"agent":{"product":"claude-code"},"tool":{"name":"WebFetch","type":"network"},"arguments":{"url":"https://ungranted.example.test/x"},` +
				`"context":{"fragments":[]}}`
			rec := httptest.NewRecorder()
			g.decide(rec, httptest.NewRequest(http.MethodPost, "/agent/v1/decide", strings.NewReader(body)), endpointPolicyTestBearer,
				map[string]any{"tenant_id": "tenant-fixture", "endpoint_id": "endpoint-1", "mode": tc.endpointMode, "agent_product": "claude-code"})
			var response map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			if response["effective_decision"] != tc.want || response["reason"] != "t13_authorization_denied" {
				t.Fatalf("T13 denial follows the endpoint mode only, global record mode does not apply: %v", response)
			}
		})
	}
}

func endpointRuntimeClient2922(t *testing.T, globalRecord bool) *ToolRiskClient {
	return endpointRuntimeClient(t, `{"id":"p","mode":"audit","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":[]}`, globalRecord)
}
