package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpconfirmation"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream/mcpprofiletest"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
)

// HITL 确认之后的重放同样支持旧 SSE 上游与 query 鉴权：批准执行走与直连相同的 forwardMCPUpstream，
// 由桥接建立临时上游会话完成 tools/call，执行后上游流关闭，审计事实齐全。
func TestApprovedMCPConfirmationReplaySupportsSSEUpstreamWithQueryAuth(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-replay-sse-key")
	var prof mcpprofiletest.Profile
	for _, p := range mcpprofiletest.All() {
		if p.Name == "amap-style" {
			prof = p
		}
	}
	inst := prof.Start(t)
	sseCase := inst.Cases[1]

	var auditPayload map[string]any
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/mcp/effective-policy":
			_, _ = w.Write([]byte(`{"matched":true,"policy_id":"policy-confirm","tool_id":"tool-echo","mode":"strict","action":"confirm","supply_chain_status":"approved","supply_chain_revision":"revision-a","server_admission_status":"approved","tool_admission_status":"approved","route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_route_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","approved_schema_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}`))
		case "/admin/v1/internal/agentguard/effective-policy":
			_, _ = w.Write([]byte(`{"data":null}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			_ = jsonDecodeInto(r, &auditPayload)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"id":"tool-log-sse-replay"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer controlPlane.Close()

	ct, _, err := secrets.EncryptProviderSecret(sseCase.Secret)
	if err != nil {
		t.Fatal(err)
	}
	client := NewToolRiskClient(controlPlane.URL, "internal")
	setToolGuardTestPosture(t, client, false, false)
	client.SetMCPConfirmationScopeSecret(mcpExecutionScopeTestSecret)
	proxy := NewMCPProxyHandler(nil, client, false)
	t.Cleanup(proxy.sseBridge.Close)
	proxy.serverCache.set("tenant-a\x1fserver-a", &mcpServerRoute{
		ID: "server-a", TenantID: "tenant-a", Name: "demo", ServerURL: sseCase.URL, Status: "active",
		Transport: "sse", AuthCiphertext: ct, ProtocolVersion: "2025-11-25", AllowPrivateEgress: true,
		RouteHash:    strings.Repeat("a", 64),
		Capabilities: map[string]interface{}{"upstream_auth_location": "query", "upstream_auth_query_param": "key"},
	})
	proxy.targetClientResolver = func(_ context.Context, rawURL string, _ bool, _ *http.Client) (*http.Client, *url.URL, error) {
		u, perr := url.Parse(rawURL)
		return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, u, perr
	}

	body := []byte(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"echo","arguments":{"text":"replayed"}}}`)
	record := encryptedMCPExecutionRecord(t, mcpExecutionScopeTestSecret, mcpconfirmation.ReplayContext{
		Version: mcpconfirmation.ReplayContextVersion, TenantID: "tenant-a", ProjectID: "project-a",
		OperationID: "op-sse-replay", TraceID: "trace-sse-replay",
		ServerID: "server-a", ToolName: "echo", ToolCallID: "number:9",
		ProtocolVersion: "2025-11-25", ToolID: "tool-echo",
		SupplyChainRevision: "revision-a", ApprovedSchemaHash: strings.Repeat("b", 64),
		ServerRouteHash: strings.Repeat("a", 64), RequestBody: body,
	})
	var execs atomic.Int32
	completion := proxy.executeApprovedMCPConfirmation(context.Background(), record)
	execs.Add(1)
	if completion.Status != "executed" || completion.ErrorCode != "" || completion.Summary["result_observed"] != true {
		t.Fatalf("replay over SSE upstream failed: %+v", completion)
	}
	if got := inst.ToolCalls(); len(got) != 1 || got[0] != "echo" {
		t.Fatalf("upstream must receive exactly one replayed tools/call: %v", got)
	}
	for _, r := range inst.Requests() {
		if !strings.Contains(r.RawQuery, "key="+mcpprofiletest.SecretValue()) {
			t.Fatalf("replay request lacks query auth: %s %q", r.Method, r.RawQuery)
		}
	}
	if auditPayload["event_kind"] != "execution_forwarded" || auditPayload["mcp_server_id"] != "server-a" || auditPayload["operation_id"] != "op-sse-replay" {
		t.Fatalf("audit=%v", auditPayload)
	}
	if strings.Contains(strings.ToLower(toJSONString(auditPayload)), strings.ToLower(mcpprofiletest.SecretValue())) {
		t.Fatalf("audit leaks upstream secret: %v", auditPayload)
	}
	if proxy.sseBridge.openSessions() != 0 {
		t.Fatal("replay must not leave a registered bridge session")
	}
}
