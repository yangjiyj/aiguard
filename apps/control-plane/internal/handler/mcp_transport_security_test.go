package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream"
	"github.com/yangjiyj/aiguard/packages/shared-go/mcpupstream/mcpprofiletest"
)

func TestMCPManifestHandshakeUsesStableProtocolSessionAndContentTypes(t *testing.T) {
	var mu sync.Mutex
	var calls []struct {
		Method          string
		ProtocolVersion string
		SessionID       string
		Accept          string
		ContentType     string
		Initialize      string
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			ID     json.RawMessage        `json:"id"`
			Method string                 `json:"method"`
			Params map[string]interface{} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		call := struct {
			Method          string
			ProtocolVersion string
			SessionID       string
			Accept          string
			ContentType     string
			Initialize      string
		}{
			Method:          request.Method,
			ProtocolVersion: r.Header.Get("MCP-Protocol-Version"),
			SessionID:       r.Header.Get("Mcp-Session-Id"),
			Accept:          r.Header.Get("Accept"),
			ContentType:     r.Header.Get("Content-Type"),
		}
		if request.Method == "initialize" {
			call.Initialize, _ = request.Params["protocolVersion"].(string)
		}
		mu.Lock()
		calls = append(calls, call)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch request.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "session-2025")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","serverInfo":{"name":"mock","version":"1"}}}`))
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[]}}`))
		default:
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
	defer server.Close()

	if _, err := fetchMCPManifest(context.Background(), server.URL, ""); err != nil {
		t.Fatalf("fetch manifest: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 3 {
		t.Fatalf("calls=%d want initialize+initialized+tools/list", len(calls))
	}
	if calls[0].Initialize != mcpProtocolVersionLatest {
		t.Fatalf("initialize requested %q", calls[0].Initialize)
	}
	for _, call := range calls {
		if call.ContentType != "application/json" ||
			!strings.Contains(call.Accept, "application/json") ||
			!strings.Contains(call.Accept, "text/event-stream") {
			t.Fatalf("bad transport headers for %s: %#v", call.Method, call)
		}
	}
	for _, call := range calls[1:] {
		if call.SessionID != "session-2025" ||
			call.ProtocolVersion != mcpProtocolVersionLatest {
			t.Fatalf("session/version not propagated for %s: %#v", call.Method, call)
		}
	}
}

func TestMCPManifestRejectsUnsupportedNegotiatedVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2023-01-01"}}`))
	}))
	defer server.Close()
	if _, err := fetchMCPManifest(context.Background(), server.URL, ""); err == nil ||
		!strings.Contains(err.Error(), "协议版本") {
		t.Fatalf("unsupported negotiated version must fail clearly: %v", err)
	}
}

func TestMCPManifestNetworkErrorStripsURLSecrets(t *testing.T) {
	root := errors.New("dial failed")
	err := mcpupstream.ClassifyDial(&url.Error{
		Op: "POST", URL: "https://mcp.example/rpc?token=upstream-secret", Err: root,
	}, "upstream-secret")
	if strings.Contains(err.Error(), "upstream-secret") || strings.Contains(err.Error(), "token=") {
		t.Fatalf("manifest error leaked URL query: %q", err)
	}
	if !errors.Is(err, root) {
		t.Fatalf("sanitized error lost root cause: %v", err)
	}
}

// 旧 HTTP+SSE 现已支持：显式 sse 配置不再被拒绝，而是走旧 SSE 客户端（握手、tools/list 全链路）。
// 本测试取代原先锁定“旧 SSE 被拒绝”的 TestMCPPureLegacySSEIsExplicitlyUnsupported。
func TestMCPLegacySSEIsSupportedForConfiguredTransport(t *testing.T) {
	inst := mcpprofiletest.StartServer(t, mcpprofiletest.Options{
		Name: "legacy", SSEPath: "/sse", Version: "2024-11-05", Endpoint: "relative",
	})
	ep, err := testMCPEndpoint(inst.URL()+"/sse", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := mcpupstream.ParseConfig("sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	ep.cfg = cfg
	tools, sess, err := fetchMCPManifestWithEndpoint(context.Background(), ep)
	if err != nil {
		t.Fatalf("legacy SSE must be supported: %v", err)
	}
	if sess.Transport != "sse" || len(tools) != 3 {
		t.Fatalf("transport=%s tools=%d", sess.Transport, len(tools))
	}
	info, kind, err := probeMCPInitialize(context.Background(), ep)
	if err != nil || kind != "" || info["transport"] != "sse" || info["protocol_version"] != "2024-11-05" {
		t.Fatalf("probe info=%v kind=%q err=%v", info, kind, err)
	}
}

// 生产入口（经 safetarget）对旧 SSE 同样不再直接拒绝：地址未通过出站校验时应报 SSRF 类错误而不是“不支持”。
func TestMCPLegacySSEProductionPathGoesThroughSafetarget(t *testing.T) {
	server := &repository.MCPServer{ServerURL: "http://127.0.0.1:9/sse", Transport: "sse"}
	_, err := fetchMCPManifestForServer(context.Background(), server)
	if err == nil || strings.Contains(err.Error(), "不支持旧式纯 SSE") || !strings.Contains(err.Error(), "出站安全校验") {
		t.Fatalf("legacy SSE must reach the safetarget gate, got: %v", err)
	}
}

func TestMCPUpstreamAuthorizationSupportsBearerAndCustomHeader(t *testing.T) {
	apply := func(caps map[string]interface{}) (*http.Request, error) {
		cfg, err := mcpupstream.ParseConfig("streamable_http", caps)
		if err != nil {
			return nil, err
		}
		req, _ := http.NewRequest(http.MethodPost, "https://mcp.example/rpc", nil)
		return req, mcpupstream.ApplyAuth(req, cfg, "secret")
	}
	req, err := apply(nil)
	if err != nil || req.Header.Get("Authorization") != "Bearer secret" {
		t.Fatalf("bearer auth=%v err=%v", req.Header, err)
	}
	req, err = apply(map[string]interface{}{"auth_header_name": "X-MCP-Token"})
	if err != nil || req.Header.Get("X-Mcp-Token") != "secret" || req.Header.Get("Authorization") != "" {
		t.Fatalf("custom auth=%v err=%v", req.Header, err)
	}
	if _, err := apply(map[string]interface{}{"auth_header_name": "Host"}); err == nil {
		t.Fatal("forbidden auth header must be rejected when a secret is configured")
	}
}

func TestMCPManifestRejectsJSONRPCBatchResponse(t *testing.T) {
	_, err := mcpupstream.DecodeResponse([]byte(`[{"jsonrpc":"2.0","id":1,"result":{}}]`), 1, 200)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "batch") {
		t.Fatalf("batch response must be rejected: %v", err)
	}
}
