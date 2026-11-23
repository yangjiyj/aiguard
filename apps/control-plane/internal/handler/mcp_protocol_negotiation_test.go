package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

type mcpNegotiationCall struct {
	Method, Header, Session string
}

// newMCPLegacyMockUpstream 模拟「只支持 serverVersion」的上游：无论客户端 initialize 发什么版本，
// 都回 serverVersion；非 initialize 请求若缺少/不等于该版本的 MCP-Protocol-Version 头，
// 且 serverVersion >= 2025-06-18 则按规范返回 400。useSSE=true 时用 text/event-stream 回包。
func newMCPLegacyMockUpstream(t *testing.T, serverVersion string, useSSE bool, calls *[]mcpNegotiationCall, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		mu.Lock()
		*calls = append(*calls, mcpNegotiationCall{req.Method, r.Header.Get("MCP-Protocol-Version"), r.Header.Get("Mcp-Session-Id")})
		mu.Unlock()
		reply := func(result string) {
			body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, req.ID, result)
			if useSSE {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = fmt.Fprintf(w, "event: message\ndata: %s\n\n", body)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		}
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "sess-"+serverVersion)
			reply(fmt.Sprintf(`{"protocolVersion":%q,"serverInfo":{"name":"mock","version":"1"}}`, serverVersion))
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			reply(`{"tools":[{"name":"echo","description":"d","inputSchema":{"type":"object"}}]}`)
		default:
			http.Error(w, "unexpected", http.StatusBadRequest)
		}
	}))
}

func TestMCPManifestNegotiatesEverySupportedUpstreamVersion(t *testing.T) {
	for _, version := range []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"} {
		for _, useSSE := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/sse=%v", version, useSSE), func(t *testing.T) {
				var mu sync.Mutex
				var calls []mcpNegotiationCall
				srv := newMCPLegacyMockUpstream(t, version, useSSE, &calls, &mu)
				defer srv.Close()
				tools, err := fetchMCPManifest(context.Background(), srv.URL, "")
				if err != nil {
					t.Fatalf("negotiate %s: %v", version, err)
				}
				if len(tools) != 1 || tools[0].Name != "echo" {
					t.Fatalf("tools=%#v", tools)
				}
				mu.Lock()
				defer mu.Unlock()
				if len(calls) != 3 {
					t.Fatalf("calls=%v", calls)
				}
				if calls[0].Method != "initialize" || calls[0].Header != "" {
					t.Fatalf("initialize must not carry version header: %#v", calls[0])
				}
				for _, c := range calls[1:] {
					if c.Header != version || c.Session != "sess-"+version {
						t.Fatalf("%s must carry negotiated version %q: %#v", c.Method, version, c)
					}
				}
			})
		}
	}
}

func TestMCPManifestUnsupportedVersionErrorListsBothSides(t *testing.T) {
	var mu sync.Mutex
	var calls []mcpNegotiationCall
	srv := newMCPLegacyMockUpstream(t, "2023-01-01", false, &calls, &mu)
	defer srv.Close()
	_, err := fetchMCPManifest(context.Background(), srv.URL, "")
	want := `MCP 协议版本不受支持：服务端返回 "2023-01-01"，客户端支持 [2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05]`
	if err == nil || err.Error() != want {
		t.Fatalf("err=%v want=%s", err, want)
	}
}

func TestMCPConnectionTestAcceptsLegacyVersionAndSurfacesVersionError(t *testing.T) {
	var mu sync.Mutex
	var calls []mcpNegotiationCall
	legacy := newMCPLegacyMockUpstream(t, "2024-11-05", false, &calls, &mu)
	defer legacy.Close()
	bad := newMCPLegacyMockUpstream(t, "2023-01-01", true, &calls, &mu)
	defer bad.Close()
	for _, tc := range []struct {
		url, wantKind, wantInMsg string
	}{{legacy.URL, "", ""}, {bad.URL, "parse", `服务端返回 "2023-01-01"，客户端支持 [2025-11-25`}} {
		ep, eerr := testMCPEndpoint(tc.url, "")
		if eerr != nil {
			t.Fatal(eerr)
		}
		info, kind, err := probeMCPInitialize(context.Background(), ep)
		if kind != tc.wantKind {
			t.Fatalf("url=%s kind=%q err=%v", tc.url, kind, err)
		}
		if tc.wantKind == "" && (err != nil || info["protocol_version"] != "2024-11-05") {
			t.Fatalf("info=%v err=%v", info, err)
		}
		if tc.wantKind != "" && (err == nil || !strings.Contains(err.Error(), tc.wantInMsg)) {
			t.Fatalf("err=%v", err)
		}
	}
}
