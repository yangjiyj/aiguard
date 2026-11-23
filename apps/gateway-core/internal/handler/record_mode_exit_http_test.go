package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

func TestRecordModeNeverEnforces_FileUploadBlockingActions(t *testing.T) {
	for _, action := range gatewayBlockingActions {
		t.Run(action, func(t *testing.T) {
			caller := &fileUploadCallerStub{body: []byte(`{"id":"file_upstream","object":"file"}`)}
			h := newFileUploadHandlerForTest(&config.Config{SecurityAuditOnly: true}, &fileUploadSecurityStub{action: action}, caller)
			w := httptest.NewRecorder()
			h.Handler().ServeHTTP(w, newFileUploadRequest(t, []byte("%PDF-safe-sample")))
			if w.Code != http.StatusOK || caller.calls != 1 {
				t.Fatalf("record mode interrupted upload for %s: status=%d calls=%d", action, w.Code, caller.calls)
			}
		})
	}
}

func TestProtectModeEnforcesFileUploadBlockingSet(t *testing.T) {
	for _, action := range gatewayBlockingActions {
		t.Run(action, func(t *testing.T) {
			caller := &fileUploadCallerStub{body: []byte(`{"id":"file_upstream","object":"file"}`)}
			h := newFileUploadHandlerForTest(&config.Config{}, &fileUploadSecurityStub{action: action}, caller)
			w := httptest.NewRecorder()
			h.Handler().ServeHTTP(w, newFileUploadRequest(t, []byte("%PDF-safe-sample")))
			if w.Code != http.StatusForbidden || caller.calls != 0 {
				t.Fatalf("protect mode forwarded upload with %s: status=%d calls=%d", action, w.Code, caller.calls)
			}
		})
	}
}

func TestDetectionFailureNeverEnforces_FileUploadWithoutChecker(t *testing.T) {
	caller := &fileUploadCallerStub{body: []byte(`{"id":"file_upstream","object":"file"}`)}
	h := newFileUploadHandlerForTest(&config.Config{}, nil, caller)
	w := httptest.NewRecorder()
	h.Handler().ServeHTTP(w, newFileUploadRequest(t, []byte("%PDF-safe-sample")))
	if w.Code != http.StatusOK || caller.calls != 1 {
		t.Fatalf("a missing checker is a coverage gap, not a block: status=%d calls=%d body=%s", w.Code, caller.calls, w.Body.String())
	}
}

func TestRecordModeNeverEnforces_MCPDestructiveGate(t *testing.T) {
	env := newMCPTestEnv(t, true, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow"})
	setMCPDestructivePolicy(env, agentguard.ModeStrict, agentguard.DestructiveActionBlock)
	body := `{"jsonrpc":"2.0","id":51,"method":"tools/call","params":{"name":"run_shell","arguments":{"command":"rm -rf /srv/isolated-fixture"}}}`
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))
	if w.Code != http.StatusOK || atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("record mode interrupted a destructive MCP call: status=%d upstream=%d body=%s", w.Code, atomic.LoadInt32(env.upstreamHits), w.Body.String())
	}
	if strings.Contains(w.Body.String(), `"error"`) {
		t.Fatalf("record mode returned a JSON-RPC safety error: %s", w.Body.String())
	}
}

func TestMCPOversizedBodyIsTransportError(t *testing.T) {
	env := newMCPTestEnv(t, false, MCPEffectivePolicy{Matched: true, PolicyID: "mcppol_allow", Mode: "strict", Action: "allow"})
	big := bytes.Repeat([]byte("a"), maxMCPRequestBodyBytes+1)
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x","arguments":{"p":"` + string(big) + `"}}}`
	w := httptest.NewRecorder()
	env.router.ServeHTTP(w, newMCPTestRequest(body))
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized MCP body status=%d", w.Code)
	}
	var payload struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil || payload.Error.Code != "request_body_too_large" {
		t.Fatalf("oversized MCP body must carry a transport code, got %s", w.Body.String())
	}
}

func TestReverseProxyQuarantineFollowsExecutionMode(t *testing.T) {
	for _, auditOnly := range []bool{true, false} {
		var upstreamCalled bool
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upstreamCalled = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
		}))
		security := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Path == "/check-input/" {
				_, _ = w.Write([]byte(`{"action":"quarantine","findings":[{"type":"pii","category":"pii","severity":"high"}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"action":"allow","findings":[]}`))
		}))
		h := &ReverseProxyHandler{
			tenantID: "tenant_default", client: upstream.Client(), securityURL: security.URL,
			resolveEgressTarget: testEgressResolver(upstream.URL), auditRecorder: &fakeReverseProxyAuditRecorder{},
			securityAuditOnlyFallback: auditOnly,
			routes:                    []ReverseProxyRoute{{ID: "rpr_q", PathPrefix: "/q", TargetURL: upstream.URL, SecurityEnabled: true, Status: "active"}},
		}
		req := httptest.NewRequest(http.MethodPost, "http://gateway.local/q/v1/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"x"}]}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		upstream.Close()
		security.Close()
		if auditOnly && (w.Code != http.StatusOK || !upstreamCalled) {
			t.Fatalf("record mode interrupted reverse proxy quarantine: status=%d called=%v", w.Code, upstreamCalled)
		}
		if !auditOnly && (w.Code != http.StatusForbidden || upstreamCalled) {
			t.Fatalf("protect mode forwarded reverse proxy quarantine: status=%d called=%v", w.Code, upstreamCalled)
		}
	}
}

// Native Responses terminal snapshots and retained metadata decide through
// securityexit as well: deny/quarantine stop an enforcing stream, and a
// stream_audit (record) posture never stops it.
func nativeTerminalOnlyFixture() string {
	fixture := strings.ReplaceAll(strings.ReplaceAll(nativePendingResponsesSecret, "key=sk-live-", "hello-"), "secret-123", "world")
	return strings.Replace(fixture, `"object":"response"`, `"object":"response","metadata":{"note":"terminal-only-secret"}`, 1)
}

func TestProtectModeEnforcesNativeTerminalBlockingSet(t *testing.T) {
	for _, action := range gatewayBlockingActions {
		t.Run(action, func(t *testing.T) {
			checker := &streamRegressionSecurity{action: func(s string) (string, []SecurityFinding) {
				if strings.Contains(s, "terminal-only-secret") {
					return action, nil
				}
				return "allow", nil
			}}
			body := nativePendingHTTP(t, "responses", &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"}, nativeTerminalOnlyFixture(), checker)
			if strings.Contains(body, "terminal-only-secret") || !strings.Contains(body, "security_blocked") {
				t.Fatalf("protect mode must stop a %s terminal snapshot: %s", action, body)
			}
		})
	}
}

func TestRecordModeNeverEnforces_NativeTerminal(t *testing.T) {
	for _, action := range gatewayBlockingActions {
		t.Run(action, func(t *testing.T) {
			checker := &streamRegressionSecurity{action: func(s string) (string, []SecurityFinding) {
				if strings.Contains(s, "terminal-only-secret") {
					return action, nil
				}
				return "allow", nil
			}}
			body := nativePendingHTTP(t, "responses", &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce", SecurityAuditOnly: true}, nativeTerminalOnlyFixture(), checker)
			if strings.Contains(body, "security_blocked") || !strings.Contains(body, "terminal-only-secret") {
				t.Fatalf("record mode must not stop the stream: %s", body)
			}
		})
	}
}
