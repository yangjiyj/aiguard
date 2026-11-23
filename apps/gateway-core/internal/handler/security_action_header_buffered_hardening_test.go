package handler

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
)

func TestSecurityActionHeaderUsesConsumedRuntimeModeAcrossBufferedResponses(t *testing.T) {
	for _, protocol := range []string{"chat", "responses", "messages"} {
		for _, tc := range []struct {
			name, header string
			record, want bool
		}{
			{"record default", "", true, false}, {"protect default", "", false, true},
			{"record explicit", "true", true, true}, {"protect disabled", "false", false, false},
		} {
			t.Run(protocol+"/"+tc.name, func(t *testing.T) {
				t.Setenv("MCP_GATEWAY_ENABLED", "false")
				t.Setenv("SECURITY_AUDIT_ONLY", "false")
				t.Setenv("SECURITY_ACTION_HEADER_ENABLED", tc.header)
				cfg, err := config.Load()
				if err != nil {
					t.Fatal(err)
				}
				client := failClosedClient(t, tc.record, false)
				checker := &MockSecurityChecker{InputAction: "audit", OutputAction: "audit", InputFindings: []SecurityFinding{{Type: "dlp", Severity: "medium", RuleID: "header-rule", Action: "audit"}}, OutputFindings: []SecurityFinding{{Type: "dlp", Severity: "medium", RuleID: "header-rule", Action: "audit"}}}
				caller := &MockProviderCaller{}
				w := httptest.NewRecorder()
				switch protocol {
				case "messages":
					caller.CallResponse = []byte(`{"id":"msg_header","type":"message","role":"assistant","model":"kiro-opus","content":[{"type":"text","text":"safe"}],"stop_reason":"end_turn"}`)
					h := nativeMessagesTestHandler(caller, checker, &MockAuditWriter{})
					h.cfg, h.toolRiskClient = cfg, client
					w = serveNativeMessages(t, h, "/v1/messages", []byte(`{"model":"claude-opus-5","max_tokens":32,"messages":[{"role":"user","content":"safe"}]}`), nil)
				case "responses":
					caller.CallResponse = []byte(`{"id":"resp_header","object":"response","status":"completed","model":"gpt-5.6","output":[{"type":"message","role":"assistant","content":[{"type":"output_text","text":"safe"}]}]}`)
					h := newNativeResponsesTestHandler(caller, checker, &MockAuditWriter{}, true)
					h.cfg, h.toolRiskClient = cfg, client
					request := nativeResponsesRequest(t, []byte(`{"model":"gpt-5.6-sol","input":"safe","reasoning":{"effort":"high"}}`))
					h.Handler().ServeHTTP(w, request)
				case "chat":
					caller.CallResponse = gapChatResponse(t)
					reference := newNativeResponsesTestHandler(caller, checker, &MockAuditWriter{}, false)
					h := NewChatCompletionsHandler(cfg, reference.modelResolver, reference.rateLimiter, checker, &MockAuditWriter{}, reference.providerAdapterFactory, client, nil)
					request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(`{"model":"gpt-5.6-sol","messages":[{"role":"user","content":"safe"}]}`))
					request = request.WithContext(setAuthInfo(request.Context(), "tenant-123", "project-123", "user-123", "key-123", "session-123"))
					h.Handler().ServeHTTP(w, request)
				}
				if w.Code != http.StatusOK || len(caller.CallCalls) != 1 {
					t.Fatalf("buffered request failed: status=%d upstream=%d body=%s", w.Code, len(caller.CallCalls), w.Body.String())
				}
				if got := w.Header().Get(SecurityActionHeader) != ""; got != tc.want {
					t.Fatalf("runtime record=%v header present=%v want=%v", tc.record, got, tc.want)
				}
			})
		}
	}
}
