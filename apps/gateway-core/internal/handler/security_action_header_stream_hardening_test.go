package handler

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

func TestSecurityActionHeaderUsesConsumedRuntimeModeAcrossStreams(t *testing.T) {
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
				cfg.UpstreamStreaming = true
				cfg.OutputSecurityMode = "stream_enforce"
				client := failClosedClient(t, tc.record, false)
				events := []relay.StreamEvent{
					{Type: relay.EventTextDelta, Index: 0, Delta: "safe-response"},
					{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop"},
				}
				if protocol == "responses" {
					events[0].Raw = []byte(`{"type":"response.output_text.delta","delta":"safe-response"}`)
					events[1].Raw = []byte(`{"type":"response.completed","response":{"id":"header-test","status":"completed","output":[]}}`)
				} else if protocol == "messages" {
					events[0].Raw = []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"safe-response"}}`)
					events[1].Raw = []byte(`{"type":"message_stop"}`)
				}
				caller := &liveRelayCaller{reader: &liveRelayReader{events: events}}
				envelope := &modelrouter.RequestEnvelope{RequestID: "header-test", TenantID: "tenant-123", Model: "test"}
				w, tracker := httptest.NewRecorder(), &relay.CommitTracker{}
				checker, audit := &MockSecurityChecker{}, &MockAuditWriter{}
				var attempted bool
				switch protocol {
				case "chat":
					h := &ChatCompletionsHandler{cfg: cfg, toolRiskClient: client, securityClient: checker, auditWriter: audit}
					attempted, err = h.tryLiveChatStream(context.Background(), w, envelope, caller, []byte("{}"), time.Now(), "audit", tracker)
				case "responses":
					h := &ResponsesHandler{cfg: cfg, toolRiskClient: client, securityClient: checker, auditWriter: audit}
					attempted, err = h.tryLiveNativeResponsesStream(context.Background(), w, envelope, caller, []byte("{}"), time.Now(), "audit", tracker, nil)
				case "messages":
					h := &MessagesHandler{cfg: cfg, toolRiskClient: client, securityClient: checker, auditWriter: audit}
					attempted, err = h.tryLiveNativeMessagesStream(context.Background(), w, envelope, caller, []byte("{}"), time.Now(), "audit", tracker, nil)
				}
				if err != nil || !attempted || tracker.State() != relay.CommitCompleted {
					t.Fatalf("stream failed: attempted=%v err=%v state=%s body=%s", attempted, err, tracker.State(), w.Body.String())
				}
				if got := w.Header().Get(SecurityActionHeader) != ""; got != tc.want {
					t.Fatalf("runtime record=%v header present=%v want=%v", tc.record, got, tc.want)
				}
			})
		}
	}
}
