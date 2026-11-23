package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

type capacityStreamTestError struct{}

func (capacityStreamTestError) Error() string                       { return "output detector pool full" }
func (capacityStreamTestError) InspectionCause() securityexit.Cause { return securityexit.Capacity }

func TestCapacityStreamingPolicyAppliesAcrossProtocolsAndCommitStates(t *testing.T) {
	for _, protocol := range []string{"chat", "responses", "messages"} {
		for _, mode := range []string{"stream_enforce", "stream_audit"} {
			for _, started := range []bool{false, true} {
				for _, test := range []struct {
					name                                                         string
					capacity, auditOnly, detectionClosed, capacityClosed, reject bool
				}{
					{"default", true, false, false, false, false},
					{"capacity-closed", true, false, false, true, true},
					{"detection-only-does-not-close-capacity", true, false, true, false, false},
					{"record-hard-lock", true, true, true, true, false},
					{"ordinary-detection-closed", false, false, true, false, true},
				} {
					t.Run(protocol+"/"+mode+"/started="+strconv.FormatBool(started)+"/"+test.name, func(t *testing.T) {
						client := failClosedClient(t, test.auditOnly, test.detectionClosed)
						t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", strconv.FormatBool(test.capacityClosed))
						var inspectionErr error = errors.New("engine unavailable")
						if test.capacity {
							inspectionErr = capacityStreamTestError{}
						}
						checker := &MockSecurityChecker{OutputError: inspectionErr}
						audit := &MockAuditWriter{}
						cfg := &config.Config{UpstreamStreaming: true, OutputSecurityMode: mode, SecurityAuditOnly: test.auditOnly}
						tracker := &relay.CommitTracker{}
						recorder := httptest.NewRecorder()
						if started {
							if err := tracker.Transition(relay.CommitHeadersCommitted); err != nil {
								t.Fatal(err)
							}
							if err := tracker.Transition(relay.CommitFirstEventFlushed); err != nil {
								t.Fatal(err)
							}
							recorder.WriteHeader(http.StatusOK)
						}
						envelope := &modelrouter.RequestEnvelope{RequestID: "capacity-stream", TenantID: "tenant-123", Model: "public-model"}
						events := []relay.StreamEvent{
							{Type: relay.EventTextDelta, Index: 0, Delta: "unverified-stream-payload"},
							{Type: relay.EventMessageEnd, Index: 0, FinishReason: "stop"},
						}
						if protocol == "responses" {
							events[0].Raw = []byte(`{"type":"response.output_text.delta","delta":"unverified-stream-payload"}`)
							events[1].Raw = []byte(`{"type":"response.completed","response":{"id":"response-test","status":"completed","output":[]}}`)
						} else if protocol == "messages" {
							events[0].Raw = []byte(`{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"unverified-stream-payload"}}`)
							events[1].Raw = []byte(`{"type":"message_stop"}`)
						}
						caller := &liveRelayCaller{reader: &liveRelayReader{events: events}}
						var attempted bool
						var err error
						switch protocol {
						case "chat":
							h := &ChatCompletionsHandler{cfg: cfg, securityClient: checker, auditWriter: audit, toolRiskClient: client}
							attempted, err = h.tryLiveChatStream(context.Background(), recorder, envelope, caller, []byte("{}"), time.Now(), "", tracker)
						case "responses":
							h := &ResponsesHandler{cfg: cfg, securityClient: checker, auditWriter: audit, toolRiskClient: client}
							attempted, err = h.tryLiveNativeResponsesStream(context.Background(), recorder, envelope, caller, []byte("{}"), time.Now(), "", tracker, nil)
						case "messages":
							h := &MessagesHandler{cfg: cfg, securityClient: checker, auditWriter: audit, toolRiskClient: client}
							attempted, err = h.tryLiveNativeMessagesStream(context.Background(), recorder, envelope, caller, []byte("{}"), time.Now(), "", tracker, nil)
						}
						if !attempted {
							t.Fatal("stream was not attempted")
						}
						body := recorder.Body.String()
						if test.reject {
							wantStatus := http.StatusServiceUnavailable
							wantLogStatus := "security_blocked"
							if started {
								wantStatus, wantLogStatus = http.StatusOK, "stream_aborted"
							}
							if err == nil || tracker.CanRetry() || recorder.Code != wantStatus || strings.Contains(body, "unverified-stream-payload") || !strings.Contains(body, "guardrail_detection_unavailable") {
								t.Fatalf("inspection fail-closed must safely terminate: attempted=%t err=%v commit=%s status=%d want=%d body=%s", attempted, err, tracker.State(), recorder.Code, wantStatus, body)
							}
							if len(audit.RequestLogFinalizes) != 1 || audit.RequestLogFinalizes[0].Status != wantLogStatus || audit.RequestLogFinalizes[0].StatusCode != wantStatus || audit.RequestLogFinalizes[0].AuditResult == nil || audit.RequestLogFinalizes[0].AuditResult.ResponseMetadata["output_scan_incomplete"] != true {
								t.Fatalf("actual delivery status and coverage gap must survive termination: %+v", audit.RequestLogFinalizes)
							}
						} else if err != nil || tracker.State() != relay.CommitCompleted || !strings.Contains(body, "unverified-stream-payload") {
							t.Fatalf("default fail-open or record must complete: err=%v state=%s body=%s", err, tracker.State(), body)
						}
					})
				}
			}
		}
	}
}
