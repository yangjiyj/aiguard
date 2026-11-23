package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

func reverseHardeningFixture(t *testing.T, path, contentType, body string, engine http.HandlerFunc, client *ToolRiskClient) (*ReverseProxyHandler, *ReverseProxyRoute, *fakeReverseProxyAuditRecorder, *atomic.Int64) {
	t.Helper()
	calls := &atomic.Int64{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", contentType)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(upstream.Close)
	checker := httptest.NewServer(engine)
	t.Cleanup(checker.Close)
	audit := &fakeReverseProxyAuditRecorder{}
	h := &ReverseProxyHandler{tenantID: "tenant_default", securityURL: checker.URL, client: http.DefaultClient, runtimeConfigClient: client, resolveEgressTarget: testEgressResolver(upstream.URL), auditRecorder: audit}
	route := &ReverseProxyRoute{ID: "hardening", PathPrefix: "/proxy", TargetURL: upstream.URL + path, SecurityEnabled: true, Status: "active"}
	return h, route, audit, calls
}

func reverseHardeningEngine(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Content string `json:"content"`
	}
	json.NewDecoder(r.Body).Decode(&payload)
	action := "allow"
	var findings []map[string]interface{}
	if strings.Contains(payload.Content, "credential-canary") {
		action = "block"
		findings = []map[string]interface{}{{"type": "secret", "category": "credential", "severity": "critical"}}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"action": action, "inspection_status": "completed", "engine_build": "test", "findings": findings})
}

func reverseHardeningForward(t *testing.T, h *ReverseProxyHandler, route *ReverseProxyRoute, method, requestBody string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "/proxy", strings.NewReader(requestBody))
	if requestBody != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	if err := h.forwardRequest(r.Context(), route, w, r); err != nil {
		t.Fatalf("forward: %v body=%s", err, w.Body.String())
	}
	return w
}

func TestReverseSecurityHardeningBlocksBeforeSensitiveFrames(t *testing.T) {
	for _, tc := range []struct{ name, path, body string }{
		{"chat", "/v1/chat/completions", `data: {"choices":[{"delta":{"content":"credential-canary"}}]}` + "\n\ndata: [DONE]\n\n"},
		{"responses", "/v1/responses", `event: response.output_text.delta` + "\n" + `data: {"type":"response.output_text.delta","delta":"credential-canary"}` + "\n\nevent: response.completed\n" + `data: {"type":"response.completed","response":{"output":[]}}` + "\n\n"},
		{"messages", "/v1/messages", `event: content_block_delta` + "\n" + `data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"credential-canary"}}` + "\n\nevent: message_stop\n" + `data: {"type":"message_stop"}` + "\n\n"},
		{"split", "/v1/chat/completions", `data: {"choices":[{"delta":{"content":"credential-"}}]}` + "\n\n" + `data: {"choices":[{"delta":{"content":"canary"}}]}` + "\n\ndata: [DONE]\n\n"},
		{"oversized_delta", "/v1/chat/completions", sseJSON(map[string]interface{}{"choices": []interface{}{map[string]interface{}{"delta": map[string]string{"content": strings.Repeat("safe ", 500) + "credential-canary" + strings.Repeat(" tail", 500)}}}}) + "data: [DONE]\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := failClosedClient(t, false, false)
			h, route, audit, _ := reverseHardeningFixture(t, tc.path, "text/event-stream", tc.body, reverseHardeningEngine, client)
			w := reverseHardeningForward(t, h, route, http.MethodGet, "")
			if strings.Contains(w.Body.String(), "credential-") || strings.Contains(w.Body.String(), `"content":"canary"`) {
				t.Fatalf("sensitive raw frame escaped: %s", w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "output_security_blocked") {
				t.Fatalf("safe terminal event missing: %s", w.Body.String())
			}
			if len(audit.records) != 1 || audit.records[0].Status != "blocked" {
				t.Fatalf("blocked stream audit=%+v", audit.records)
			}
			if len(audit.securityEvents) != 1 || audit.securityEvents[0].actionTaken != "security_blocked" {
				t.Fatalf("effective block event=%+v", audit.securityEvents)
			}
		})
	}
}

func TestReverseSecurityHardeningPreservesSafeNativeFrames(t *testing.T) {
	for _, tc := range []struct{ path, body string }{
		{"/v1/chat/completions", ": heartbeat\r\n\r\nid: chat-1\r\nretry: 7000\r\ndata: " + `{"choices":[{"delta":{"content":"safe output"}}]}` + "\r\n\r\ndata: [DONE]\r\n\r\n"},
		{"/v1/responses", ": heartbeat\n\nid: response-1\nretry: 7000\nevent: response.output_text.delta\ndata: " + `{"type":"response.output_text.delta","item_id":"item-1","output_index":0,"content_index":0,"delta":"safe output"}` + "\n\nevent: response.completed\ndata: " + `{"type":"response.completed","response":{"id":"response-1","status":"completed","output":[]}}` + "\n\n"},
		{"/v1/messages", ": heartbeat\n\nid: message-1\nretry: 7000\nevent: content_block_delta\ndata: " + `{"type":"content_block_delta","index":2,"delta":{"type":"text_delta","text":"safe output"}}` + "\n\nevent: message_stop\ndata: " + `{"type":"message_stop"}` + "\n\n"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			h, route, _, _ := reverseHardeningFixture(t, tc.path, "text/event-stream", tc.body, reverseHardeningEngine, failClosedClient(t, false, false))
			w := reverseHardeningForward(t, h, route, http.MethodGet, "")
			if w.Body.String() != tc.body {
				t.Fatalf("safe frame identity/framing changed: got=%q want=%q", w.Body.String(), tc.body)
			}
		})
	}
}

func TestReverseSecurityHardeningInspectionFailureMatrix(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		record, closed, stream, input bool
		wantStatus                    int
	}{
		{"input_closed", false, true, false, true, 503},
		{"input_open", false, false, false, true, 200},
		{"output_closed", false, true, false, false, 503},
		{"output_open", false, false, false, false, 200},
		{"record_closed", true, true, false, false, 200},
		{"stream_closed", false, true, true, false, 200},
		{"stream_open", false, false, true, false, 200},
		{"stream_record", true, true, true, false, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contentType := "application/json"
			body := `{"choices":[{"message":{"content":"safe output"}}]}`
			if tc.stream {
				contentType = "text/event-stream"
				body = `data: {"choices":[{"delta":{"content":"safe output"}}]}` + "\n\ndata: [DONE]\n\n"
			}
			h, route, audit, calls := reverseHardeningFixture(t, "/v1/chat/completions", contentType, body, func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			}, failClosedClient(t, tc.record, tc.closed))
			method, requestBody := http.MethodGet, ""
			if tc.input {
				method = http.MethodPost
				requestBody = `{"model":"test","messages":[{"role":"user","content":"hello"}]}`
			}
			w := reverseHardeningForward(t, h, route, method, requestBody)
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
			if tc.input && tc.closed && !tc.record && calls.Load() != 0 {
				t.Fatal("fail-closed input was forwarded")
			}
			if tc.stream && tc.closed && !tc.record {
				if strings.Contains(w.Body.String(), "safe output") || !strings.Contains(w.Body.String(), guardrailDetectionUnavailableCode) {
					t.Fatalf("failed inspection must stop pending frames safely: %s", w.Body.String())
				}
			} else if tc.stream && w.Body.String() != body {
				t.Fatalf("open/record stream changed: %s", w.Body.String())
			}
			if len(audit.securityEvents) == 0 {
				t.Fatal("coverage gap audit event missing")
			}
			for _, event := range audit.securityEvents {
				if event.actionTaken != "audit" && event.actionTaken != "block" {
					t.Fatalf("coverage gap effective action=%s", event.actionTaken)
				}
			}
		})
	}
}

func TestReverseSecurityHardeningAuditOnlyDeploymentLock(t *testing.T) {
	// 2.9.22（D7）：部署变量只在没有显式执行模式时作初值，这里用未托管（unmanaged）的快照；
	// 托管 protect 时按防护执行（原用例用托管 protect 断言“部署锁压过控制台”，随之改写）。
	client := failClosedClient(t, false, true)
	runtime, _ := client.runtimeCache.getSemanticConfig()
	runtime.SecurityExecutionModeManaged = false
	client.runtimeCache.setSemanticConfig(runtime)
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	body := `data: {"choices":[{"delta":{"content":"credential-canary"}}]}` + "\n\ndata: [DONE]\n\n"
	h, route, audit, _ := reverseHardeningFixture(t, "/v1/chat/completions", "text/event-stream", body, reverseHardeningEngine, client)
	w := reverseHardeningForward(t, h, route, http.MethodGet, "")
	if w.Code != 200 || w.Body.String() != body {
		t.Fatalf("deployment record lock interrupted stream: %d %s", w.Code, w.Body.String())
	}
	if len(audit.records) != 1 || audit.records[0].Status != "success" {
		t.Fatalf("record status=%+v", audit.records)
	}
}

func TestReverseSecurityHardeningDeploymentLockWithoutRuntimeClient(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	body := `{"choices":[{"message":{"content":"credential-canary"}}]}`
	h, route, audit, _ := reverseHardeningFixture(t, "/v1/chat/completions", "application/json", body, reverseHardeningEngine, nil)
	w := reverseHardeningForward(t, h, route, http.MethodGet, "")
	if w.Code != 200 || w.Body.String() != body {
		t.Fatalf("deployment record lock ignored without runtime client: %d %s", w.Code, w.Body.String())
	}
	if len(audit.records) != 1 || audit.records[0].Status != "success" || len(audit.securityEvents) != 1 || audit.securityEvents[0].actionTaken != "security_audit_only" {
		t.Fatalf("deployment lock audit=%+v %+v", audit.records, audit.securityEvents)
	}
}

func TestReverseSecurityHardeningStreamAuditKeepsFailurePolicyLive(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		failure, closed, record bool
		blocked                 bool
	}{
		{"rule_hit_records", false, false, false, false},
		{"detection_open", true, false, false, false},
		{"detection_closed", true, true, false, true},
		{"record_closed", true, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `data: {"choices":[{"delta":{"content":"credential-canary"}}]}` + "\n\ndata: [DONE]\n\n"
			engine := http.HandlerFunc(reverseHardeningEngine)
			if tc.failure {
				engine = func(w http.ResponseWriter, r *http.Request) { http.Error(w, "unavailable", 503) }
			}
			h, route, audit, _ := reverseHardeningFixture(t, "/v1/chat/completions", "text/event-stream", body, engine, failClosedClient(t, tc.record, tc.closed))
			if setter, ok := any(h).(interface{ SetOutputStreamConfig(*config.Config) }); ok {
				setter.SetOutputStreamConfig(&config.Config{OutputSecurityMode: "stream_audit"})
			}
			w := reverseHardeningForward(t, h, route, http.MethodGet, "")
			if tc.blocked {
				if strings.Contains(w.Body.String(), "credential-canary") || !strings.Contains(w.Body.String(), guardrailDetectionUnavailableCode) {
					t.Fatalf("stream_audit disabled fail-closed: %s", w.Body.String())
				}
				if len(audit.records) != 1 || audit.records[0].Status != "blocked" {
					t.Fatalf("closed record=%+v", audit.records)
				}
			} else if w.Body.String() != body {
				t.Fatalf("stream_audit altered recorded output: %s", w.Body.String())
			}
		})
	}
}

func TestReverseSecurityHardeningCapacityPolicyIsIndependent(t *testing.T) {
	for _, tc := range []struct {
		name                                            string
		capacityClosed, detectionClosed, stream, record bool
		reject                                          bool
	}{
		{"buffer_default_open", false, true, false, false, false},
		{"buffer_capacity_closed", true, false, false, false, true},
		{"stream_default_open", false, true, true, false, false},
		{"stream_capacity_closed", true, false, true, false, true},
		{"record_capacity_closed", true, true, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_CAPACITY_FAIL_CLOSED", fmt.Sprint(tc.capacityClosed))
			body, ct := `{"choices":[{"message":{"content":"safe output"}}]}`, "application/json"
			if tc.stream {
				body = `data: {"choices":[{"delta":{"content":"safe output"}}]}` + "\n\ndata: [DONE]\n\n"
				ct = "text/event-stream"
			}
			h, route, audit, _ := reverseHardeningFixture(t, "/v1/chat/completions", ct, body, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(503)
				fmt.Fprint(w, `{"detail":{"code":"output_capacity_overflow","inspection_status":"incomplete"}}`)
			}, failClosedClient(t, tc.record, tc.detectionClosed))
			if setter, ok := any(h).(interface{ SetOutputStreamConfig(*config.Config) }); ok {
				setter.SetOutputStreamConfig(&config.Config{OutputSecurityMode: "stream_audit"})
			}
			w := reverseHardeningForward(t, h, route, http.MethodGet, "")
			if tc.reject {
				if strings.Contains(w.Body.String(), "safe output") || !strings.Contains(w.Body.String(), guardrailDetectionUnavailableCode) {
					t.Fatalf("capacity rejection missing: %d %s", w.Code, w.Body.String())
				}
				if !tc.stream && w.Code != 503 {
					t.Fatalf("capacity status=%d want503", w.Code)
				}
			} else if w.Code != 200 || w.Body.String() != body {
				t.Fatalf("capacity default/record interrupted: %d %s", w.Code, w.Body.String())
			}
			if len(audit.securityEvents) != 1 || audit.securityEvents[0].record.OutputSemanticReason != "output_capacity_overflow" {
				t.Fatalf("capacity gap reason lost: %+v", audit.securityEvents)
			}
		})
	}
}

func TestReverseSecurityHardeningRecordedRuleHitHasEffectiveAuditAction(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		record                bool
		outputMode, wantEvent string
	}{
		{"deployment_record", true, "stream_enforce", "security_audit_only"},
		{"output_record", false, "stream_audit", "security_audit"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `data: {"choices":[{"delta":{"content":"credential-canary"}}]}` + "\n\ndata: [DONE]\n\n"
			h, route, audit, _ := reverseHardeningFixture(t, "/v1/chat/completions", "text/event-stream", body, reverseHardeningEngine, failClosedClient(t, tc.record, false))
			if setter, ok := any(h).(interface{ SetOutputStreamConfig(*config.Config) }); ok {
				setter.SetOutputStreamConfig(&config.Config{OutputSecurityMode: tc.outputMode})
			}
			d, err := h.checkStreamInspection(context.Background(), "audit-test", "credential-canary", "", "api.openai.com", "/v1/chat/completions")
			if err != nil || !d.Allowed || d.Action != "audit" {
				t.Fatalf("recorded rule hit reported enforce action: %+v %v", d, err)
			}
			raw := reflect.ValueOf(d).FieldByName("RawAction")
			if !raw.IsValid() || raw.String() != "block" {
				t.Fatalf("raw would-block evidence missing: %+v", d)
			}
			w := reverseHardeningForward(t, h, route, http.MethodGet, "")
			if w.Body.String() != body || len(audit.securityEvents) != 1 || audit.securityEvents[0].actionTaken != tc.wantEvent {
				t.Fatalf("recorded rule event=%+v body=%s", audit.securityEvents, w.Body.String())
			}
			row := buildReverseProxySecurityEventRow(audit.securityEvents[0].record, "output", tc.wantEvent, audit.securityEvents[0].findings)
			if row.MatchedSummary["raw_action"] != "block" || row.MatchedSummary["would_block"] != true || row.MatchedSummary["enforcement_boundary"] != "stream_holdback" {
				t.Fatalf("raw/effective or boundary audit=%+v", row.MatchedSummary)
			}
		})
	}
}

func TestReverseSecurityHardeningDisabledOutputBypassesHoldbackBudget(t *testing.T) {
	p := inspectionscope.Default()
	p.InspectModelOutput = false
	client := inspectionTestClient(p)
	checked := &atomic.Int64{}
	body := "data: " + strings.Repeat("unparsed ", 1000) + "\n\n"
	h, route, audit, _ := reverseHardeningFixture(t, "/v1/chat/completions", "text/event-stream", body, func(w http.ResponseWriter, r *http.Request) { checked.Add(1); http.Error(w, "must not inspect", 503) }, client)
	if setter, ok := any(h).(interface{ SetOutputStreamConfig(*config.Config) }); ok {
		setter.SetOutputStreamConfig(&config.Config{OutputStreamPendingBytes: 8, OutputSecurityMode: "strict_buffered", OutputStrictMaxBytes: 8})
	}
	w := reverseHardeningForward(t, h, route, http.MethodGet, "")
	if w.Body.String() != body || checked.Load() != 0 || len(audit.securityEvents) != 0 {
		t.Fatalf("disabled inspection affected stream: checked=%d events=%+v body=%s", checked.Load(), audit.securityEvents, w.Body.String())
	}
	if len(audit.records) != 1 || audit.records[0].OutputSemanticStatus != "disabled" {
		t.Fatalf("disabled inspection posture missing: %+v", audit.records)
	}
	if guarded := reflect.ValueOf(audit.records[0]).FieldByName("OutputGuarded"); guarded.IsValid() && guarded.Bool() {
		t.Fatalf("disabled stream advertised holdback inspection: %+v", audit.records)
	}
}

func TestReverseSecurityHardeningOversizedFramePreservesFailOpenWireBytes(t *testing.T) {
	body := "data: " + strings.Repeat("safe ", maxInspectionSSEEvent/5+100) + "\n\ndata: [DONE]\n\n"
	for _, tc := range []struct {
		name           string
		closed, record bool
	}{{"open", false, false}, {"closed", true, false}, {"record_closed", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			h, route, audit, _ := reverseHardeningFixture(t, "/v1/chat/completions", "text/event-stream", body, reverseHardeningEngine, failClosedClient(t, tc.record, tc.closed))
			w := reverseHardeningForward(t, h, route, http.MethodGet, "")
			if tc.closed && !tc.record {
				if strings.Contains(w.Body.String(), "safe ") || !strings.Contains(w.Body.String(), guardrailDetectionUnavailableCode) {
					t.Fatalf("over-limit failure was not safely closed: bytes=%d", w.Body.Len())
				}
			} else if w.Body.String() != body {
				t.Fatalf("fail-open parser lost wire bytes: got=%d want=%d", w.Body.Len(), len(body))
			}
			if len(audit.securityEvents) != 1 || audit.securityEvents[0].record.OutputSemanticStatus != "incomplete" {
				t.Fatalf("parser coverage gap missing: %+v", audit.securityEvents)
			}
		})
	}
}

type reverseTimeoutRoundTripper func(*http.Request) (*http.Response, error)

func (f reverseTimeoutRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestReverseSecurityHardeningPayloadTimeoutBudget(t *testing.T) {
	t.Setenv("SECURITY_ENGINE_TIMEOUT", "200ms")
	t.Setenv("SECURITY_ENGINE_MAX_TIMEOUT", "3s")
	for _, tc := range []struct {
		size        int
		outer, want time.Duration
	}{
		{0, 0, 200 * time.Millisecond}, {1024, 0, 250 * time.Millisecond}, {4096, 0, 400 * time.Millisecond}, {64 << 10, 0, 3 * time.Second}, {4096, 50 * time.Millisecond, 50 * time.Millisecond},
	} {
		captured := time.Duration(0)
		h := &ReverseProxyHandler{securityURL: "http://engine.invalid", client: &http.Client{Timeout: 5 * time.Millisecond, Transport: reverseTimeoutRoundTripper(func(r *http.Request) (*http.Response, error) {
			deadline, ok := r.Context().Deadline()
			if !ok {
				t.Fatal("inspection request has no deadline")
			}
			captured = time.Until(deadline)
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"action":"allow","inspection_status":"completed"}`))}, nil
		})}}
		ctx := context.Background()
		cancel := func() {}
		if tc.outer > 0 {
			ctx, cancel = context.WithTimeout(ctx, tc.outer)
		}
		_, err := h.postReverseInspection(ctx, "/check-output/", bytes.Repeat([]byte("x"), tc.size))
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if captured > tc.want || captured < tc.want-20*time.Millisecond {
			t.Fatalf("payload=%d timeout=%s want~%s", tc.size, captured, tc.want)
		}
	}
}
