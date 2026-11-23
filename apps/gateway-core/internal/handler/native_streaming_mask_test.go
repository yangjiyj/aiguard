package handler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// r2922 对抗复核：原生流式里配置为“脱敏”的命中不能升级成阻断。能重写的（增量、Responses 终态快照）
// 用已脱敏文本重写；无法脱敏的元数据帧放行并告警（与聊天流式、附件、独立代理一致，2026-09-23 定案）。

const nativeMaskSecret = "sk-live-secret-123"
const nativeMaskEcho = "instr-secret-456"

// maskingStreamSecurity 对含秘密的输出判“脱敏”，并把秘密换成 [MASKED]。
type maskingStreamSecurity struct {
	mu    sync.Mutex
	calls []string
}

func (s *maskingStreamSecurity) CheckInput(context.Context, *modelrouter.RequestEnvelope, string, int, string, string) (string, string, []SecurityFinding, error) {
	return "allow", "", nil, nil
}

func (s *maskingStreamSecurity) CheckOutput(_ context.Context, _ *modelrouter.RequestEnvelope, content string, _ int) (string, string, []SecurityFinding, error) {
	s.mu.Lock()
	s.calls = append(s.calls, content)
	s.mu.Unlock()
	if !strings.Contains(content, nativeMaskSecret) && !strings.Contains(content, nativeMaskEcho) {
		return "allow", content, nil, nil
	}
	masked := strings.NewReplacer(nativeMaskSecret, "[MASKED]", nativeMaskEcho, "[MASKED]").Replace(content)
	return "mask", masked, []SecurityFinding{{Type: "secret", Category: "api_key", Severity: "high", RuleID: "secret-mask", Action: "mask"}}, nil
}

func (s *maskingStreamSecurity) CheckSemanticOnly(context.Context, *modelrouter.RequestEnvelope, string) ([]SecurityFinding, error) {
	return nil, nil
}

func (s *maskingStreamSecurity) CheckTriage(_ context.Context, _ *modelrouter.RequestEnvelope, _ string, findings []SecurityFinding) ([]SecurityFinding, error) {
	return findings, nil
}

func nativeMaskHTTP(t *testing.T, protocol, mode, upstreamBody string) (string, *MockAuditWriter) {
	t.Helper()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, upstreamBody)
	}))
	defer upstream.Close()
	cfg := &config.Config{UpstreamStreaming: true, OutputSecurityMode: mode}
	record := &modelrouter.ModelRecord{ID: "model", ProviderID: "provider", ModelName: "test", UpstreamModelID: "test", ProviderType: "openai", ProviderBaseURL: upstream.URL, Status: "active", ResponsesNative: true}
	reqBody := `{"model":"test","input":"inspect","stream":true}`
	if protocol == "messages" {
		record.ProviderType = "anthropic"
		reqBody = `{"model":"test","max_tokens":100,"messages":[{"role":"user","content":"inspect"}],"stream":true}`
	}
	resolver := &MockModelResolver{ProviderAPIKey: "fixture-key", ModelRecord: record}
	audit := &MockAuditWriter{}
	var handler http.HandlerFunc
	if protocol == "messages" {
		handler = NewMessagesHandler(cfg, resolver, &MockRateLimitChecker{}, &maskingStreamSecurity{}, audit, &RealProviderAdapterFactory{}, nil, nil).Handler()
	} else {
		handler = NewResponsesHandler(cfg, resolver, &MockRateLimitChecker{}, &maskingStreamSecurity{}, audit, &RealProviderAdapterFactory{}, nil, nil).Handler()
	}
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(setAuthInfo(r.Context(), "tenant", "project", "user", "key", "session"))
		handler.ServeHTTP(w, r)
	}))
	defer gateway.Close()
	resp, err := http.Post(gateway.URL+"/v1/"+protocol, "application/json", strings.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(body), audit
}

func nativeMaskUnavailableAlerted(audit *MockAuditWriter) bool {
	audit.mu.Lock()
	defer audit.mu.Unlock()
	for _, event := range audit.SecurityEventWrites {
		if event.ActionTaken == "security_audit" && event.MaskUnavailable {
			return true
		}
	}
	return false
}

func nativeMaskRequestLogMarked(audit *MockAuditWriter) bool {
	for _, final := range audit.RequestLogFinalizes {
		if final.AuditResult != nil && final.AuditResult.ResponseMetadata["mask_unavailable"] == true {
			return true
		}
	}
	return false
}

const nativeMaskResponsesBase = "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp\",\"output\":[]}}\n\n" +
	"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg\",\"output_index\":0,\"content_index\":0,\"sequence_number\":5,\"delta\":\"key=DELTA_A\"}\n\n" +
	"event: response.output_text.delta\ndata: {\"type\":\"response.output_text.delta\",\"item_id\":\"msg\",\"output_index\":0,\"content_index\":0,\"sequence_number\":6,\"delta\":\"DELTA_B\"}\n\n" +
	"event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"test\"TERMINAL_EXTRA,\"output\":TERMINAL_OUTPUT,\"usage\":{\"input_tokens\":1,\"output_tokens\":2}}}\n\n"

func nativeMaskResponsesFixture(deltaA, deltaB, terminalExtra, terminalOutput, createdExtra string) string {
	fixture := strings.NewReplacer("DELTA_A", deltaA, "DELTA_B", deltaB, "TERMINAL_EXTRA", terminalExtra, "TERMINAL_OUTPUT", terminalOutput).Replace(nativeMaskResponsesBase)
	return strings.Replace(fixture, `"type":"response.created","response":{"id":"resp"`, `"type":"response.created","response":{"id":"resp"`+createdExtra, 1)
}

const nativeMaskMessagesBase = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg\",\"model\":\"test\",\"content\":[],\"usage\":{\"input_tokens\":1}START_EXTRA}}\n\n" +
	"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"key=DELTA_A\"}}\n\n" +
	"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"DELTA_B\"}}\n\n" +
	"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
	"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}DELTA_EXTRA}\n\n" +
	"event: message_stop\ndata: {\"type\":\"message_stop\"STOP_EXTRA}\n\n"

func nativeMaskMessagesFixture(deltaA, deltaB, startExtra, deltaExtra, stopExtra string) string {
	return strings.NewReplacer("DELTA_A", deltaA, "DELTA_B", deltaB, "START_EXTRA", startExtra, "DELTA_EXTRA", deltaExtra, "STOP_EXTRA", stopExtra).Replace(nativeMaskMessagesBase)
}

func TestHTTPNativeConfiguredMaskIsNeverUpgradedToBlock(t *testing.T) {
	secretOutput := `[{"type":"message","id":"msg","status":"completed","role":"assistant","content":[{"type":"output_text","text":"key=` + nativeMaskSecret + `","annotations":[]}]}]`
	for _, tc := range []struct {
		name, protocol, fixture string
		// leak 是放行后客户端仍会看到的原文（无法脱敏的元数据帧）；空表示原文不得出现。
		leak       string
		wantMasked bool
		wantAlert  bool
	}{
		{name: "responses delta", protocol: "responses", fixture: nativeMaskResponsesFixture("sk-live-", "secret-123", "", "[]", ""), wantMasked: true},
		{name: "responses terminal full output", protocol: "responses", fixture: nativeMaskResponsesFixture("sk-live-", "secret-123", "", secretOutput, ""), wantMasked: true},
		{name: "responses terminal instructions echo", protocol: "responses", fixture: nativeMaskResponsesFixture("hello-", "world", `,"instructions":"`+nativeMaskEcho+`"`, "[]", "")},
		{name: "responses metadata frame", protocol: "responses", fixture: nativeMaskResponsesFixture("hello-", "world", "", "[]", `,"instructions":"`+nativeMaskEcho+`"`), leak: nativeMaskEcho, wantAlert: true},
		{name: "messages delta", protocol: "messages", fixture: nativeMaskMessagesFixture("sk-live-", "secret-123", "", "", ""), wantMasked: true},
		{name: "messages terminal full output", protocol: "messages", fixture: nativeMaskMessagesFixture("sk-live-", "secret-123", "", `,"content":[{"type":"text","text":"key=`+nativeMaskSecret+`"}]`, ""), wantMasked: true},
		{name: "messages terminal instructions echo", protocol: "messages", fixture: nativeMaskMessagesFixture("hello-", "world", "", "", `,"system":"`+nativeMaskEcho+`"`)},
		{name: "messages metadata frame", protocol: "messages", fixture: nativeMaskMessagesFixture("hello-", "world", `,"system":"`+nativeMaskEcho+`"`, "", ""), leak: nativeMaskEcho, wantAlert: true},
	} {
		for _, mode := range []string{"stream_enforce", "strict_buffered"} {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				body, audit := nativeMaskHTTP(t, tc.protocol, mode, tc.fixture)
				if strings.Contains(body, "security_blocked") {
					t.Fatalf("配置为脱敏不能升级成阻断：%s", body)
				}
				terminal := "event: message_stop"
				if tc.protocol == "responses" {
					terminal = "event: response.completed"
				}
				if strings.Count(body, terminal) != 1 {
					t.Fatalf("终态缺失或重复：%s", body)
				}
				if strings.Contains(body, nativeMaskSecret) {
					t.Fatalf("能重写的输出必须按脱敏文本发出：%s", body)
				}
				if tc.leak == "" && strings.Contains(body, nativeMaskEcho) {
					t.Fatalf("能重写的终态快照不得带出原文：%s", body)
				}
				if tc.leak != "" && !strings.Contains(body, tc.leak) {
					t.Fatalf("无法脱敏的元数据帧放行原文：%s", body)
				}
				if tc.wantMasked && !strings.Contains(body, "[MASKED]") {
					t.Fatalf("输出应为脱敏文本：%s", body)
				}
				if got := nativeMaskUnavailableAlerted(audit); got != tc.wantAlert {
					t.Fatalf("无法脱敏告警=%v want %v：%+v", got, tc.wantAlert, audit.SecurityEventWrites)
				}
				if tc.wantAlert && !nativeMaskRequestLogMarked(audit) {
					t.Fatalf("请求记录应标 mask_unavailable：%+v", audit.RequestLogFinalizes)
				}
			})
		}
	}
}
