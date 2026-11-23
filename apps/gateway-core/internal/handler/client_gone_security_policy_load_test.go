package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// AgentGuard 策略加载（GetAgentGuardPolicy）用请求 ctx 发 HTTP；客户端在此期间断开，请求随 ctx 取消失败。
// 原先 analyzeAgentGuardToolCall 把它包成 errAgentGuardPolicyUnavailable，applyAgentGuardToolDecisionResult
// 写 agentguard_policy_load_failed 事件、设 tool_policy_coverage_gap，fail-closed 时还返回
// errGuardrailDetectionUnavailable（输出侧 503）。这不是策略不可用，是客户端走了：
// 返回哨兵，不写事件、不设覆盖缺口、不走 fail-closed。

// policyHangControlPlane 起一个控制面：agentguard/effective-policy 请求阻塞到请求 ctx 取消（模拟控制面慢、客户端先走）；
// failWith 非空时改为立即返回该 HTTP 状态（对照组：加载返回非取消错误）。
type policyHangControlPlane struct {
	hits atomic.Int32
	url  string
}

func newPolicyControlPlane(t *testing.T, entered chan struct{}, failStatus int) *policyHangControlPlane {
	t.Helper()
	cp := &policyHangControlPlane{}
	var once atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			cp.hits.Add(1)
			if failStatus != 0 {
				http.Error(w, "boom", failStatus)
				return
			}
			if once.CompareAndSwap(false, true) && entered != nil {
				close(entered)
			}
			<-r.Context().Done()
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	cp.url = server.URL
	return cp
}

func policyToolCallResponse(t *testing.T) []byte {
	t.Helper()
	call := ToolCall{ID: "call_1", Type: "function", Function: ToolCallFunc{Name: "read_file", Arguments: `{"path":"README.md"}`}}
	return destructiveChatResponse(t, "", call)
}

func TestApplyOutputSecurityPolicyLoadClientGone(t *testing.T) {
	for _, wrapMode := range []struct {
		name   string
		status int // 0 = 阻塞到请求 ctx 取消（客户端断开）；非 0 = 对照组：立即返回该 HTTP 状态
	}{{"client_gone", 0}, {"control_plane_503", http.StatusServiceUnavailable}, {"control_plane_500", http.StatusInternalServerError}} {
		for _, cfg := range goneConfigs {
			t.Run(wrapMode.name+"/"+cfg.name, func(t *testing.T) {
				entered := make(chan struct{})
				cp := newPolicyControlPlane(t, entered, wrapMode.status)
				client := NewToolRiskClient(cp.url, "internal-secret")
				setToolGuardTestPosture(t, client, cfg.auditOnly, cfg.failClosed)

				ctx, cancel := context.WithCancel(context.WithValue(context.Background(), detachProbeKey{}, detachProbeMarker))
				defer cancel()
				if wrapMode.status == 0 {
					go func() { <-entered; cancel() }()
				}
				audit := &MockAuditWriter{}
				h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, securityClient: &MockSecurityChecker{}, auditWriter: audit}
				envelope := &modelrouter.RequestEnvelope{RequestID: "req-policy-gone", TenantID: "tenant-client-gone", UserID: "user-1", SessionID: "session-1"}

				_, result, err := h.applyOutputSecurity(ctx, envelope, nil, policyToolCallResponse(t))

				if wrapMode.status == 0 {
					if !errors.Is(err, context.Canceled) || isGuardrailDetectionUnavailable(err) {
						t.Errorf("客户端断开应返回包装 context.Canceled 的哨兵错误且不是 fail-closed 拒绝, got %v", err)
					}
					if hasSecurityEvent(audit, agentGuardPolicyLoadFailureReason) {
						t.Errorf("断开不应写 %s 事件: %#v", agentGuardPolicyLoadFailureReason, audit.SecurityEventWrites)
					}
					if result != nil && result.ResponseMetadata != nil {
						if _, set := result.ResponseMetadata["tool_policy_coverage_gap"]; set {
							t.Errorf("断开不应设置 tool_policy_coverage_gap: %#v", result.ResponseMetadata)
						}
					}
					return
				}
				// 对照组：控制面故障。策略加载失败仍写事件、设覆盖缺口；只有 protect + fail-closed 拒绝（503 语义）。
				if !hasSecurityEvent(audit, agentGuardPolicyLoadFailureReason) {
					t.Errorf("对照组应写 %s 事件: %#v", agentGuardPolicyLoadFailureReason, audit.SecurityEventWrites)
				}
				if result == nil || result.ResponseMetadata == nil {
					t.Fatalf("对照组应设置覆盖缺口元数据, got %#v", result)
				}
				if _, set := result.ResponseMetadata["tool_policy_coverage_gap"]; !set {
					t.Errorf("对照组应设置 tool_policy_coverage_gap: %#v", result.ResponseMetadata)
				}
				wantReject := cfg.failClosed && !cfg.auditOnly
				if got := isGuardrailDetectionUnavailable(err); got != wantReject {
					t.Errorf("对照组 fail-closed 拒绝=%v, want %v (err=%v)", got, wantReject, err)
				}
				if !wantReject && err != nil {
					t.Errorf("对照组放行场景不应返回错误: %v", err)
				}
			})
		}
	}
}

// 端到端：chat 非流式带 tool_calls，策略加载期间客户端断开 -> client_canceled/408；
// fail-closed 下不是 503；对照组（控制面 503）原行为不变。
func TestChatNonStreamPolicyLoadClientGone(t *testing.T) {
	for _, stage := range []struct {
		name   string
		status int
	}{{"client_gone", 0}, {"control_plane_503", http.StatusServiceUnavailable}} {
		for _, cfg := range goneConfigs {
			t.Run(stage.name+"/"+cfg.name, func(t *testing.T) {
				entered := make(chan struct{})
				cp := newPolicyControlPlane(t, entered, stage.status)
				client := NewToolRiskClient(cp.url, "internal-secret")
				setToolGuardTestPosture(t, client, cfg.auditOnly, cfg.failClosed)

				ctx, cancel := context.WithCancel(context.WithValue(context.Background(), detachProbeKey{}, detachProbeMarker))
				defer cancel()
				if stage.status == 0 {
					go func() { <-entered; cancel() }()
				}
				probe := &ctxProbe{}
				db := &goneDB{probe: probe, t: t}
				writer := &RealAuditWriter{db: db}
				h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, writer,
					fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: policyToolCallResponse(t)}}, client, nil)

				res := serveGone(h.Handler(), goneChatRequest(ctx, false))

				fin := db.finalizes()
				if len(fin) == 0 {
					t.Fatalf("request_logs 没有收尾写入 (events=%v body=%q)", db.eventNames(), res.body)
				}
				last := fin[len(fin)-1]
				names := db.eventNames()
				if stage.status == 0 {
					if last.status != "client_canceled" || last.code != http.StatusRequestTimeout {
						t.Errorf("收尾=%s/%d, want client_canceled/408 (events=%v body=%q)", last.status, last.code, names, res.body)
					}
					if res.httpCode == http.StatusServiceUnavailable || strings.Contains(res.body, guardrailDetectionUnavailableCode) {
						t.Errorf("客户端断开不应走 fail-closed 503: http=%d body=%q", res.httpCode, res.body)
					}
					if containsString(names, agentGuardPolicyLoadFailureReason) {
						t.Errorf("断开不应写 %s 事件: %v", agentGuardPolicyLoadFailureReason, names)
					}
					probe.require(t, "db.finalize")
					return
				}
				wantStatus, wantCode := "success", http.StatusOK
				if cfg.failClosed && !cfg.auditOnly {
					wantStatus, wantCode = "security_blocked", http.StatusServiceUnavailable
				}
				if last.status != wantStatus || last.code != wantCode {
					t.Errorf("对照组收尾=%s/%d, want %s/%d (events=%v)", last.status, last.code, wantStatus, wantCode, names)
				}
				if !containsString(names, agentGuardPolicyLoadFailureReason) {
					t.Errorf("对照组应写 %s 事件: %v", agentGuardPolicyLoadFailureReason, names)
				}
			})
		}
	}
}

// 其余出口：同一个策略加载断开，经 messages 原生、responses 原生、实时流（chat）都应落到 client_canceled。
func TestPolicyLoadClientGoneAcrossProtocols(t *testing.T) {
	for _, proto := range []string{"messages_native", "responses_native", "responses_compat", "chat_buffered_stream"} {
		for _, cfg := range []goneConfig{goneConfigs[0], goneConfigs[1]} {
			t.Run(proto+"/"+cfg.name, func(t *testing.T) {
				entered := make(chan struct{})
				cp := newPolicyControlPlane(t, entered, 0)
				client := NewToolRiskClient(cp.url, "internal-secret")
				setToolGuardTestPosture(t, client, cfg.auditOnly, cfg.failClosed)
				ctx, cancel := context.WithCancel(context.WithValue(context.Background(), detachProbeKey{}, detachProbeMarker))
				defer cancel()
				go func() { <-entered; cancel() }()
				db := &goneDB{probe: &ctxProbe{}, t: t}
				writer := &RealAuditWriter{db: db}

				var res goneResult
				switch proto {
				case "messages_native":
					toolUse := []byte(`{"id":"msg_tool","type":"message","role":"assistant","model":"claude-opus-5","content":[{"type":"tool_use","id":"toolu_1","name":"read_file","input":{"path":"README.md"}}],"stop_reason":"tool_use","stop_sequence":null,"usage":{"input_tokens":10,"output_tokens":5}}`)
					resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
						ID: "model-native", ModelName: "claude-opus-5", ProviderID: "provider-native",
						ProviderType: "openai", ProviderBaseURL: "https://boflow.example", UpstreamModelID: "kiro-opus", Status: "active",
					}}
					h := NewMessagesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, writer,
						fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: toolUse}}, client, nil)
					res = serveGone(h.Handler(), goneMessagesRequest(ctx, false))
				case "responses_native":
					native := `{"id":"resp_n","object":"response","status":"completed","model":"gpt-5.6","output":[{"id":"fc_1","type":"function_call","call_id":"call_1","name":"read_file","arguments":"{\"path\":\"README.md\"}","status":"completed"}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`
					h := newGoneResponsesHandler(&goneEnv{sec: &goneSecurity{}, writer: writer, client: client, metrics: nil}, &config.Config{}, true,
						&MockProviderCaller{CallResponse: []byte(native)})
					res = serveGone(h.Handler(), goneResponsesRequest(ctx, responsesKeepalivePlainBody))
				case "responses_compat":
					h := newGoneResponsesHandler(&goneEnv{sec: &goneSecurity{}, writer: writer, client: client, metrics: nil}, &config.Config{}, false,
						&MockProviderCaller{CallResponse: policyToolCallResponse(t)})
					res = serveGone(h.Handler(), goneResponsesRequest(ctx, compatKeepalivePlainBody))
				case "chat_buffered_stream":
					h := NewChatCompletionsHandler(&config.Config{UpstreamStreaming: false}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, writer,
						fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: policyToolCallResponse(t)}}, client, nil)
					res = serveGone(h.Handler(), goneChatRequest(ctx, true))
				}

				fin := db.finalizes()
				if len(fin) == 0 {
					t.Fatalf("request_logs 没有收尾写入 (events=%v body=%q)", db.eventNames(), res.body)
				}
				last := fin[len(fin)-1]
				if last.status != "client_canceled" || last.code != http.StatusRequestTimeout {
					t.Errorf("收尾=%s/%d, want client_canceled/408 (events=%v body=%q)", last.status, last.code, db.eventNames(), res.body)
				}
				if res.httpCode == http.StatusServiceUnavailable || strings.Contains(res.body, guardrailDetectionUnavailableCode) {
					t.Errorf("客户端断开不应走 fail-closed 503: http=%d body=%q", res.httpCode, res.body)
				}
				if containsString(db.eventNames(), agentGuardPolicyLoadFailureReason) {
					t.Errorf("断开不应写 %s 事件: %v", agentGuardPolicyLoadFailureReason, db.eventNames())
				}
			})
		}
	}
}
