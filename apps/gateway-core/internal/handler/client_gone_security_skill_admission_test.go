package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
)

// skill 准入查询（ResolveSkillAdmission）用请求 ctx 发 HTTP；客户端在此期间断开，请求随 ctx 取消失败。
// 原先 resolveSkillAdmissionForAnalysis 会先写 skill_admission_coverage_gap 事件再返回错误，
// 客户端走了却留下一条假的覆盖缺口。断开时不写事件、不打 coverage_gap 日志，错误带上哨兵；
// 返回的 status 沿用原有计算（fail-open 与只审计模式下的 analysis-only 放行不变）。

const skillAdmissionGapEvent = "skill_admission_coverage_gap"

var skillAdmissionTestArgs = `{"skill":"pdf","version":"1","bundle_hash":"` + strings.Repeat("a", 64) + `"}`

// skillAdmissionControlPlane：策略接口正常返回，skill 准入接口阻塞到请求 ctx 取消（模拟控制面慢、客户端先走）；
// failStatus 非 0 时改为立即返回该 HTTP 状态（对照组：查询返回非取消错误）。
type skillAdmissionControlPlane struct {
	hits atomic.Int32
	url  string
}

func newSkillAdmissionControlPlane(t *testing.T, entered chan struct{}, failStatus int) *skillAdmissionControlPlane {
	t.Helper()
	cp := &skillAdmissionControlPlane{}
	var once atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":{"id":"policy-1","name":"p","policy_version":"v1","mode":"strict","default_action":"audit","fail_policy":"closed","confirm_channel_enabled":true,"rules":[],"exceptions":[]}}`))
		case skillAdmissionPath:
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

func skillAdmissionTestIdentity(t *testing.T) agentguard.SkillIdentity {
	t.Helper()
	var args map[string]interface{}
	if err := json.Unmarshal([]byte(skillAdmissionTestArgs), &args); err != nil {
		t.Fatal(err)
	}
	identity := agentguard.ExtractSkillIdentity(args)
	if !identity.Complete() {
		t.Fatalf("测试用 skill 身份应完整: %+v", identity)
	}
	return identity
}

func skillAdmissionToolCall() ToolCall {
	return ToolCall{ID: "call_skill", Type: "function", Function: ToolCallFunc{Name: "use_skill", Arguments: skillAdmissionTestArgs}}
}

// 直接作用于 resolveSkillAdmissionForAnalysis：断开 -> 哨兵、无事件、status 与「同配置下查询失败但客户端还在」一致。
func TestResolveSkillAdmissionForAnalysisClientGone(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     securityexit.Mode
		failMode string
	}{
		{"protect_closed", securityexit.Protect, ""},
		{"protect_open", securityexit.Protect, "open"},
		{"record_closed", securityexit.Record, ""},
		{"record_open", securityexit.Record, "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SKILL_ADMISSION_FAIL_MODE", tc.failMode)
			identity := skillAdmissionTestIdentity(t)
			envelope := &modelrouter.RequestEnvelope{RequestID: "req-skill-gone", TenantID: "tenant-skill-gone"}

			// 对照：查询返回 503，客户端还在 -> 照常写覆盖缺口事件，错误不是哨兵。
			controlCP := newSkillAdmissionControlPlane(t, nil, http.StatusServiceUnavailable)
			controlAudit := &MockAuditWriter{}
			_, controlStatus, controlErr := resolveSkillAdmissionForAnalysis(context.Background(), NewToolRiskClient(controlCP.url, "internal-secret"), controlAudit, envelope, identity, tc.mode)
			if controlErr == nil {
				t.Fatal("对照组查询失败应返回错误")
			}
			if errors.Is(controlErr, errClientGoneDuringSecurity) {
				t.Errorf("对照组客户端还在，不应是哨兵: %v", controlErr)
			}
			if !hasSecurityEvent(controlAudit, skillAdmissionGapEvent) {
				t.Errorf("对照组应写 %s 事件: %+v", skillAdmissionGapEvent, controlAudit.SecurityEventWrites)
			}

			// 断开：查询阻塞到请求 ctx 取消。
			entered := make(chan struct{})
			cp := newSkillAdmissionControlPlane(t, entered, 0)
			audit := &MockAuditWriter{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() { <-entered; cancel() }()
			_, status, err := resolveSkillAdmissionForAnalysis(ctx, NewToolRiskClient(cp.url, "internal-secret"), audit, envelope, identity, tc.mode)

			if err == nil {
				t.Fatal("准入查询被取消应返回错误")
			}
			if !errors.Is(err, errClientGoneDuringSecurity) {
				t.Errorf("客户端断开应带哨兵 errClientGoneDuringSecurity: %v", err)
			}
			if !errors.Is(err, context.Canceled) {
				t.Errorf("哨兵必须保留 context.Canceled，调用方的 client_canceled 分支依赖它: %v", err)
			}
			if hasSecurityEvent(audit, skillAdmissionGapEvent) {
				t.Errorf("客户端断开不应写 %s 事件: %+v", skillAdmissionGapEvent, audit.SecurityEventWrites)
			}
			if status != controlStatus {
				t.Errorf("断开不应改变返回的 status（fail-open/只审计下的 analysis-only 放行语义）: gone=%q control=%q", status, controlStatus)
			}
		})
	}
}

// 对照：请求 ctx 因自身超时结束（DeadlineExceeded，不是 Canceled）-> 仍按查询失败处理，写覆盖缺口。
func TestResolveSkillAdmissionForAnalysisDeadlineStillWritesGap(t *testing.T) {
	cp := newSkillAdmissionControlPlane(t, nil, 0)
	audit := &MockAuditWriter{}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, _, err := resolveSkillAdmissionForAnalysis(ctx, NewToolRiskClient(cp.url, "internal-secret"), audit,
		&modelrouter.RequestEnvelope{RequestID: "req-skill-deadline", TenantID: "tenant-skill-gone"}, skillAdmissionTestIdentity(t), securityexit.Protect)

	if err == nil {
		t.Fatal("准入查询超时应返回错误")
	}
	if errors.Is(err, errClientGoneDuringSecurity) || clientGoneDuring(ctx, err) {
		t.Errorf("DeadlineExceeded 不是客户端断开: %v", err)
	}
	if !hasSecurityEvent(audit, skillAdmissionGapEvent) {
		t.Errorf("超时应照常写 %s 事件: %+v", skillAdmissionGapEvent, audit.SecurityEventWrites)
	}
}

func skillAdmissionHandlerForChat(t *testing.T, client *ToolRiskClient, db *goneDB) *ChatCompletionsHandler {
	t.Helper()
	return NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, &RealAuditWriter{db: db},
		fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: destructiveChatResponse(t, "", skillAdmissionToolCall())}}, client, nil)
}

// 端到端（chat 非流式）：上游返回 skill 工具调用，准入查询期间客户端断开 -> client_canceled/408，
// 无覆盖缺口事件，fail-closed 下也不是 503。对照组：查询 503、客户端还在 -> 原行为，仍写覆盖缺口。
func TestChatNonStreamSkillAdmissionClientGone(t *testing.T) {
	for _, stage := range []struct {
		name   string
		status int // 0 = 阻塞到请求 ctx 取消（客户端断开）；非 0 = 对照组
	}{{"client_gone", 0}, {"control_plane_503", http.StatusServiceUnavailable}} {
		for _, cfg := range goneConfigs {
			t.Run(stage.name+"/"+cfg.name, func(t *testing.T) {
				entered := make(chan struct{})
				cp := newSkillAdmissionControlPlane(t, entered, stage.status)
				client := NewToolRiskClient(cp.url, "internal-secret")
				setToolGuardTestPosture(t, client, cfg.auditOnly, cfg.failClosed)

				ctx, cancel := context.WithCancel(context.WithValue(context.Background(), detachProbeKey{}, detachProbeMarker))
				defer cancel()
				if stage.status == 0 {
					go func() { <-entered; cancel() }()
				}
				probe := &ctxProbe{}
				db := &goneDB{probe: probe, t: t}
				h := skillAdmissionHandlerForChat(t, client, db)

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
					if containsString(names, skillAdmissionGapEvent) {
						t.Errorf("断开不应写 %s 事件: %v", skillAdmissionGapEvent, names)
					}
					probe.require(t, "db.finalize")
					return
				}
				if last.status == "client_canceled" {
					t.Errorf("对照组客户端还在，不应收尾为 client_canceled (events=%v)", names)
				}
				if !containsString(names, skillAdmissionGapEvent) {
					t.Errorf("对照组应写 %s 事件: %v", skillAdmissionGapEvent, names)
				}
			})
		}
	}
}

// 其余出口：同一个准入查询断开，经 messages 原生、responses 原生、responses 兼容、chat 先攒后发都应落到 client_canceled。
func TestSkillAdmissionClientGoneAcrossProtocols(t *testing.T) {
	skillInput := json.RawMessage(skillAdmissionTestArgs)
	for _, proto := range []string{"messages_native", "responses_native", "responses_compat", "chat_buffered_stream"} {
		for _, cfg := range []goneConfig{goneConfigs[0], goneConfigs[1]} {
			t.Run(proto+"/"+cfg.name, func(t *testing.T) {
				entered := make(chan struct{})
				cp := newSkillAdmissionControlPlane(t, entered, 0)
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
					toolUse, err := json.Marshal(map[string]any{
						"id": "msg_tool", "type": "message", "role": "assistant", "model": "claude-opus-5", "stop_reason": "tool_use", "stop_sequence": nil,
						"content": []any{map[string]any{"type": "tool_use", "id": "toolu_1", "name": "use_skill", "input": skillInput}},
						"usage":   map[string]any{"input_tokens": 10, "output_tokens": 5},
					})
					if err != nil {
						t.Fatal(err)
					}
					resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{
						ID: "model-native", ModelName: "claude-opus-5", ProviderID: "provider-native",
						ProviderType: "openai", ProviderBaseURL: "https://boflow.example", UpstreamModelID: "kiro-opus", Status: "active",
					}}
					h := NewMessagesHandler(&config.Config{}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, writer,
						fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: toolUse}}, client, nil)
					res = serveGone(h.Handler(), goneMessagesRequest(ctx, false))
				case "responses_native":
					native, err := json.Marshal(map[string]any{
						"id": "resp_n", "object": "response", "status": "completed", "model": "gpt-5.6",
						"output": []any{map[string]any{"id": "fc_1", "type": "function_call", "call_id": "call_1", "name": "use_skill", "arguments": skillAdmissionTestArgs, "status": "completed"}},
						"usage":  map[string]any{"input_tokens": 1, "output_tokens": 1, "total_tokens": 2},
					})
					if err != nil {
						t.Fatal(err)
					}
					h := newGoneResponsesHandler(&goneEnv{sec: &goneSecurity{}, writer: writer, client: client, metrics: nil}, &config.Config{}, true,
						&MockProviderCaller{CallResponse: native})
					res = serveGone(h.Handler(), goneResponsesRequest(ctx, responsesKeepalivePlainBody))
				case "responses_compat":
					h := newGoneResponsesHandler(&goneEnv{sec: &goneSecurity{}, writer: writer, client: client, metrics: nil}, &config.Config{}, false,
						&MockProviderCaller{CallResponse: destructiveChatResponse(t, "", skillAdmissionToolCall())})
					res = serveGone(h.Handler(), goneResponsesRequest(ctx, compatKeepalivePlainBody))
				case "chat_buffered_stream":
					h := NewChatCompletionsHandler(&config.Config{UpstreamStreaming: false}, &MockModelResolver{}, &MockRateLimitChecker{}, &MockSecurityChecker{}, writer,
						fixedAdapterFactory{caller: &MockProviderCaller{CallResponse: destructiveChatResponse(t, "", skillAdmissionToolCall())}}, client, nil)
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
				if containsString(db.eventNames(), skillAdmissionGapEvent) {
					t.Errorf("断开不应写 %s 事件: %v", skillAdmissionGapEvent, db.eventNames())
				}
			})
		}
	}
}
