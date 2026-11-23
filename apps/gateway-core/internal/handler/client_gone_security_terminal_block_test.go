package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

// 终态快照里「工具调用 A 被破坏性工具闸门拦截 + 工具调用 B 的参数扫描期间客户端断开」。
//
// 闸门拦截只把 OutputAction 设成 block（不返回 error）；随后 B 的参数扫描因客户端断开返回哨兵。
// checkNativeResponsesTerminal 看到 OutputAction=block 就把错误包成 errLiveStreamOutputBlocked，
// 原先用 %v 切断了错误链，调用方认不出断开，于是对已断开的客户端记了一次 security_blocked/403。
// 断开时必须记 client_canceled，且不能因为 audit 里已有 block 动作就写 security_blocked 事件。

// blockableToolPolicy 起一个控制面：破坏性工具策略 mode=light / action=block，shell_command 的 rm -rf 会被闸门拦截。
func blockableToolPolicy(t *testing.T) (*ToolRiskClient, *atomic.Int32) {
	t.Helper()
	var confirmations atomic.Int32
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"data":{"id":"policy-destructive","name":"destructive","policy_version":"v1","mode":"light","default_action":"allow","fail_policy":"fail_closed","confirm_channel_enabled":true,"rules":[],"exceptions":[],"config_source":"tenant_policy","destructive":{"mode":"light","action":"block","scope_type":"tenant","scope_ref":""}}}`)
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			w.WriteHeader(http.StatusCreated)
		case "/admin/v1/internal/agentguard/confirmations":
			confirmations.Add(1)
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(controlPlane.Close)
	client := NewToolRiskClient(controlPlane.URL, "internal-secret")
	setToolGuardTestPosture(t, client, false, false)
	return client, &confirmations
}

// toolArgGoneSecurity 在第二个工具调用的参数扫描时让客户端断开：参数内容里带 gone-marker 的调用才触发。
func toolArgGoneSecurity(entered chan struct{}, wrap bool) *goneSecurity {
	sec := &goneSecurity{}
	sec.output = blockUntilClientGone(entered, wrap)
	// 只在第二个工具调用的参数扫描（内容恰好是它的 arguments）时断开；第一次的整段快照文本扫描与被闸门拦截的 A 都放行。
	sec.outputExact = `{"path":"gone-marker.md"}`
	return sec
}

func terminalSnapshotWithBlockedCall() []byte {
	return []byte(`{"type":"response.completed","response":{"id":"resp-gate","object":"response","status":"completed","output":[` +
		`{"id":"fc_1","type":"function_call","call_id":"call-delete","name":"shell_command","arguments":"{\"command\":\"rm -rf /srv/sandbox-target\"}","status":"completed"},` +
		`{"id":"fc_2","type":"function_call","call_id":"call-read","name":"read_file","arguments":"{\"path\":\"gone-marker.md\"}","status":"completed"}]}}`)
}

func TestCheckNativeResponsesTerminalClientGoneAfterBlockedToolCall(t *testing.T) {
	for _, wrap := range []bool{false, true} {
		name := "plain"
		if wrap {
			name = "wrapped"
		}
		t.Run(name, func(t *testing.T) {
			client, confirmations := blockableToolPolicy(t)
			entered := make(chan struct{})
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), detachProbeKey{}, detachProbeMarker))
			defer cancel()
			go func() { <-entered; cancel() }()

			audit := &MockAuditWriter{}
			h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, securityClient: toolArgGoneSecurity(entered, wrap), auditWriter: audit}
			envelope := &modelrouter.RequestEnvelope{RequestID: "req-terminal-gone", TenantID: "tenant-client-gone", UserID: "user-1", SessionID: "session-1"}

			_, err := checkNativeResponsesTerminal(ctx, h, envelope, terminalSnapshotWithBlockedCall(), nil)
			if err == nil {
				t.Fatal("expected an error: the second tool call's argument scan was interrupted by the client leaving")
			}
			if !clientGoneDuring(ctx, err) {
				t.Errorf("断开应保留可识别的哨兵错误链, got %v", err)
			}
			if errors.Is(err, errLiveStreamOutputBlocked) {
				t.Errorf("客户端断开不应被包成 errLiveStreamOutputBlocked（调用方会据此记 security_blocked/403）: %v", err)
			}
			if hasSecurityEvent(audit, "security_blocked") || hasSecurityEvent(audit, "security_output_check_failed") {
				t.Errorf("断开不应写拦截/检测失败事件: %#v", audit.SecurityEventWrites)
			}
			if confirmations.Load() != 0 {
				t.Errorf("断开不应创建确认单: %d", confirmations.Load())
			}
		})
	}
}

// 对照组：不断开（B 的参数扫描正常），闸门拦截 A 照常得到 errLiveStreamOutputBlocked，行为不变。
func TestCheckNativeResponsesTerminalBlockedToolCallStillBlocksWhenClientStays(t *testing.T) {
	client, _ := blockableToolPolicy(t)
	h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, securityClient: &goneSecurity{}, auditWriter: &MockAuditWriter{}}
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-terminal-block", TenantID: "tenant-client-gone", UserID: "user-1", SessionID: "session-1"}
	_, err := checkNativeResponsesTerminal(context.Background(), h, envelope, terminalSnapshotWithBlockedCall(), nil)
	if !errors.Is(err, errLiveStreamOutputBlocked) {
		t.Fatalf("闸门拦截应仍得到 errLiveStreamOutputBlocked, got %v", err)
	}
}

// 端到端：responses 原生实时流，终态快照扫描时断开，已有 block 动作的 audit 不能把收尾变成 security_blocked。
func TestLiveResponsesTerminalClientGoneAfterBlockedToolCall(t *testing.T) {
	for _, cfg := range []goneConfig{goneConfigs[0], goneConfigs[1]} {
		t.Run(cfg.name, func(t *testing.T) {
			client, _ := blockableToolPolicy(t)
			entered := make(chan struct{})
			probe := &ctxProbe{}
			db := &goneDB{probe: probe, t: t}
			ctx, cancel := context.WithCancel(context.WithValue(context.Background(), detachProbeKey{}, detachProbeMarker))
			defer cancel()
			go func() { <-entered; cancel() }()

			sec := toolArgGoneSecurity(entered, false)
			h := &ResponsesHandler{
				cfg:            &config.Config{UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"},
				toolRiskClient: client, securityClient: sec, auditWriter: &RealAuditWriter{db: db}, relayMetrics: relay.NewMetrics(),
			}
			events := []relay.StreamEvent{
				{Type: relay.EventTextDelta, Index: 0, Delta: "hello",
					Raw: []byte(`{"type":"response.output_text.delta","delta":"hello"}`)},
				{Type: relay.EventMessageEnd, Index: 0, FinishReason: "tool_calls", Raw: terminalSnapshotWithBlockedCall()},
			}
			caller := &liveRelayCaller{reader: &liveRelayReader{events: events}}
			w := httptest.NewRecorder()
			attempted, err := h.tryLiveNativeResponsesStream(ctx, w, liveGoneEnvelope(), caller, []byte("{}"), time.Now(), "", &relay.CommitTracker{}, nil)
			if !attempted {
				t.Fatalf("实时流没有被尝试: err=%v", err)
			}
			fin := db.finalizes()
			if len(fin) == 0 {
				t.Fatalf("request_logs 没有收尾写入 body=%q", w.Body.String())
			}
			last := fin[len(fin)-1]
			if last.status != "client_canceled" || last.code != http.StatusRequestTimeout {
				t.Errorf("收尾=%s/%d, want client_canceled/408 (events=%v)", last.status, last.code, db.eventNames())
			}
			for _, name := range db.eventNames() {
				if clientGoneForbiddenEvents[name] {
					t.Errorf("客户端断开不应写事件 %q (全部事件=%v)", name, db.eventNames())
				}
			}
			if strings.Contains(w.Body.String(), "security_blocked") {
				t.Errorf("客户端断开后不应写入拦截帧: %q", w.Body.String())
			}
		})
	}
}
