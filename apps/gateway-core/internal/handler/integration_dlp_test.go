package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
	"net/http/httptest"
	"testing"
	"time"
)

// 全局观察留痕管全部检测类拦截（2.9.22 D6）：集成凭据的 DLP 强制档也只记录、不拦，
// 无论引擎是否标了 integration_dlp_block。
func TestGlobalRecordModeRecordsIntegrationDLPBlock(t *testing.T) {
	for _, gate := range []string{"record_only", "allow_block"} {
		for _, verified := range []bool{false, true} {
			for _, agent := range []string{"", "agent1"} {
				t.Run(gate+agent+map[bool]string{true: "核验", false: "未核验"}[verified], func(t *testing.T) {
					t.Setenv("INTEGRATION_KEY_ENFORCEMENT", gate)
					ctx := context.WithValue(context.Background(), auth.AgentInstanceIDKey, agent)
					ctx = context.WithValue(ctx, auth.KeyDLPEnforcementKey, "block")
					finding := SecurityFinding{Type: "pii", Category: "phone_cn", RuleID: "policy1", PolicyCode: "p.dlp", Action: "block", Severity: "high", Triage: map[string]any{"integration_dlp_block": verified}}
					checker := &MockSecurityChecker{InputAction: "block", InputFindings: []SecurityFinding{finding}}
					writer := &MockAuditWriter{}
					h := &EmbeddingsHandler{cfg: &config.Config{SecurityAuditOnly: true}, securityClient: checker, auditWriter: writer}
					if err := h.applyInputSecurity(ctx, &modelrouter.RequestEnvelope{RequestID: "测试请求"}, &EmbeddingsRequest{Input: "测试内容"}); err != nil {
						t.Fatalf("向量输入只记录，不拦：%v", err)
					}
					chat := &ChatCompletionsHandler{cfg: &config.Config{SecurityAuditOnly: true}, securityClient: checker, auditWriter: writer}
					if _, err := chat.applyInputSecurity(ctx, &modelrouter.RequestEnvelope{RequestID: "测试请求"}, &ChatCompletionRequest{Messages: []Message{{Role: "user", Content: []byte(`"测试内容"`)}}}); err != nil {
						t.Fatalf("聊天输入只记录，不拦：%v", err)
					}
					checker.OutputAction, checker.OutputFindings = "block", []SecurityFinding{finding}
					_, result, err := chat.applyOutputSecurity(ctx, &modelrouter.RequestEnvelope{RequestID: "测试请求"}, nil, []byte(`{"choices":[{"message":{"content":"测试内容"}}]}`))
					if err != nil || result == nil || result.OutputAction != "audit" {
						t.Fatalf("输出只记录，不拦：err=%v result=%+v", err, result)
					}
					images := &ImagesHandler{cfg: &config.Config{SecurityAuditOnly: true}, securityClient: checker, auditWriter: writer}
					if _, err := images.applyInputSecurity(ctx, &modelrouter.RequestEnvelope{RequestID: "测试请求"}, &ImagesRequest{Prompt: "测试内容"}, nil, nil); err != nil {
						t.Fatalf("图片输入只记录，不拦：%v", err)
					}
					if hasSecurityEvent(writer, "security_blocked") || !hasSecurityEvent(writer, "security_audit_only") {
						t.Fatalf("观察留痕下只留 security_audit_only：%+v", writer.SecurityEventWrites)
					}
				})
			}
		}
	}
}

func TestIntegrationDLPBlockUsesInspectedBufferedOutput(t *testing.T) {
	t.Setenv("INTEGRATION_KEY_ENFORCEMENT", "allow_block")
	ctx := context.WithValue(context.Background(), auth.AgentInstanceIDKey, "agent1")
	ctx = context.WithValue(ctx, auth.KeyDLPEnforcementKey, "block")
	for _, protocol := range []string{"chat", "messages", "responses"} {
		t.Run(protocol, func(t *testing.T) {
			cfg := &config.Config{UpstreamStreaming: true, SecurityAuditOnly: true, OutputSecurityMode: "stream_audit"}
			caller := &liveRelayCaller{reader: &liveRelayReader{}}
			envelope := &modelrouter.RequestEnvelope{RequestID: "测试请求"}
			w := httptest.NewRecorder()
			tracker := &relay.CommitTracker{}
			var attempted bool
			var err error
			switch protocol {
			case "chat":
				h := NewChatCompletionsHandler(cfg, nil, nil, &MockSecurityChecker{}, &MockAuditWriter{}, nil, nil, nil)
				attempted, err = h.tryLiveChatStream(ctx, w, envelope, caller, []byte(`{}`), time.Now(), "", tracker)
			case "messages":
				h := NewMessagesHandler(cfg, nil, nil, &MockSecurityChecker{}, &MockAuditWriter{}, nil, nil, nil)
				attempted, err = h.tryLiveNativeMessagesStream(ctx, w, envelope, caller, []byte(`{}`), time.Now(), "", tracker, nil)
			case "responses":
				h := NewResponsesHandler(cfg, nil, nil, &MockSecurityChecker{}, &MockAuditWriter{}, nil, nil, nil)
				attempted, err = h.tryLiveNativeResponsesStream(ctx, w, envelope, caller, []byte(`{}`), time.Now(), "", tracker, nil)
			}
			if attempted || err != nil || tracker.State() != relay.CommitNotStarted || w.Body.Len() != 0 {
				t.Fatalf("专用拦截凭据提前进入直通流：attempted=%v state=%s err=%v", attempted, tracker.State(), err)
			}
		})
	}
}
