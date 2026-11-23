package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

// failClosedHistoryClient 在 failClosedClient 的基础上打开历史检测：默认检测范围只有最新一条用户输入，
// 条目数不超过 1 不会走批量接口；多条消息的批量路径需要把历史消息也纳入检测范围。
func failClosedHistoryClient(t *testing.T, auditOnly, failClosed bool) *ToolRiskClient {
	t.Helper()
	t.Setenv("SECURITY_AUDIT_ONLY", "")
	policy := inspectionscope.Default()
	policy.InspectBuiltinContext = true
	policy.InspectHistory = true
	client := NewToolRiskClient("http://control-plane.invalid", gatewaySemanticInternalTestSecret, gatewaySemanticTestKey)
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision: "00000000000000000000000000000000", Enabled: true, InputEnabled: true, AgentEnabled: true,
		SecurityAuditOnly: auditOnly, SecurityExecutionModeManaged: true, GuardrailFailClosedEnabled: failClosed,
		InspectionPolicy: &policy,
	})
	return client
}

// goneBatchSecurity 在 goneSecurity 之上实现 detailedInputBatchChecker，模拟生产里的
// RealSecurityChecker：多条消息时输入侧走批量接口，批量调用失败后把同一个错误挂到每个条目上
// （见 RealSecurityChecker.CheckInputBatchDetailed）。客户端断开时 HTTP 客户端返回的就是被包装的
// context.Canceled，这里按 "security batch request canceled: %w" 的真实包装方式复现。
type goneBatchSecurity struct {
	*goneSecurity
	batchCalls atomic.Int32
}

func (s *goneBatchSecurity) CheckInputBatchDetailed(ctx context.Context, _ *modelrouter.RequestEnvelope, items []InputCheckBatchItem) ([]InputCheckBatchResult, error) {
	s.batchCalls.Add(1)
	results := make([]InputCheckBatchResult, len(items))
	if hook := s.hook("input"); hook != nil {
		if err := hook(ctx); err != nil {
			for i := range results {
				results[i].Err = fmt.Errorf("security batch request canceled: %w", err)
			}
			return results, nil
		}
	}
	for i := range results {
		results[i].Outcome = &InputCheckOutcome{Action: "allow"}
	}
	return results, nil
}

// 多条消息的 chat 请求走批量输入检测：客户端断开必须同样记 client_canceled，
// 对照组（超时、引擎不可用、引擎内部自己 cancel）保持原行为。
func TestChatInputBatchScanClientGone(t *testing.T) {
	runGoneMatrix(t, "input", goneConfigs, func(t *testing.T, e *goneEnv, cfg goneConfig) {
		batch := &goneBatchSecurity{goneSecurity: e.sec}
		h := NewChatCompletionsHandler(&config.Config{}, &MockModelResolver{}, &MockRateLimitChecker{}, batch, e.writer,
			fixedAdapterFactory{caller: &MockProviderCaller{}}, failClosedHistoryClient(t, cfg.auditOnly, cfg.failClosed), nil)
		h.SetRelayMetrics(e.metrics)
		body, _ := json.Marshal(ChatCompletionRequest{
			Model: "gpt-4",
			// 历史检测打开后，两条用户消息 + 一条助手历史都会送检，条目数 > 1 走批量接口。
			Messages: []Message{
				{Role: "user", Content: jsonQuote("first question")},
				{Role: "assistant", Content: jsonQuote("first answer")},
				{Role: "user", Content: jsonQuote("second question")},
			},
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(setAuthInfo(e.ctx, "tenant-123", "project-123", "user-123", "key-123", ""))
		res := serveGone(h.Handler(), req)
		if batch.batchCalls.Load() == 0 {
			t.Fatal("测试夹具没有走到批量输入检测，用例没有意义")
		}
		e.check(t, res, controlFor(cfg, "security_check_failed"))
	})
}
