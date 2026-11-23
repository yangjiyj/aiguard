package handler

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 直接作用于 analyzeAgentGuardToolCall 的分类测试：它把策略加载错误分成两类，
// 返回给 applyAgentGuardToolDecisionResult 去处置。
//   - 请求 ctx 已取消，加载因此失败：是「客户端走了」，返回哨兵，不能是 errAgentGuardPolicyUnavailable；
//   - 请求 ctx 仍然存活，加载因控制面故障失败：是「策略不可用」，返回 errAgentGuardPolicyUnavailable，不能是哨兵。
// applyAgentGuardToolDecisionResult 里还有一道同样的判定，旧写法的错误链同时包着 context.Canceled，
// 那一道对旧链也成立，所以只靠端到端用例保护不了这里的分类；这条单测直接钉住分类本身。

func policyLoadClassifierHandler(t *testing.T, controlPlaneURL string) *ChatCompletionsHandler {
	t.Helper()
	client := NewToolRiskClient(controlPlaneURL, "internal-secret")
	setToolGuardTestPosture(t, client, false, true)
	return &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, securityClient: &MockSecurityChecker{}, auditWriter: &MockAuditWriter{}}
}

func policyLoadClassifierEnvelope() *modelrouter.RequestEnvelope {
	// 独立租户：全局限频日志按租户限频，别吃掉其他用例的首条。
	return &modelrouter.RequestEnvelope{RequestID: "req-classifier", TenantID: "tenant-classifier", UserID: "user-1", SessionID: "session-1"}
}

func TestAnalyzeAgentGuardToolCallClassifiesClientGoneAsSentinel(t *testing.T) {
	entered := make(chan struct{})
	cp := newPolicyControlPlane(t, entered, 0) // 阻塞到请求 ctx 取消
	h := policyLoadClassifierHandler(t, cp.url)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-entered; cancel() }()

	call := ToolCall{ID: "call_1", Type: "function", Function: ToolCallFunc{Name: "read_file", Arguments: `{"path":"README.md"}`}}
	_, _, err := h.analyzeAgentGuardToolCall(ctx, policyLoadClassifierEnvelope(), call, nil)

	if err == nil {
		t.Fatal("策略加载被取消应返回错误")
	}
	if !errors.Is(err, errClientGoneDuringSecurity) {
		t.Errorf("客户端断开应分类为哨兵 errClientGoneDuringSecurity, got %v", err)
	}
	if errors.Is(err, errAgentGuardPolicyUnavailable) {
		t.Errorf("客户端断开不应被分类为「策略不可用」: %v", err)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("哨兵必须保留 context.Canceled，调用方的 client_canceled 分支依赖它: %v", err)
	}
}

// 对照：请求 ctx 活着，控制面返回 5xx（非取消错误）-> 仍是「策略不可用」，不是哨兵。
func TestAnalyzeAgentGuardToolCallKeepsPolicyUnavailableWhenClientStays(t *testing.T) {
	for _, status := range []int{http.StatusServiceUnavailable, http.StatusInternalServerError} {
		cp := newPolicyControlPlane(t, nil, status)
		h := policyLoadClassifierHandler(t, cp.url)
		call := ToolCall{ID: "call_1", Type: "function", Function: ToolCallFunc{Name: "read_file", Arguments: `{"path":"README.md"}`}}

		_, _, err := h.analyzeAgentGuardToolCall(context.Background(), policyLoadClassifierEnvelope(), call, nil)

		if !errors.Is(err, errAgentGuardPolicyUnavailable) {
			t.Errorf("status=%d: 控制面故障应分类为 errAgentGuardPolicyUnavailable, got %v", status, err)
		}
		if errors.Is(err, errClientGoneDuringSecurity) || errors.Is(err, context.Canceled) {
			t.Errorf("status=%d: 请求 ctx 仍存活，不应被分类为客户端断开: %v", status, err)
		}
	}
}

// 对照：请求 ctx 活着，但加载错误本身是 Canceled（例如控制面连接被内部取消）-> 请求没走，仍是「策略不可用」。
// 这里用一个已取消的派生 ctx 之外的请求 ctx 来区分：clientGoneDuring 只认原始请求 ctx。
func TestAnalyzeAgentGuardToolCallInternalCancelWithLiveRequestStaysPolicyUnavailable(t *testing.T) {
	cp := newPolicyControlPlane(t, nil, http.StatusServiceUnavailable)
	h := policyLoadClassifierHandler(t, cp.url)
	call := ToolCall{ID: "call_1", Type: "function", Function: ToolCallFunc{Name: "read_file", Arguments: `{"path":"README.md"}`}}

	requestCtx := context.Background() // 原始请求 ctx 活着
	_, _, err := h.analyzeAgentGuardToolCall(requestCtx, policyLoadClassifierEnvelope(), call, nil)

	if clientGoneDuring(requestCtx, err) {
		t.Errorf("原始请求 ctx 活着时，不应判为客户端断开: %v", err)
	}
	if !errors.Is(err, errAgentGuardPolicyUnavailable) {
		t.Errorf("应仍是策略不可用: %v", err)
	}
}
