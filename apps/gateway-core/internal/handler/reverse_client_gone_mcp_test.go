package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// MCP 工具结果守卫：客户端在工具返回检测期间断开。
// 数据面字节行为保持不变（宁可替换也不把未扫描的工具结果原样放出），只改标签：
//   - 断开：不追加 mcp_tool_result_unverified 证据；Enforce 时仍替换为 -32000，但不置
//     ToolResultEnforced / ToolResultCapacityRejected；非 Enforce 原样放行；
//   - 对照组（引擎不可用 / 检测超时 / 引擎内部 cancel / 总超时到期）：证据与标志位照旧。

type rcgMCPScenario struct {
	name string
	gone bool
	// ctxTimeout 非零：守卫 ctx 带这个超时（模拟 30 分钟总超时到期），检测阻塞到 ctx 到期，
	// 返回 DeadlineExceeded，不是客户端断开。
	ctxTimeout time.Duration
	hook       func(entered chan struct{}) func(context.Context) error
}

func rcgMCPBlock(wrap bool) func(chan struct{}) func(context.Context) error {
	return func(entered chan struct{}) func(context.Context) error {
		var once sync.Once
		return func(ctx context.Context) error {
			once.Do(func() { close(entered) })
			select {
			case <-ctx.Done():
				if wrap {
					return fmt.Errorf("failed to call security engine: %w", ctx.Err())
				}
				return ctx.Err()
			case <-time.After(10 * time.Second):
				return errors.New("test timeout: ctx was never done")
			}
		}
	}
}

func rcgMCPConstant(err error) func(chan struct{}) func(context.Context) error {
	return func(chan struct{}) func(context.Context) error {
		return func(context.Context) error { return err }
	}
}

var rcgMCPScenarios = []rcgMCPScenario{
	{name: "client_gone", gone: true, hook: rcgMCPBlock(false)},
	{name: "client_gone_wrapped", gone: true, hook: rcgMCPBlock(true)},
	{name: "engine_down", hook: rcgMCPConstant(errors.New("engine down"))},
	{name: "engine_deadline", hook: rcgMCPConstant(context.DeadlineExceeded)},
	// 引擎内部自己 cancel：返回 Canceled，但请求 ctx 仍然存活，仍是检测失败。
	{name: "engine_internal_cancel", hook: rcgMCPConstant(context.Canceled)},
	{name: "ctx_total_timeout", ctxTimeout: 120 * time.Millisecond, hook: rcgMCPBlock(false)},
}

type rcgMCPChecker struct {
	hook  func(context.Context) error
	mu    sync.Mutex
	calls int
}

func (c *rcgMCPChecker) CheckInput(ctx context.Context, _ *modelrouter.RequestEnvelope, _ string, _ int, _ string, _ string) (string, string, []SecurityFinding, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	if err := c.hook(ctx); err != nil {
		return "", "", nil, err
	}
	return "allow", "", nil, nil
}

// rcgMCPContext 构造守卫用的 ctx：gone 场景在检测开始后取消；ctxTimeout 场景带到期时限。
func rcgMCPContext(t *testing.T, parent context.Context, sc rcgMCPScenario, entered chan struct{}) context.Context {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	t.Cleanup(cancel)
	if sc.ctxTimeout > 0 {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, sc.ctxTimeout)
		t.Cleanup(cancelTimeout)
	}
	if sc.gone {
		go func() {
			select {
			case <-entered:
			case <-time.After(10 * time.Second):
			}
			cancel()
		}()
	}
	return ctx
}

func rcgHasEvidence(d mcpToolCallDecision, ruleID string) bool {
	for _, ev := range d.Decision.Evidence {
		if ev.RuleID == ruleID {
			return true
		}
	}
	return false
}

// 守卫层：直接调用 rewritePayload，检查字节、证据、标志位。
func TestReverseClientGoneMCPGuardMatrix(t *testing.T) {
	for _, sc := range rcgMCPScenarios {
		for _, cfg := range rcgConfigs {
			t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
				client := failClosedClient(t, cfg.auditOnly, cfg.failClosed)
				h := NewMCPProxyHandler(nil, client, false)
				entered := make(chan struct{})
				checker := &rcgMCPChecker{hook: sc.hook(entered)}
				h.SetToolResultChecker(checker)
				ctx := rcgMCPContext(t, context.Background(), sc, entered)
				decisions := []mcpToolCallDecision{{Message: mcpRPCMessage{ID: json.RawMessage("9")}, ToolName: "fetch", Qualified: "demo__fetch"}}
				guard := h.prepareMCPToolResultGuard(ctx, &modelrouter.RequestEnvelope{}, nil, decisions, cfg.auditOnly)
				if guard == nil {
					t.Fatal("守卫未构造")
				}
				out := guard.rewritePayload([]byte(ws1InjectedResult))
				d := decisions[0]
				if checker.calls != 1 {
					t.Fatalf("检测应被调用 1 次, got %d", checker.calls)
				}

				// 数据面字节：fail-closed 才替换；其余原样放行。断开与否都一样。
				replaced := string(out) != ws1InjectedResult
				if replaced != cfg.enforcing() {
					t.Fatalf("replaced=%v, want %v (out=%s)", replaced, cfg.enforcing(), out)
				}
				if replaced {
					if rpcErrorCode(t, string(out)) != -32000 || !strings.Contains(string(out), "fail-closed policy rejected it") {
						t.Errorf("应为同 id 的 -32000 fail-closed 错误: %s", out)
					}
					var resp struct {
						ID json.RawMessage `json:"id"`
					}
					if err := json.Unmarshal(out, &resp); err != nil || string(resp.ID) != "9" {
						t.Errorf("替换体应保持原 id: %s", out)
					}
					if strings.Contains(string(out), "IGNORE ALL") {
						t.Errorf("未扫描的工具结果不得原样放出: %s", out)
					}
				}

				if d.ToolResultCapacityRejected {
					t.Errorf("检测失败/断开都不是容量拒绝")
				}
				if d.ToolResultWouldBlock || len(d.ToolResultFindings) != 0 {
					t.Errorf("没有命中，不应有 would_block/findings: %+v", d)
				}
				if sc.gone {
					if rcgHasEvidence(d, "mcp_tool_result_unverified") {
						t.Errorf("断开不应追加 mcp_tool_result_unverified 证据: %+v", d.Decision.Evidence)
					}
					if d.ToolResultEnforced {
						t.Errorf("断开不应置 ToolResultEnforced")
					}
					if mcpDecisionNeedsSecurityEvent(&d, cfg.auditOnly) {
						t.Errorf("断开不应产生安全事件")
					}
					return
				}
				if !rcgHasEvidence(d, "mcp_tool_result_unverified") {
					t.Errorf("对照组应保留 mcp_tool_result_unverified 证据: %+v", d.Decision.Evidence)
				}
				if d.ToolResultEnforced != cfg.enforcing() {
					t.Errorf("对照组 ToolResultEnforced=%v, want %v", d.ToolResultEnforced, cfg.enforcing())
				}
			})
		}
	}
}

// SSE 帧（含审批重放路径用的 mcpRewriteSSEBody）：断开 + fail-closed 仍替换为 -32000，且不置标志位。
func TestReverseClientGoneMCPGuardSSE(t *testing.T) {
	body := "event: message\ndata: " + ws1InjectedResult + "\n\n"
	for _, sc := range rcgMCPScenarios {
		for _, cfg := range rcgConfigs {
			t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
				client := failClosedClient(t, cfg.auditOnly, cfg.failClosed)
				h := NewMCPProxyHandler(nil, client, false)
				entered := make(chan struct{})
				h.SetToolResultChecker(&rcgMCPChecker{hook: sc.hook(entered)})
				ctx := rcgMCPContext(t, context.Background(), sc, entered)
				decisions := []mcpToolCallDecision{{Message: mcpRPCMessage{ID: json.RawMessage("9")}, ToolName: "fetch", Qualified: "demo__fetch"}}
				guard := h.prepareMCPToolResultGuard(ctx, &modelrouter.RequestEnvelope{}, nil, decisions, cfg.auditOnly)
				out := string(mcpRewriteSSEBody([]byte(body), guard.rewritePayload))
				replaced := !strings.Contains(out, "IGNORE ALL")
				if replaced != cfg.enforcing() {
					t.Fatalf("replaced=%v, want %v (out=%q)", replaced, cfg.enforcing(), out)
				}
				d := decisions[0]
				if sc.gone && (d.ToolResultEnforced || d.ToolResultCapacityRejected || rcgHasEvidence(d, "mcp_tool_result_unverified")) {
					t.Errorf("断开不应置标志位/追加证据: %+v", d)
				}
				if !sc.gone && (!rcgHasEvidence(d, "mcp_tool_result_unverified") || d.ToolResultEnforced != cfg.enforcing()) {
					t.Errorf("对照组标志位/证据应照旧: %+v", d)
				}
			})
		}
	}
}

// HTTP 层：完整 HandlePost，请求 ctx 在检测期间被取消。字节与审批前一致，工具日志里没有 unverified 证据。
func TestReverseClientGoneMCPHandlePost(t *testing.T) {
	for _, sc := range rcgMCPScenarios {
		for _, cfg := range rcgConfigs {
			t.Run(sc.name+"/"+cfg.name, func(t *testing.T) {
				entered := make(chan struct{})
				checker := &rcgMCPChecker{hook: sc.hook(entered)}
				env := ws1ResultEnv(t, cfg.auditOnly, ws1InjectedResult, "application/json", checker)
				env.handler.toolRiskClient.runtimeCache.setSemanticConfig(semanticRuntimeConfig{Revision: gatewaySemanticRevision,
					SecurityAuditOnly: cfg.auditOnly, SecurityExecutionModeManaged: true, GuardrailFailClosedEnabled: cfg.failClosed})
				req := newMCPTestRequest(ws1ToolCallRequest)
				req = req.WithContext(rcgMCPContext(t, req.Context(), sc, entered))
				w := httptest.NewRecorder()
				env.router.ServeHTTP(w, req)

				if w.Code != http.StatusOK {
					t.Fatalf("http=%d, want 200 (body=%s)", w.Code, w.Body.String())
				}
				blocked := rpcErrorCode(t, w.Body.String()) == -32000
				if blocked != cfg.enforcing() {
					t.Fatalf("fail-closed 替换=%v, want %v (body=%s)", blocked, cfg.enforcing(), w.Body.String())
				}
				if !cfg.enforcing() && w.Body.String() != ws1InjectedResult {
					t.Errorf("非 fail-closed 应原样放行: %s", w.Body.String())
				}
				if len(env.logs()) == 0 {
					t.Fatalf("没有写工具日志，用例无意义")
				}
				if got := ws1LogsContain(env, "mcp_tool_result_unverified"); got == sc.gone {
					t.Errorf("unverified 证据 present=%v, 断开时应为 false、对照组应为 true", got)
				}
			})
		}
	}
}
