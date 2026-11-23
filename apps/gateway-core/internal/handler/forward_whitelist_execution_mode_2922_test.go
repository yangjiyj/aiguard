package handler

import (
	"context"
	"strings"
	"testing"
	"time"
)

// 2.9.22（D7）：部署变量 SECURITY_AUDIT_ONLY=true 只在控制台没有显式执行模式时作初值。
// 正向代理白名单判定的执行模式与其他出口同源（运行配置快照），不再把部署变量当硬锁。
func TestForwardWhitelistDeploymentAuditOnlyIsOnlyInitialValue(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "true")
	for _, tc := range []struct {
		name            string
		managed, record bool
		wantEnforce     bool
	}{
		{"显式防护压过部署变量", true, false, true},
		{"显式记录", true, true, false},
		{"没有显式模式时部署变量作初值", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := NewToolRiskClient("http://127.0.0.1:1", "internal")
			client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
				Revision: strings.Repeat("0", 32), SecurityAuditOnly: tc.record, SecurityExecutionModeManaged: tc.managed,
			})
			reverse := &ReverseProxyHandler{}
			reverse.SetRuntimeConfigClient(client, true)
			h := &ForwardProxyHandler{lastReload: time.Now(), forwardProxyMode: "deny_unlisted", reverseProxy: reverse}
			outcome, reason := h.whitelistOutcome(context.Background(), "unlisted.example", 443)
			if outcome.Enforce != tc.wantEnforce {
				t.Fatalf("outcome=%+v reason=%s want enforce=%v", outcome, reason, tc.wantEnforce)
			}
		})
	}
}
