package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// skillAdmissionFailureServer 模拟控制面故障：准入查询等一律 503。policyJSON 非空时
// AgentGuard 策略照常下发（用来带上 2.9.22 防护项配置），否则策略也拉不到。
func skillAdmissionFailureServer(t *testing.T, policyJSON string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if policyJSON != "" && r.URL.Path == "/admin/v1/internal/agentguard/effective-policy" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"data":` + policyJSON + `}`))
			return
		}
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)
	return server
}

// 2.9.22：准入服务不可用是防护项 skill.admission_unavailable 的命中。批次 2B 起不再读
// SKILL_ADMISSION_FAIL_MODE：原先 open 时放行（不记命中），改为与 closed 一样按防护项处置。
func TestSkillAdmissionFailureModesAndAuditLock(t *testing.T) {
	const blockingPolicy = `{"id":"p","mode":"strict","default_action":"audit","rules":[],"exceptions":[],"protections":{"skill.admission_unavailable":{"action":"block","params":{}}}}`
	for _, tc := range []struct {
		name, failMode string
		auditOnly      bool
		policy         string
		want           agentguard.DecisionAction
	}{
		{"default closed", "", false, blockingPolicy, agentguard.DecisionBlock},
		{"closed", "closed", false, blockingPolicy, agentguard.DecisionBlock},
		{"open is ignored", "open", false, blockingPolicy, agentguard.DecisionBlock},
		{"invalid closes", "invalid", false, blockingPolicy, agentguard.DecisionBlock},
		{"audit lock", "closed", true, blockingPolicy, agentguard.DecisionAudit},
		{"closed without policy follows default protection", "closed", false, "", agentguard.DecisionAudit},
		{"invalid without policy follows default protection", "invalid", false, "", agentguard.DecisionAudit},
		{"open without policy follows default protection", "open", false, "", agentguard.DecisionAudit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SKILL_ADMISSION_FAIL_MODE", tc.failMode)
			// 2.9.22（D7）：部署变量不再压过控制台，“只审计”改由控制台显式 record 表达
			// （原用例用 SECURITY_AUDIT_ONLY=true 叠加托管 protect）。
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			server := skillAdmissionFailureServer(t, tc.policy)
			audit := &MockAuditWriter{}
			client := NewToolRiskClient(server.URL, "internal")
			client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
				Revision: strings.Repeat("0", 32), SecurityAuditOnly: tc.auditOnly, SecurityExecutionModeManaged: true,
			})
			h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, auditWriter: audit}
			call := ToolCall{ID: "call", Type: "function", Function: ToolCallFunc{
				Name: "use_skill", Arguments: `{"skill":"pdf","version":"1","bundle_hash":"` + strings.Repeat("a", 64) + `"}`,
			}}
			decision, _, err := h.analyzeAgentGuardToolCall(context.Background(), &modelrouter.RequestEnvelope{TenantID: "tenant", RequestID: "request"}, call, nil)
			if err == nil || decision.EffectiveDecision != tc.want {
				t.Fatalf("failure decision=%+v err=%v want=%s", decision, err, tc.want)
			}
			if !hasSecurityEvent(audit, "skill_admission_coverage_gap") {
				t.Fatalf("admission failure must record a coverage gap: %+v", audit.SecurityEventWrites)
			}
		})
	}
}

// 2.9.22：准入不可用不影响 Skill 参数里的敏感目标分析；元数据是防护项，配成阻断时照拦，
// 策略拉不到时按注册表默认告警放行。批次 2B 起准入不可用一律记命中（不再有 fail-open 放行），
// 默认配置下两条告警放行的命中并存，摘要取先出现的一条，原断言“摘要是元数据”改为“命中里有元数据”。
func TestSkillAdmissionFailOpenPreservesIndependentToolProtection(t *testing.T) {
	t.Setenv("SKILL_ADMISSION_FAIL_MODE", "open")
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	for _, tc := range []struct {
		name, policy string
		want         agentguard.DecisionAction
	}{
		{"configured", `{"id":"p","mode":"strict","default_action":"audit","rules":[],"exceptions":[],"protections":{"agent.cloud_metadata":{"action":"block","params":{}}}}`, agentguard.DecisionBlock},
		{"policy unavailable", "", agentguard.DecisionAudit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := skillAdmissionFailureServer(t, tc.policy)
			client := NewToolRiskClient(server.URL, "internal")
			client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
				Revision: strings.Repeat("0", 32), SecurityAuditOnly: false, SecurityExecutionModeManaged: true,
			})
			h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, auditWriter: &MockAuditWriter{}}
			call := ToolCall{ID: "call", Type: "function", Function: ToolCallFunc{
				Name: "use_skill", Arguments: `{"skill":"pdf","version":"1","bundle_hash":"` + strings.Repeat("a", 64) + `","input":{"url":"http://169.254.169.254/latest/meta-data/"}}`,
			}}
			decision, _, err := h.analyzeAgentGuardToolCall(context.Background(), &modelrouter.RequestEnvelope{TenantID: "tenant", RequestID: "request"}, call, nil)
			if _, metadata := agentguard.ProtectionHitAction(decision, "blocked_cloud_metadata"); err == nil || decision.EffectiveDecision != tc.want || !metadata {
				t.Fatalf("fail-open admission must preserve metadata protection analysis: %+v err=%v", decision, err)
			}
			if tc.want == agentguard.DecisionBlock && (decision.Reason != "blocked_cloud_metadata" || decision.ProtectionItem != "agent.cloud_metadata") {
				t.Fatalf("configured block must name the metadata protection: %+v", decision)
			}
		})
	}
}
