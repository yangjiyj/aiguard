package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// MCP 路径也经 resolveSkillAdmissionForAnalysis：准入查询期间客户端断开，不追加 skill_admission_coverage_gap 证据；
// 查询失败而客户端还在（对照组）仍追加。decision 的拦截与否沿用原有计算，这里只断言证据。

func mcpSkillAdmissionEvidenceGap(decision agentguard.Decision) bool {
	for _, evidence := range decision.Evidence {
		if evidence.RuleID == "skill_admission_coverage_gap" {
			return true
		}
	}
	return false
}

func TestMCPSkillAdmissionClientGoneAddsNoCoverageGapEvidence(t *testing.T) {
	skillArgs := map[string]interface{}{"skill": "reader", "version": "1.0.0", "bundle_hash": strings.Repeat("a", 64)}
	for _, failMode := range []string{"closed", "open"} {
		for _, auditOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/audit=%t", failMode, auditOnly), func(t *testing.T) {
				t.Setenv("SKILL_ADMISSION_FAIL_MODE", failMode)
				input := structuredToolCallInput{
					ToolName: "use_skill", ToolType: agentguard.ToolTypeSkill, Arguments: skillArgs,
					Mode: agentguard.ModeStrict,
				}
				envelope := &modelrouter.RequestEnvelope{TenantID: "tenant_test", ProjectID: "project_test", UserID: "user_test", TraceID: "trace-skill-gone"}

				// 对照：准入查询返回 503，客户端还在 -> 照常追加缺口证据。
				controlEnv := newWS1Env(t, auditOnly, blockTool("__none__"))
				controlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == skillAdmissionPath {
						http.Error(w, "boom", http.StatusServiceUnavailable)
						return
					}
					w.WriteHeader(http.StatusNotFound)
				}))
				t.Cleanup(controlServer.Close)
				controlEnv.handler.toolRiskClient.controlPlaneURL = controlServer.URL
				controlDecision := controlEnv.handler.analyzeMCPCallArguments(context.Background(), envelope, input, nil)
				if !mcpSkillAdmissionEvidenceGap(controlDecision) {
					t.Fatalf("对照组应追加 skill_admission_coverage_gap 证据: %+v", controlDecision.Evidence)
				}

				// 断开：准入查询阻塞到请求 ctx 取消。
				entered := make(chan struct{})
				cp := newSkillAdmissionControlPlane(t, entered, 0)
				env := newWS1Env(t, auditOnly, blockTool("__none__"))
				env.handler.toolRiskClient.controlPlaneURL = cp.url
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go func() { <-entered; cancel() }()

				decision := env.handler.analyzeMCPCallArguments(ctx, envelope, input, nil)

				if mcpSkillAdmissionEvidenceGap(decision) {
					t.Errorf("客户端断开不应追加 skill_admission_coverage_gap 证据: %+v", decision.Evidence)
				}
				if decision.EffectiveDecision != controlDecision.EffectiveDecision {
					t.Errorf("断开不应改变分析结论（拦截与否沿用原有计算）: gone=%s control=%s", decision.EffectiveDecision, controlDecision.EffectiveDecision)
				}
			})
		}
	}
}
