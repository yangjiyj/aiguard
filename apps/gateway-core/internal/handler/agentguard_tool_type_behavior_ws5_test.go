package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 自定义工具名没有任何启发式特征，只有 schema 暴露了 url / path 参数：
// 5.9 之前这类工具按 unknown 处理，不进 network / file 分析器，
// 访问云元数据、读取 /etc/shadow 都会被放行。
// 2.9.22：命中的是防护项；经 protections 配成阻断时照拦，无租户策略时取默认告警放行。
func TestWS5SchemaInferredToolTypeDrivesAnalysis(t *testing.T) {
	cases := []struct {
		name, schema, args, wantReason, item string
	}{
		{"network", `{"type":"object","properties":{"url":{"type":"string"}}}`, `{"url":"http://169.254.169.254/latest/meta-data/"}`, "blocked_cloud_metadata", "agent.cloud_metadata"},
		// 2.9.22 任务 2.1：/etc/shadow 按完整路径归“系统口令与进程环境”。
		{"file", `{"type":"object","properties":{"path":{"type":"string"}}}`, `{"path":"/etc/shadow"}`, "blocked_system_secret_file", "agent.system_secret_file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			analyze := func(client *ToolRiskClient) agentguard.Decision {
				h := &ChatCompletionsHandler{cfg: &config.Config{}, securityClient: &MockSecurityChecker{}, auditWriter: &MockAuditWriter{}, agentGuardToolTypes: newAgentGuardToolTypeCache(), toolRiskClient: client}
				envelope := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", UserID: "u", AgentType: "openai-codex"}
				h.rememberAgentGuardToolDefinition(envelope, ToolDef{Type: "function", Function: ToolFunc{Name: "acme_sync", Parameters: json.RawMessage(c.schema)}})
				call := ToolCall{ID: "c1", Type: "function", Function: ToolCallFunc{Name: "acme_sync", Arguments: c.args}}
				decision, _, _ := h.analyzeAgentGuardToolCall(context.Background(), envelope, call, nil)
				return decision
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/admin/v1/internal/agentguard/effective-policy":
					_, _ = w.Write([]byte(`{"data":{"id":"p","mode":"strict","default_action":"audit","rules":[],"exceptions":[],"protections":{"` + c.item + `":{"action":"block","params":{}}}}}`))
				case "/admin/v1/internal/tools/config":
					_, _ = w.Write([]byte(`{"data":[]}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			client := NewToolRiskClient(server.URL, "secret")
			setToolGuardTestPosture(t, client, false, false)
			if decision := analyze(client); decision.EffectiveDecision != agentguard.DecisionBlock || decision.Reason != c.wantReason || decision.ProtectionItem != c.item {
				t.Fatalf("schema-inferred %s tool must be analyzed and blocked when configured: %+v", c.name, decision)
			}
			if decision := analyze(nil); decision.EffectiveDecision != agentguard.DecisionAudit || !decision.NotificationRequired || decision.ProtectionItem != c.item {
				t.Fatalf("schema-inferred %s tool must be analyzed and alerted by default: %+v", c.name, decision)
			}
		})
	}
}
