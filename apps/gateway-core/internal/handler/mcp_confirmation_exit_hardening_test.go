package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpconfirmation"
)

// 2.9.22：元数据不再是内置底线；“metadata floor”两行改为经 protections 把 agent.cloud_metadata
// 配成阻断，另加一行默认配置（告警放行）照常执行。
const metadataBlockProtections = `,"protections":{"agent.cloud_metadata":{"action":"block","params":{}}}`

func TestApprovedMCPConfirmationCurrentPolicyUsesCentralExit(t *testing.T) {
	for _, tc := range []struct {
		name, action, arguments  string
		record, auditLock, drift bool
		wantError                string
		protections, wantRaw     string
	}{
		{"Protect configured block", "block", `{}`, false, false, false, "current_policy_blocked", "", "block"},
		{"Record configured block", "block", `{}`, true, false, false, "", "", "block"},
		// 2.9.22（D7）：部署变量只在没有显式执行模式时作初值；控制台显式 protect 时照拦
		// （原用例“部署锁下照样执行”随用户 11-17 决定改写）。
		{"deployment variable with managed protect", "block", `{}`, false, true, false, "current_policy_blocked", "", "block"},
		{"Protect metadata protection", "allow", `{"url":"http://169.254.169.254/latest/meta-data/"}`, false, false, false, "current_policy_blocked", metadataBlockProtections, "block"},
		{"Record metadata protection", "allow", `{"url":"http://169.254.169.254/latest/meta-data/"}`, true, false, false, "", metadataBlockProtections, "block"},
		{"Protect metadata default protection", "allow", `{"url":"http://169.254.169.254/latest/meta-data/"}`, false, false, false, "", "", "audit"},
		// 2.9.22：重放时环境变化默认告警放行；配成阻断（mcp.replay_changed=block）时照拦。
		{"Record preserves approval drift rejection", "block", `{}`, true, false, true, "approval_context_drift", `,"protections":{"mcp.replay_changed":{"action":"block"}}`, "block"},
		// 只有环境变化、没有别的阻断结论时，默认告警放行。
		{"Record approval drift alerts by default", "allow", `{}`, true, false, true, "", "", "allow"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("JJD_PROVIDER_SECRET_KEY", "mcp-central-exit-key")
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			if tc.auditLock {
				t.Setenv("SECURITY_AUDIT_ONLY", "true")
			}
			var upstreamHits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":9,"result":{"content":[{"type":"text","text":"ok"}]}}`))
			}))
			defer upstream.Close()
			var payload map[string]any
			controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/admin/v1/internal/mcp/effective-policy":
					schemaHash := strings.Repeat("b", 64)
					if tc.drift {
						schemaHash = strings.Repeat("c", 64)
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"matched": true, "policy_id": "current", "tool_id": "tool-write", "mode": "strict", "action": tc.action,
						"supply_chain_status": "approved", "supply_chain_revision": "revision-a",
						"server_admission_status": "approved", "tool_admission_status": "approved",
						"route_hash": strings.Repeat("a", 64), "approved_route_hash": strings.Repeat("a", 64), "approved_schema_hash": schemaHash,
					})
				case "/admin/v1/internal/agentguard/effective-policy":
					_, _ = w.Write([]byte(`{"data":{"mode":"strict","default_action":"audit","rules":[],"exceptions":[]` + tc.protections + `}}`))
				case "/admin/v1/internal/tools/logs":
					if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
						t.Error(err)
					}
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(`{"id":"replay-audit"}`))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer controlPlane.Close()
			client := NewToolRiskClient(controlPlane.URL, "internal")
			client.SetMCPConfirmationScopeSecret(mcpExecutionScopeTestSecret)
			client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
				Revision: strings.Repeat("0", 32), SecurityAuditOnly: tc.record, SecurityExecutionModeManaged: true,
			})
			proxy := NewMCPProxyHandler(nil, client, false)
			proxy.auditRecorder = &mcpProxyAuditRecorder{db: newFakeAuditDB()}
			proxy.serverCache.set("tenant-a\x1fserver-a", &mcpServerRoute{
				ID: "server-a", TenantID: "tenant-a", Name: "demo", ServerURL: upstream.URL,
				Status: "active", Transport: "streamable_http", ProtocolVersion: mcpProtocolVersionLatest,
				AllowPrivateEgress: true, RouteHash: strings.Repeat("a", 64),
			})
			proxy.targetClientResolver = func(_ context.Context, rawURL string, _ bool, _ *http.Client) (*http.Client, *url.URL, error) {
				parsed, err := url.Parse(rawURL)
				return upstream.Client(), parsed, err
			}
			body := json.RawMessage(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"network.get","arguments":` + tc.arguments + `}}`)
			record := encryptedMCPExecutionRecord(t, mcpExecutionScopeTestSecret, mcpconfirmation.ReplayContext{
				Version: mcpconfirmation.ReplayContextVersion, TenantID: "tenant-a", EnvironmentScope: "customer",
				ServerID: "server-a", ToolName: "network.get", ToolCallID: "number:9", ProtocolVersion: mcpProtocolVersionLatest,
				ToolID: "tool-write", SupplyChainRevision: "revision-a", ApprovedSchemaHash: strings.Repeat("b", 64),
				ServerRouteHash: strings.Repeat("a", 64), RequestBody: body,
			})
			completion := proxy.executeApprovedMCPConfirmation(context.Background(), record)
			wantStatus, wantHits := "executed", int32(1)
			if tc.wantError != "" {
				wantStatus, wantHits = "failed", 0
			}
			if completion.Status != wantStatus || completion.ErrorCode != tc.wantError || upstreamHits.Load() != wantHits || completion.EvidenceStatus != "complete" {
				t.Fatalf("approved replay must use current posture while preserving approval validation: completion=%+v hits=%d want=%s/%s/%d", completion, upstreamHits.Load(), wantStatus, tc.wantError, wantHits)
			}
			if tc.wantError == "" && (payload["raw_decision"] != tc.wantRaw || payload["effective_decision"] != "audit") {
				t.Fatalf("Record replay must retain the would-block verdict: %+v", payload)
			}
		})
	}
}
