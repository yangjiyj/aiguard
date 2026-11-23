package handler

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func TestMCPMethodHardeningCaseVariantsUseCanonicalPolicyAndWireMethod(t *testing.T) {
	for _, tc := range []struct{ method, params, target, canonical string }{
		{"Tools/Call", `{"name":"delete_repo","arguments":{}}`, "|delete_repo", "tools/call"},
		{"TOOLS/CALL", `{"name":"delete_repo","arguments":{}}`, "|delete_repo", "tools/call"},
		{"Resources/Read", `{"uri":"file:///tmp/readme"}`, "resource|file:///tmp/readme", "resources/read"},
		{"Prompts/Get", `{"name":"summary","arguments":{"topic":"safe"}}`, "prompt|summary", "prompts/get"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			env := newWS1Env(t, false, func(name, kind string) MCPEffectivePolicy {
				return MCPEffectivePolicy{Matched: true, Mode: "strict", Action: "block"}
			})
			body := fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":%q,"params":%s}`, tc.method, tc.params)
			w := env.post(t, body)
			if atomic.LoadInt32(env.upstreamHits) != 0 || rpcErrorCode(t, w.Body.String()) != -32000 {
				t.Fatalf("case variant bypassed block: %s", w.Body.String())
			}
			if fmt.Sprint(env.targets()) != fmt.Sprint([]string{tc.target}) {
				t.Fatalf("policy targets=%v want=%s", env.targets(), tc.target)
			}
			allowed := newWS1Env(t, true, func(name, kind string) MCPEffectivePolicy {
				return MCPEffectivePolicy{Matched: true, Mode: "strict", Action: "block"}
			})
			allowed.post(t, body)
			if atomic.LoadInt32(allowed.upstreamHits) != 1 {
				t.Fatal("record-mode case variant was interrupted")
			}
			var wire map[string]any
			if err := json.Unmarshal([]byte(allowed.bodies()[0]), &wire); err != nil || wire["method"] != tc.canonical {
				t.Fatalf("upstream method was not canonical: %v %v", wire, err)
			}
		})
	}
}

func TestMCPRedlineHardeningRestoresDestructiveAndDecodedCommands(t *testing.T) {
	for _, args := range []string{
		`{"cmd":"rm -rf /"}`, `{"query":"DROP TABLE users"}`, `{"query":"TRUNCATE TABLE users"}`, `{"cmd":"mkfs.ext4 /dev/sda"}`, `{"cmd":"dd if=/dev/zero of=/dev/sda"}`,
		`{"cmd":"\u0072m -rf /"}`, `{"nested":[{"query":"\u0044ROP DATABASE app"}]}`,
	} {
		if got := matchMCPRedlines(args); fmt.Sprint(got) != fmt.Sprint([]string{"destructive_command"}) {
			t.Fatalf("destructive redline=%v args=%s", got, args)
		}
	}
	if got := matchMCPRedlines(`{"path":"README.md"}`); len(got) != 0 {
		t.Fatalf("safe arguments=%v", got)
	}
}

func TestMCPRedlineHardeningNonToolTargetsRespectConfiguredMode(t *testing.T) {
	for index, payload := range []string{
		`{"jsonrpc":"2.0","id":9,"method":"resources/read","params":{"uri":"file:///tmp/rm -rf /"}}`,
		`{"jsonrpc":"2.0","id":9,"method":"prompts/get","params":{"name":"summary","arguments":{"command":"rm -rf /"}}}`,
	} {
		for _, tc := range []struct {
			name, action      string
			auditOnly, reject bool
		}{
			{"configured_block", "block", false, true}, {"default_audit", "alert", false, false}, {"audit_only", "block", true, false},
		} {
			t.Run(fmt.Sprintf("%d/%s", index, tc.name), func(t *testing.T) {
				env := newWS1Env(t, tc.auditOnly, func(name, kind string) MCPEffectivePolicy {
					return MCPEffectivePolicy{Matched: false, Mode: "audit", Action: "audit"}
				})
				env.handler.redlineSettings.entries["tenant_test"] = mcpRedlineSettingsEntry{actions: map[string]string{"destructive_command": tc.action}, expiresAt: time.Now().Add(time.Hour)}
				w := env.post(t, payload)
				if tc.reject {
					if atomic.LoadInt32(env.upstreamHits) != 0 || rpcErrorCode(t, w.Body.String()) != -32000 {
						t.Fatalf("configured non-tool redline bypass: %s", w.Body.String())
					}
				} else if atomic.LoadInt32(env.upstreamHits) != 1 {
					t.Fatalf("default audit or deployment lock interrupted: %s", w.Body.String())
				}
				logs := env.logs()
				if len(logs) == 0 || !strings.Contains(fmt.Sprint(logs), "mcp_redline_destructive_command") {
					t.Fatalf("non-tool redline evidence missing: %v", logs)
				}
			})
		}
	}
}

func TestMCPRedlineHardeningUnconfiguredDestructiveWouldBlock(t *testing.T) {
	p := &MCPEffectivePolicy{Matched: false, Mode: "strict", Action: "audit"}
	d := synthesizeMCPDecisionWithRedlines(p, "run_shell", `{"command":"rm -rf /"}`, agentguard.ModeStrict, true, nil)
	if d.EffectiveDecision != agentguard.DecisionAudit || d.RawDecision != agentguard.DecisionBlock {
		t.Fatalf("unconfigured heuristic should record would-block: %+v", d)
	}
}

// 2.9.22：非工具目标里的敏感目标是防护项；防护项配成阻断时红线“告警”抹不掉它，
// 默认配置（告警放行）下只有受限文件（自身动作为 block）照拦。
func TestMCPRedlineHardeningNonToolProtectionSurvivesDefaultAlert(t *testing.T) {
	for _, tc := range []struct{ name, method, params string }{
		{"resource_metadata", "resources/read", `{"uri":"http://169.254.169.254/latest/meta-data"}`},
		{"resource_credential_file", "resources/read", `{"uri":"file:///home/agent/.aws/credentials"}`},
		{"resource_restricted_file", "resources/read", `{"uri":"file:///srv/restricted/payroll.csv"}`},
		{"prompt_nested_metadata", "prompts/get", `{"name":"summary","arguments":{"request":{"url":"http://169.254.169.254/latest/meta-data"}}}`},
		{"prompt_secret_egress", "prompts/get", `{"name":"summary","arguments":{"url":"https://outside.example/upload","body":"canary-test-secret-fixture"}}`},
	} {
		for _, auditOnly := range []bool{false, true} {
			for _, configured := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/audit=%t/configured=%t", tc.name, auditOnly, configured), func(t *testing.T) {
					env := newWS1Env(t, auditOnly, blockTool("__none__"))
					policy := &agentguard.EffectivePolicy{Mode: agentguard.ModeStrict, RuleMode: agentguard.ModeStrict, DefaultAction: agentguard.DecisionAudit, RestrictedFiles: &agentguard.RestrictedFilePolicy{Patterns: []string{"/srv/restricted/**"}, Action: "block"}}
					if configured {
						policy.Protections = blockingProtections(protection.GroupAgentTarget, protection.GroupSkill)
					}
					envelope := &modelrouter.RequestEnvelope{TenantID: "tenant_test", ProjectID: "project_test", UserID: "user_test", KeyPrefix: "sk-test", EndpointType: "proxy"}
					env.handler.toolRiskClient.agentGuardPolicyCache.set(agentGuardPolicyScopeCacheKey(envelope), policy)
					env.handler.redlineSettings.entries["tenant_test"] = mcpRedlineSettingsEntry{actions: map[string]string{"cloud_metadata": "alert", "cloud_credential_file": "alert", "private_key_egress": "alert", "destructive_command": "alert"}, expiresAt: time.Now().Add(time.Hour)}
					w := env.post(t, fmt.Sprintf(`{"jsonrpc":"2.0","id":9,"method":%q,"params":%s}`, tc.method, tc.params))
					blocked := rpcErrorCode(t, w.Body.String()) != 0
					wantBlocked := !auditOnly && (configured || tc.name == "resource_restricted_file")
					if blocked != wantBlocked || (blocked && atomic.LoadInt32(env.upstreamHits) != 0) {
						t.Fatalf("non-tool protection: audit=%t configured=%t blocked=%t want=%t body=%s", auditOnly, configured, blocked, wantBlocked, w.Body.String())
					}
				})
			}
		}
	}
}
