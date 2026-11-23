package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
)

func TestToolRiskClientMapsAgentOperationRuntimeFields(t *testing.T) {
	var receivedProtocol string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedProtocol = r.URL.Query().Get("protocol")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"policy-destructive","policy_version":"v7","mode":"strict","default_action":"audit","config_source":"application_policy","protocol":"mcp","discardable_paths":["dist","build/output"],"notify_channel_ids":["channel-a","channel-b"],"destructive":{"mode":"strict","action":"confirm","scope_type":"application","scope_ref":"app-public","protocol":"mcp"}}}`))
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, "secret")
	policy, err := client.GetAgentGuardPolicy(context.Background(), &modelrouter.RequestEnvelope{
		TenantID: "tenant-1", ProjectID: "app-public", EndpointType: "mcp",
	})
	if err != nil {
		t.Fatalf("GetAgentGuardPolicy: %v", err)
	}
	if receivedProtocol != "mcp" {
		t.Fatalf("effective policy protocol query=%q want mcp", receivedProtocol)
	}
	if policy == nil || policy.ConfigSource != agentguard.ConfigSourceApplicationPolicy || policy.Destructive == nil {
		t.Fatalf("destructive contract not mapped: %#v", policy)
	}
	if policy.Destructive.Protocol != "mcp" {
		t.Fatalf("destructive protocol mismatch: %#v", policy.Destructive)
	}
	if !reflect.DeepEqual(policy.Destructive.DiscardablePaths, []string{"dist", "build/output"}) {
		t.Fatalf("destructive paths mismatch: %#v", policy.Destructive)
	}
	if !reflect.DeepEqual(policy.Destructive.NotifyChannelIDs, []string{"channel-a", "channel-b"}) {
		t.Fatalf("destructive channel ids mismatch: %#v", policy.Destructive)
	}
}
func TestToolRiskClientUsesRuntimeProtocolForPolicyLookup(t *testing.T) {
	tests := []struct {
		endpointType string
		wantProtocol string
	}{
		{endpointType: "chat", wantProtocol: "chat"},
		{endpointType: "responses", wantProtocol: "responses"},
		{endpointType: "mcp", wantProtocol: "mcp"},
		{endpointType: "proxy", wantProtocol: "mcp"},
	}
	for _, tt := range tests {
		t.Run(tt.endpointType, func(t *testing.T) {
			var received string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received = r.URL.Query().Get("protocol")
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"data":null}`))
			}))
			defer server.Close()

			client := NewToolRiskClient(server.URL, "secret")
			_, err := client.GetAgentGuardPolicy(context.Background(), &modelrouter.RequestEnvelope{
				TenantID: "tenant-1", EndpointType: tt.endpointType,
			})
			if err != nil {
				t.Fatalf("GetAgentGuardPolicy: %v", err)
			}
			if received != tt.wantProtocol {
				t.Fatalf("protocol query=%q want %q", received, tt.wantProtocol)
			}
		})
	}
}

func TestToolRiskClientSeparatesPolicyCacheByRuntimeProtocol(t *testing.T) {
	var received []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = append(received, r.URL.Query().Get("protocol"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":null}`))
	}))
	defer server.Close()

	client := NewToolRiskClient(server.URL, "secret")
	envelope := &modelrouter.RequestEnvelope{TenantID: "tenant-1", SessionID: "session-1", EndpointType: "chat"}
	if _, err := client.GetAgentGuardPolicy(context.Background(), envelope); err != nil {
		t.Fatalf("chat policy lookup: %v", err)
	}
	envelope.EndpointType = "proxy"
	if _, err := client.GetAgentGuardPolicy(context.Background(), envelope); err != nil {
		t.Fatalf("MCP policy lookup: %v", err)
	}
	if !reflect.DeepEqual(received, []string{"chat", "mcp"}) {
		t.Fatalf("policy lookups=%#v want separate chat and MCP requests", received)
	}
}

func TestConvertValidatedDestructivePolicyRejectsUntrustedFields(t *testing.T) {
	valid := func() *agentGuardPolicyData {
		return &agentGuardPolicyData{
			Mode:             "strict",
			ConfigSource:     "application_policy",
			Protocol:         "mcp",
			DiscardablePaths: []string{"dist"},
			NotifyChannelIDs: []string{"channel-a"},
			Destructive: &agentGuardDestructiveData{
				Mode: "strict", Action: "confirm", ScopeType: "application",
				ScopeRef: "app-public", Protocol: "mcp",
			},
		}
	}
	tests := []struct {
		name   string
		mutate func(*agentGuardPolicyData)
	}{
		{"unsupported protocol", func(data *agentGuardPolicyData) {
			data.Protocol, data.Destructive.Protocol = "chat", "chat"
		}},
		{"protocol mismatch", func(data *agentGuardPolicyData) {
			data.Destructive.Protocol = ""
		}},
		{"too many paths", func(data *agentGuardPolicyData) {
			data.DiscardablePaths = make([]string, 33)
			for i := range data.DiscardablePaths {
				data.DiscardablePaths[i] = "path"
			}
		}},
		{"unsafe path", func(data *agentGuardPolicyData) {
			data.DiscardablePaths = []string{"../secret"}
		}},
		{"too many channels", func(data *agentGuardPolicyData) {
			data.NotifyChannelIDs = make([]string, 17)
			for i := range data.NotifyChannelIDs {
				data.NotifyChannelIDs[i] = "channel"
			}
		}},
		{"overlong channel", func(data *agentGuardPolicyData) {
			data.NotifyChannelIDs = []string{strings.Repeat("c", 129)}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := valid()
			tt.mutate(data)
			if policy, _, ok := convertValidatedDestructivePolicy(data); ok || policy != nil {
				t.Fatalf("untrusted policy accepted: %#v", policy)
			}
		})
	}
	// 2.9.22 批次 2B：原表里的“confirm without mcp”（protocol 为空的确认）不再是非法输入——
	// protocol 为空表示所有协议，非 MCP 协议也能选确认。
	data := valid()
	data.Protocol, data.Destructive.Protocol = "", ""
	if policy, _, ok := convertValidatedDestructivePolicy(data); !ok || policy.Action != "confirm" {
		t.Fatalf("a confirm policy for all protocols is valid: %#v", policy)
	}
}
func TestConvertAgentGuardPolicyFailsClosedForInvalidDestructivePayload(t *testing.T) {
	invalid := &agentGuardPolicyData{
		ID: "invalid-destructive", Mode: "light", ConfigSource: "application_policy",
		Protocol: "chat",
		Destructive: &agentGuardDestructiveData{
			Mode: "light", Action: "confirm", ScopeType: "application",
			ScopeRef: "app-public", Protocol: "chat",
		},
	}
	// 2.9.22 批次 2B：无效的确认载荷不再强制改成 strict 走预设阻断（那是不读配置的拦截），
	// 丢弃破坏性策略，按下发的模式取预设（这里 light → 告警放行）。原断言 Mode=strict。
	policy := convertAgentGuardPolicy(invalid)
	if policy.Destructive != nil || policy.Mode != agentguard.ModeLight {
		t.Fatalf("invalid destructive payload must be dropped without a forced block: %#v", policy)
	}

	withoutDestructive := convertAgentGuardPolicy(&agentGuardPolicyData{
		ID: "legacy-policy", Mode: "audit",
	})
	if withoutDestructive.Destructive != nil {
		t.Fatalf("absent destructive payload changed legacy policy: %#v", withoutDestructive)
	}
}

func TestStructuredToolGateUsesConfiguredDiscardablePaths(t *testing.T) {
	policy := &agentguard.EffectivePolicy{
		Mode: agentguard.ModeStrict,
		Destructive: &agentguard.DestructivePolicy{
			Mode: agentguard.ModeStrict, Action: agentguard.DestructiveActionBlock,
			DiscardablePaths: []string{"generated"},
		},
	}
	got := evaluateStructuredToolCall(structuredToolCallInput{
		TenantID: "tenant-1", Protocol: "chat", ToolName: "shell",
		Arguments: map[string]interface{}{
			"command": "rm -rf /repo/generated", "working_directory": "/repo", "repository_root": "/repo",
		},
		Policy: policy, Mode: agentguard.ModeStrict,
	})
	if !got.Destructive.DiscardablePathMatched {
		t.Fatalf("custom discardable path was not sent to analyzer: %#v", got.Destructive)
	}
}

func TestStructuredToolGatePropagatesImpactRiskLevel(t *testing.T) {
	policy := &agentguard.EffectivePolicy{
		Mode: agentguard.ModeAudit,
		Destructive: &agentguard.DestructivePolicy{
			Mode: agentguard.ModeAudit, Action: agentguard.DestructiveActionRecord,
		},
	}
	for _, tt := range []struct {
		name, command, severity string
	}{
		{"data directory", "sudo rm -rf /srv/build-cache", "high"},
		// 客户A 11-21：只删临时目录降为中危，级别照样透传到安全事件。
		{"workspace cleanup", "sudo rm -rf /tmp/build-cache", "medium"},
		{"root filesystem", "sudo rm -rf /", "critical"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateStructuredToolCall(structuredToolCallInput{
				TenantID: "tenant-1", Protocol: "chat", ToolName: "shell_command",
				Arguments: map[string]interface{}{"command": tt.command},
				Policy:    policy, Mode: agentguard.ModeAudit,
			})
			if got.Decision.RiskLevel != tt.severity {
				t.Fatalf("decision risk=%q want %q: %#v", got.Decision.RiskLevel, tt.severity, got.Decision)
			}
			finding := agentGuardSecurityFinding(
				ToolCall{Function: ToolCallFunc{Name: "shell_command"}}, got.Decision, 0,
			)
			if finding.Severity != tt.severity {
				t.Fatalf("finding severity=%q want %q: %#v", finding.Severity, tt.severity, finding)
			}
		})
	}
}

// 2.9.22 批次 2B：解析失败改为兜底防护项 agent.parse_rejected，不再按“删除与破坏”卡片处置。
// 原用例锁的是“卡片仅记录则放行、卡片阻断则阻断，且记为破坏性结论”，改为：卡片是阻断也只按
// 防护项默认告警放行；防护项配成阻断照拦；加例外放开。结论不再是破坏性结论（没有 FinalAction）。
func TestStructuredToolGateParseRejectedFailSafeRespectsDestructivePolicy(t *testing.T) {
	future := time.Now().Add(time.Hour)
	tests := []struct {
		name         string
		settings     protection.Settings
		exceptions   []agentguard.PolicyException
		wantDecision agentguard.DecisionAction
		wantNotify   bool
	}{
		{name: "default alerts and allows even when the destructive card blocks", wantDecision: agentguard.DecisionAudit, wantNotify: true},
		{name: "configured block blocks", settings: protection.Settings{"agent.parse_rejected": {Action: protection.ActionBlock}},
			wantDecision: agentguard.DecisionBlock},
		{name: "exception releases", settings: protection.Settings{"agent.parse_rejected": {Action: protection.ActionBlock}},
			exceptions:   []agentguard.PolicyException{{ID: "e-parse", RuleID: "agent.parse_rejected", ExpiresAt: future}},
			wantDecision: agentguard.DecisionAudit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := &agentguard.EffectivePolicy{
				ID: "policy-parse-rejected", PolicyVersion: "v-parse-rejected",
				Mode: agentguard.ModeStrict, RuleMode: agentguard.ModeStrict, ConfigSource: agentguard.ConfigSourceTenantPolicy,
				Destructive: &agentguard.DestructivePolicy{
					Mode: agentguard.ModeStrict, Action: agentguard.DestructiveActionBlock, ScopeType: "tenant",
					NotifyChannelIDs: []string{"channel-failsafe"},
				},
				Protections: tt.settings, Exceptions: tt.exceptions,
			}
			got := evaluateStructuredToolCall(structuredToolCallInput{
				TenantID: "tenant_default", Protocol: "chat", SessionID: "session-parse",
				RequestID: "req-parse", ToolCallID: "call-bash", ToolName: "Bash", ToolType: "shell",
				Arguments: map[string]interface{}{"command": "rm -rf /srv/data && ("},
				Policy:    policy, Mode: agentguard.ModeStrict,
			})
			if !got.Destructive.ParseRejected || got.Destructive.HighConfidence {
				t.Fatalf("test input must hit ParseRejected && !HighConfidence: %#v", got.Destructive)
			}
			decision := got.Decision
			if decision.EffectiveDecision != tt.wantDecision || decision.NotificationRequired != tt.wantNotify {
				t.Fatalf("parse_rejected action mismatch: %#v", decision)
			}
			if decision.Reason != destructiveParseRejectedFailSafeReason || decision.ReasonSummary != destructiveParseRejectedFailSafeReason ||
				decision.ProtectionItem != "agent.parse_rejected" {
				t.Fatalf("fail-safe reason and protection item were not retained: %#v", decision)
			}
			if decision.FinalAction != "" || decision.RiskCategory == agentguard.DestructiveRiskCategory || isDestructiveGateDecision(decision) {
				t.Fatalf("a parse rejection is not a destructive-card verdict any more: %#v", decision)
			}
			if decision.OperationID == "" || !strings.HasPrefix(decision.OperationID, "op_") {
				t.Fatalf("operation id missing: %#v", decision)
			}
			assertEvidenceRule(t, decision.Evidence, "agent_destructive_command_parse_incomplete")
			payloads := buildAgentGuardToolAuditPayloads(ToolCall{ID: "call-bash", Function: ToolCallFunc{Name: "Bash"}}, decision, nil)
			if len(payloads) != 1 || payloads[0].EffectiveReason != decision.EffectiveReason {
				t.Fatalf("an ordinary tool payload is written: %#v", payloads)
			}
		})
	}
}

func TestStructuredToolGatePreservesParseRejectedEvidenceFromAnalysis(t *testing.T) {
	analysis := agentguard.DestructiveAnalysis{
		Confidence: "medium", Reason: "destructive_target_incomplete",
		SuggestedAction: agentguard.DecisionAudit, ParseRejected: true,
		Evidence: []agentguard.Evidence{{RuleID: "agent_destructive_command_parse_rejected", Category: "destructive_operation"}},
	}
	decision := applyStructuredRejectionPolicy(structuredToolCallInput{
		TenantID: "tenant_default", Protocol: "chat", ToolName: "Bash", ToolType: "shell",
		Policy: &agentguard.EffectivePolicy{
			Mode: agentguard.ModeAudit, ConfigSource: agentguard.ConfigSourceTenantPolicy,
			Destructive: &agentguard.DestructivePolicy{Mode: agentguard.ModeAudit, Action: agentguard.DestructiveActionRecord, ScopeType: "tenant"},
		},
		Mode: agentguard.ModeAudit,
	}, agentguard.Decision{}, "op_synthetic", analysis, []string{destructiveParseRejectedFailSafeReason})
	// 2.9.22：原断言“破坏性卡片仅记录 + 原因保留在 EffectiveReason”改为“防护项结论放行 + 原因码
	// 是防护项命中”。
	if decision.EffectiveDecision != agentguard.DecisionAudit || decision.Reason != destructiveParseRejectedFailSafeReason ||
		decision.OperationID != "op_synthetic" {
		t.Fatalf("parse rejection should allow while keeping the fail-safe reason: %#v", decision)
	}
	assertEvidenceRule(t, decision.Evidence, "agent_destructive_command_parse_rejected")
}

// 2.9.22 批次 2B：删除与破坏选“确认”不再限定 MCP。原用例锁的是“非 MCP 协议的确认一律改成阻断”，
// 改为：有确认通道的协议都走确认（chat/responses 用普通确认票据）；没有通道时按
// agent.confirm_without_channel，默认告警放行，配成阻断才拦。
func TestStructuredToolGateRestrictsConfirmToMCP(t *testing.T) {
	policy := func(channel bool, settings protection.Settings) *agentguard.EffectivePolicy {
		return &agentguard.EffectivePolicy{
			Mode: agentguard.ModeStrict, ConfirmChannelEnabled: channel, Protections: settings,
			Destructive: &agentguard.DestructivePolicy{
				Mode: agentguard.ModeStrict, Action: agentguard.DestructiveActionConfirm, Protocol: "chat",
			},
		}
	}
	for _, tt := range []struct {
		name     string
		protocol string
		policy   *agentguard.EffectivePolicy
		want     agentguard.DecisionAction
	}{
		{name: "mcp extension", protocol: "mcp", policy: policy(false, nil), want: agentguard.DecisionConfirm},
		{name: "chat ticket", protocol: "chat", policy: policy(true, nil), want: agentguard.DecisionConfirm},
		{name: "responses ticket", protocol: "responses", policy: policy(true, nil), want: agentguard.DecisionConfirm},
		{name: "chat without channel alerts by default", protocol: "chat", policy: policy(false, nil), want: agentguard.DecisionAudit},
		{name: "chat without channel blocks when configured", protocol: "chat",
			policy: policy(false, protection.Settings{"agent.confirm_without_channel": {Action: protection.ActionBlock}}), want: agentguard.DecisionBlock},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateStructuredToolCall(structuredToolCallInput{
				TenantID: "tenant-1", Protocol: tt.protocol, ToolName: "shell",
				Arguments: map[string]interface{}{"command": "rm -rf /repo/src"},
				Policy:    tt.policy, Mode: agentguard.ModeStrict, ConfirmSupported: tt.protocol == "mcp",
			})
			if got.Decision.EffectiveDecision != tt.want {
				t.Fatalf("decision=%q want %q: %#v", got.Decision.EffectiveDecision, tt.want, got.Decision)
			}
			if tt.want == agentguard.DecisionAudit && !got.Decision.NotificationRequired {
				t.Fatalf("confirm without a channel must alert: %#v", got.Decision)
			}
		})
	}
}

// 兜底项 agent.identity_rejected：协议层身份异常默认告警放行，配成阻断照拦，加例外放开；
// 可信客户端名单可改（参数 trusted_agent_types，空时用内置名单）；身份异常不再跳过破坏性分析。
func TestStructuredToolGateIdentityRejectedFollowsProtectionItem(t *testing.T) {
	future := time.Now().Add(time.Hour)
	call := func(agent string, settings protection.Settings, exceptions []agentguard.PolicyException, command string) agentguard.Decision {
		policy := &agentguard.EffectivePolicy{ID: "p", Mode: agentguard.ModeStrict, RuleMode: agentguard.ModeStrict,
			Destructive: &agentguard.DestructivePolicy{Mode: agentguard.ModeStrict, Action: agentguard.DestructiveActionBlock},
			Protections: settings, Exceptions: exceptions}
		return evaluateStructuredToolCall(structuredToolCallInput{
			TenantID: "tenant-1", Protocol: "responses", ToolName: "shell", ToolType: "shell", AgentType: agent,
			Arguments: map[string]interface{}{"command": command}, ProtocolIdentityRejected: true,
			Policy: policy, Mode: agentguard.ModeStrict,
		}).Decision
	}
	blocking := protection.Settings{"agent.identity_rejected": {Action: protection.ActionBlock}}
	if got := call("", nil, nil, "ls"); got.EffectiveDecision != agentguard.DecisionAudit || !got.NotificationRequired || got.ProtectionItem != "agent.identity_rejected" {
		t.Fatalf("identity rejection alerts and allows by default: %#v", got)
	}
	if got := call("", blocking, nil, "ls"); got.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("identity rejection configured to block must block: %#v", got)
	}
	exception := []agentguard.PolicyException{{ID: "e-id", RuleID: "destructive_identity_rejected", ExpiresAt: future}}
	if got := call("", blocking, exception, "ls"); got.EffectiveDecision == agentguard.DecisionBlock {
		t.Fatalf("an exception naming the identity item must release it: %#v", got)
	}
	if got := call("claude-code", blocking, nil, "ls"); got.ProtectionItem == "agent.identity_rejected" || got.EffectiveDecision == agentguard.DecisionBlock {
		t.Fatalf("built-in trusted clients are not identity rejections: %#v", got)
	}
	trusted := protection.Settings{"agent.identity_rejected": {Action: protection.ActionBlock, Params: map[string]any{"trusted_agent_types": []any{"my-agent"}}}}
	if got := call("my-agent", trusted, nil, "ls"); got.EffectiveDecision == agentguard.DecisionBlock {
		t.Fatalf("a configured trusted client is not an identity rejection: %#v", got)
	}
	if got := call("claude-code", trusted, nil, "ls"); got.EffectiveDecision != agentguard.DecisionBlock {
		t.Fatalf("a configured list replaces the built-in one: %#v", got)
	}
	if got := call("", nil, nil, "rm -rf /srv/isolated-fixture"); got.EffectiveDecision != agentguard.DecisionBlock || !isDestructiveGateDecision(got) {
		t.Fatalf("an identity rejection still runs the destructive card: %#v", got)
	}
}

func TestStructuredToolGatePreservesAllowForNonDestructiveCalls(t *testing.T) {
	base := agentguard.Decision{
		RawDecision: agentguard.DecisionAllow, EffectiveDecision: agentguard.DecisionAllow,
	}
	got := evaluateStructuredToolCall(structuredToolCallInput{
		TenantID: "tenant-1", Protocol: "chat", ToolName: "shell",
		Arguments: map[string]interface{}{"command": "echo hello"}, BaseDecision: base,
	})
	if got.Decision.RawDecision != agentguard.DecisionAllow ||
		got.Decision.EffectiveDecision != agentguard.DecisionAllow {
		t.Fatalf("non-destructive allow changed: %#v", got.Decision)
	}
}

func assertEvidenceRule(t *testing.T, evidence []agentguard.Evidence, want string) {
	t.Helper()
	for _, item := range evidence {
		if item.RuleID == want {
			return
		}
	}
	t.Fatalf("evidence rule %q not found in %#v", want, evidence)
}

// Field case (acme, 2026-09-23): GLM wrote a Windows path into tool-argument
// JSON with raw backslashes. The call was a read-only `ls`, yet the gateway
// could not decode it and the parse-rejected fail-safe blocked it under a
// destructive "block" policy.
func TestStructuredToolGateReadOnlyWindowsPathsAreNotFailSafeBlocked(t *testing.T) {
	policy := &agentguard.EffectivePolicy{
		ID: "policy-windows", PolicyVersion: "v-windows",
		Mode: agentguard.ModeAudit, ConfigSource: agentguard.ConfigSourceTenantPolicy,
		Destructive: &agentguard.DestructivePolicy{Mode: agentguard.ModeAudit, Action: agentguard.DestructiveActionBlock, ScopeType: "tenant"},
	}
	for _, raw := range []string{
		`{"command":"ls -la \"C:\Users\acme\Desktop\" && ls -la \"C:\Users\acme\Documents\""}`,
		`{"command":"ls -la \"C:\Users\acme\Desktop\\\" && ls -la \"C:\Users\acme\Documents\\\""}`,
		`{"command":"dir C:\work\ 2>nul", "description":"list the work dir"`,
	} {
		t.Run(raw, func(t *testing.T) {
			args, rejected := parseToolCallArguments(raw)
			got := evaluateStructuredToolCall(structuredToolCallInput{
				TenantID: "tenant_default", Protocol: "chat", SessionID: "session-win",
				RequestID: "req-win", ToolCallID: "call-bash", ToolName: "Bash", ToolType: "shell",
				Arguments: args, RawArguments: raw, ArgumentsParseRejected: rejected,
				Policy: policy, Mode: agentguard.ModeStrict,
			})
			if got.Decision.EffectiveDecision == agentguard.DecisionBlock || isDestructiveGateDecision(got.Decision) {
				t.Fatalf("read-only Windows command must not be blocked as destructive: rejected=%t %#v", rejected, got.Decision)
			}
		})
	}
}

func TestParseToolCallArgumentsRepairsRawWindowsBackslashes(t *testing.T) {
	args, rejected := parseToolCallArguments(`{"command":"ls -la \"C:\Users\x\"","n":"\u4e2d"}`)
	if rejected {
		t.Fatal("invalid escapes inside strings must be repaired, not rejected")
	}
	if args["command"] != `ls -la "C:\Users\x"` || args["n"] != "中" {
		t.Fatalf("repaired arguments = %#v", args)
	}
	if _, rejected := parseToolCallArguments(`{"command":`); !rejected {
		t.Fatal("truncated JSON must still be rejected")
	}
}

// 2.9.22：解析失败的兜底改由防护项 agent.parse_rejected 决定（原先跟删除与破坏卡片的阻断走）。
// 用例改为“该项配成阻断时照拦”；默认告警放行见 TestStructuredToolGateParseRejectedFailSafeRespectsDestructivePolicy。
func TestStructuredToolGateMalformedDestructiveCommandKeepsFailSafe(t *testing.T) {
	policy := &agentguard.EffectivePolicy{
		ID: "policy-keep", Mode: agentguard.ModeAudit, RuleMode: agentguard.ModeStrict, ConfigSource: agentguard.ConfigSourceTenantPolicy,
		Destructive: &agentguard.DestructivePolicy{Mode: agentguard.ModeAudit, Action: agentguard.DestructiveActionBlock, ScopeType: "tenant"},
		Protections: protection.Settings{"agent.parse_rejected": {Action: protection.ActionBlock}},
	}
	for _, raw := range []string{`{"command":"rm -rf \"C:\data\" && ("}`, `{"command":`} {
		args, rejected := parseToolCallArguments(raw)
		if raw == `{"command":` {
			raw = `{"command": "rm -rf /srv/data`
		}
		got := evaluateStructuredToolCall(structuredToolCallInput{
			TenantID: "tenant_default", Protocol: "chat", SessionID: "session-keep",
			RequestID: "req-keep", ToolCallID: "call-keep", ToolName: "Bash", ToolType: "shell",
			Arguments: args, RawArguments: raw, ArgumentsParseRejected: rejected,
			Policy: policy, Mode: agentguard.ModeStrict,
		})
		if got.Decision.EffectiveDecision != agentguard.DecisionBlock || got.Decision.Reason != destructiveParseRejectedFailSafeReason {
			t.Fatalf("malformed destructive command must keep the fail-safe (%s): %#v", raw, got.Decision)
		}
	}
}
