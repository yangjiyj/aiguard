package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/relay"
)

func governanceRuntimeHandler(t *testing.T, toolAction, behaviorAction string, record bool) (*ChatCompletionsHandler, *MockAuditWriter, *[]map[string]any) {
	t.Helper()
	logs := []map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/admin/v1/internal/tools/config":
			if toolAction == "" {
				_, _ = w.Write([]byte(`{"data":[]}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": []any{map[string]any{"id": "named-policy", "tenant_id": "tenant-1", "tool_name": r.URL.Query().Get("tool_name"), "tool_type": "system", "risk_level": "medium", "action": toolAction}}})
		case "/admin/v1/internal/agentguard/effective-policy":
			rules := []any{}
			if behaviorAction != "" {
				action := "audit"
				if behaviorAction == "block" {
					action = "block"
				}
				rules = append(rules, map[string]any{"id": "policy-center-system_command", "tool_pattern": "system.*", "action": action, "policy_center_action": behaviorAction, "enabled": true})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"id": "behavior-policy", "name": "behavior", "mode": "audit", "default_action": "allow", "rules": rules, "exceptions": []any{}, "destructive": map[string]any{"mode": "audit", "action": "record", "scope_type": "tenant"}, "config_source": "tenant_policy"}})
		case "/admin/v1/internal/tools/logs":
			var item map[string]any
			if err := json.NewDecoder(r.Body).Decode(&item); err != nil {
				t.Error(err)
			}
			logs = append(logs, item)
			w.WriteHeader(http.StatusCreated)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client := NewToolRiskClient(server.URL, "fixture-internal")
	client.runtimeCache.setSecurityAuditOnly(record)
	client.runtimeCache.setSemanticAgentEnabled(false)
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{cfg: &config.Config{SecurityAuditOnly: record, UpstreamStreaming: true, OutputSecurityMode: "stream_enforce"}, securityClient: &MockSecurityChecker{}, auditWriter: audit, toolRiskClient: client, agentGuardToolTypes: newAgentGuardToolTypeCache()}
	return h, audit, &logs
}

func governanceEnvelope() *modelrouter.RequestEnvelope {
	return &modelrouter.RequestEnvelope{RequestID: "governance-request", TenantID: "tenant-1", UserID: "user-1", SessionID: "session-1", EndpointType: "chat_completions", AgentType: "claude-code"}
}

func governanceCall() ToolCall {
	return ToolCall{ID: "call-governance", Type: "function", Function: ToolCallFunc{Name: "Bash", Arguments: `{"executable":"go","args":["test","./..."]}`}}
}

func TestGovernanceDefinitionDenialWaitsForActualProposedCall(t *testing.T) {
	h, audit, logs := governanceRuntimeHandler(t, "block", "", false)
	req := &ChatCompletionRequest{Tools: []ToolDef{{Type: "function", Function: ToolFunc{Name: "Bash", Parameters: json.RawMessage(`{"type":"object","properties":{"executable":{"type":"string"}}}`)}}}}
	if err := h.checkToolRisk(context.Background(), governanceEnvelope(), req); err != nil {
		t.Fatalf("unused definition blocked request: %v", err)
	}
	if len(*logs) != 1 || (*logs)[0]["event_kind"] != "definition_exposed" || (*logs)[0]["status"] != "observed" || len(audit.SecurityEventWrites) != 0 {
		t.Fatalf("definition falsely enforced or alerted: logs=%+v events=%+v", *logs, audit.SecurityEventWrites)
	}
	decision, err := h.applyAgentGuardToolDecisionResult(context.Background(), governanceEnvelope(), governanceCall(), nil, &AuditResult{}, 0)
	if err == nil || decision.EffectiveDecision != agentguard.DecisionBlock || decision.EffectiveReason != toolNamePolicyBlockReason {
		t.Fatalf("actual named denial lost: %+v err=%v", decision, err)
	}
	if len(*logs) != 2 || (*logs)[1]["event_kind"] != "invocation_proposed" || (*logs)[1]["execution_observed"] != false || (*logs)[1]["result_observed"] != false {
		t.Fatalf("wrong call fact: %+v", *logs)
	}
}

func TestGovernanceToolAllowAndAuditCannotOverrideBehaviorBlock(t *testing.T) {
	for _, toolAction := range []string{"allow", "audit"} {
		t.Run(toolAction, func(t *testing.T) {
			h, _, _ := governanceRuntimeHandler(t, toolAction, "block", false)
			decision, err := h.applyAgentGuardToolDecisionResult(context.Background(), governanceEnvelope(), governanceCall(), nil, &AuditResult{}, 0)
			if err == nil || decision.EffectiveDecision != agentguard.DecisionBlock {
				t.Fatalf("named %s erased behavior block: %+v err=%v", toolAction, decision, err)
			}
		})
	}
}

func TestGovernanceNamedDenialHonorsRecordCeiling(t *testing.T) {
	h, audit, logs := governanceRuntimeHandler(t, "block", "", true)
	decision, err := h.applyAgentGuardToolDecisionResult(context.Background(), governanceEnvelope(), governanceCall(), nil, &AuditResult{}, 0)
	if err != nil || decision.EffectiveDecision != agentguard.DecisionAudit || hasSecurityEvent(audit, "block") || hasSecurityEvent(audit, "alert") {
		t.Fatalf("record ceiling failed: %+v err=%v", decision, err)
	}
	if len(*logs) != 1 || (*logs)[0]["effective_decision"] != "audit" {
		t.Fatalf("record evidence=%+v", *logs)
	}
}

func TestGovernanceBehaviorRiskAlertIsDistinctAndDeduplicated(t *testing.T) {
	for _, behaviorAction := range []string{"record", "alert_allow"} {
		t.Run(behaviorAction, func(t *testing.T) {
			h, audit, logs := governanceRuntimeHandler(t, "", behaviorAction, false)
			call := governanceCall()
			call.Function.Arguments = `{"executable":"curl","args":["--version"]}`
			_, _, err := h.applyOutputSecurity(context.Background(), governanceEnvelope(), nil, destructiveChatResponse(t, "", call, call))
			if err != nil {
				t.Fatal(err)
			}
			alerts := 0
			for _, event := range audit.SecurityEventWrites {
				if event.ActionTaken == "alert" {
					alerts++
				}
			}
			want := 0
			if behaviorAction == "alert_allow" {
				want = 1
			}
			if alerts != want || len(*logs) != 1 {
				t.Fatalf("alerts=%d want=%d logs=%d", alerts, want, len(*logs))
			}
		})
	}
}

func TestGovernanceBenignCallDoesNotRaiseRiskAlert(t *testing.T) {
	h, audit, _ := governanceRuntimeHandler(t, "", "alert_allow", false)
	if _, err := h.applyAgentGuardToolDecisionResult(context.Background(), governanceEnvelope(), governanceCall(), nil, &AuditResult{}, 0); err != nil {
		t.Fatal(err)
	}
	if hasSecurityEvent(audit, "alert") {
		t.Fatal("benign parameters became a tool-name risk alert")
	}
}

func TestGovernanceConfiguredCriticalToolLabelDoesNotCreateBenignRiskAlert(t *testing.T) {
	h, audit, _ := governanceRuntimeHandler(t, "audit", "alert_allow", false)
	h.toolRiskClient.cache.set("tenant-1:Bash", &ToolRiskConfigResponse{ID: "critical-label", TenantID: "tenant-1", ToolName: "Bash", ToolType: "system", RiskLevel: "critical", Action: "audit"})
	decision, err := h.applyAgentGuardToolDecisionResult(context.Background(), governanceEnvelope(), governanceCall(), nil, &AuditResult{}, 0)
	if err != nil || decision.RiskLevel != "low" || decision.NotificationRequired || hasSecurityEvent(audit, "alert") {
		t.Fatalf("configured label became risk evidence: %+v err=%v", decision, err)
	}
}

// 2.9.22：删除与破坏配成“仅记录”时，抹不掉其他配置结论的阻断（受限文件、Skill 撤销、
// 配成阻断的密钥外发防护项、显式规则）；不再有不带 ConfiguredEnforcement 的“底线”阻断。
func TestGovernanceDestructiveRecordCannotEraseIndependentBlocks(t *testing.T) {
	policy := &agentguard.EffectivePolicy{Mode: agentguard.ModeAudit, Destructive: &agentguard.DestructivePolicy{Action: agentguard.DestructiveActionRecord, ScopeType: "tenant"}, ConfigSource: agentguard.ConfigSourceTenantPolicy}
	for _, base := range []agentguard.Decision{
		{RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock, ConfiguredEnforcement: true, RestrictedFileMatched: true, Reason: "restricted_file_pattern"},
		{RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock, ConfiguredEnforcement: true, Reason: "skill_revoked"},
		{RawDecision: agentguard.DecisionBlock, EffectiveDecision: agentguard.DecisionBlock, ConfiguredEnforcement: true, Reason: "high_confidence_secret_egress",
			ProtectionItem: "agent.secret_egress", ProtectionAction: "block"},
		{RawDecision: agentguard.DecisionAllow, EffectiveDecision: agentguard.DecisionBlock, ConfiguredEnforcement: true, MatchedRuleID: "policy-center-system_command", Reason: "command_allowlisted"},
	} {
		result := evaluateStructuredToolCall(structuredToolCallInput{ToolName: "Bash", ToolType: "system", Mode: agentguard.ModeStrict, BaseDecision: base,
			Arguments: map[string]any{"command": "rm -rf /srv/business-data"}, Policy: policy})
		if result.Decision.EffectiveDecision != agentguard.DecisionBlock {
			t.Fatalf("independent block erased: %+v", result.Decision)
		}
	}
	// 默认配置下密钥外发只告警（base 不是阻断），删除与破坏的“仅记录”照常生效。
	alerted := agentguard.Decision{RawDecision: agentguard.DecisionAudit, EffectiveDecision: agentguard.DecisionAudit, Reason: "high_confidence_secret_egress",
		ProtectionItem: "agent.secret_egress", ProtectionAction: "alert_allow", NotificationRequired: true}
	result := evaluateStructuredToolCall(structuredToolCallInput{ToolName: "Bash", ToolType: "system", Mode: agentguard.ModeStrict, BaseDecision: alerted,
		Arguments: map[string]any{"command": "rm -rf /srv/business-data"}, Policy: policy})
	if result.Decision.EffectiveDecision == agentguard.DecisionBlock || result.Decision.EffectiveDecision == agentguard.DecisionConfirm {
		t.Fatalf("default secret_egress must not turn a recorded destructive call into a block: %+v", result.Decision)
	}
}

func TestGovernanceOpenAIStreamNamedDeniedArgumentsNeverReachClient(t *testing.T) {
	h, _, logs := governanceRuntimeHandler(t, "block", "", false)
	recorder := httptest.NewRecorder()
	events := []relay.StreamEvent{
		{Type: relay.EventToolCallStart, Index: 0, ToolCall: &relay.ToolCall{ID: "call-governance", Name: "Bash", Index: 0}},
		{Type: relay.EventToolArgumentsDelta, Index: 0, Delta: `{"executable":"go","args":["test","./..."]}`, ToolCall: &relay.ToolCall{ID: "call-governance", Index: 0}},
		{Type: relay.EventMessageEnd, Index: 0, FinishReason: "tool_calls"},
	}
	attempted, err := h.tryLiveChatStream(context.Background(), recorder, governanceEnvelope(), &liveRelayCaller{reader: &liveRelayReader{events: events}}, []byte(`{"stream":true}`), time.Now(), "", &relay.CommitTracker{})
	if !attempted || err == nil || !strings.Contains(err.Error(), toolNamePolicyBlockReason) {
		t.Fatalf("stream did not deny the call: attempted=%t err=%v", attempted, err)
	}
	if strings.Contains(recorder.Body.String(), `"executable"`) || strings.Contains(recorder.Body.String(), `"tool_calls"`) {
		t.Fatalf("denied invocation reached stream: %s", recorder.Body.String())
	}
	if len(*logs) != 1 || (*logs)[0]["event_kind"] != "invocation_proposed" {
		t.Fatalf("stream did not evaluate call: %+v", *logs)
	}
}

func TestGovernanceNativeMessagesAndResponsesBlockNamedCallsBufferedAndSSE(t *testing.T) {
	for _, protocol := range []string{"messages", "responses"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", protocol, stream), func(t *testing.T) {
				chat, audit, logs := governanceRuntimeHandler(t, "block", "", false)
				call := governanceCall()
				var payload []byte
				var handler http.HandlerFunc
				var request *http.Request
				if protocol == "responses" {
					output := map[string]any{"id": "resp-governance", "object": "response", "status": "completed", "model": "gpt-5.6", "output": []any{map[string]any{"id": "item-1", "type": "function_call", "status": "completed", "call_id": call.ID, "name": call.Function.Name, "arguments": call.Function.Arguments}}, "usage": map[string]int{"input_tokens": 1, "output_tokens": 1, "total_tokens": 2}}
					raw, _ := json.Marshal(output)
					payload = raw
					if stream {
						payload = []byte("event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"resp-governance\",\"object\":\"response\",\"status\":\"in_progress\",\"output\":[]}}\n\n" + "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":" + string(raw) + "}\n\n")
					}
					resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{ID: "model-native", ProviderID: "provider-native", ModelName: "gpt-5.6-sol", UpstreamModelID: "gpt-5.6", ProviderType: "openai", ProviderBaseURL: "https://upstream.example/v1", Status: "active", ResponsesNative: true}}
					native := NewResponsesHandler(&config.Config{SecurityAuditOnly: false}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: payload}}, chat.toolRiskClient, nil)
					handler = native.Handler()
					request = nativeResponsesRequest(t, []byte(fmt.Sprintf(`{"model":"gpt-5.6-sol","input":"inspect","stream":%t}`, stream)))
					request = request.WithContext(setAuthInfo(request.Context(), "tenant-1", "project-1", "user-1", "key-1", "session-1"))
				} else {
					output := map[string]any{"id": "msg-governance", "type": "message", "role": "assistant", "model": "claude-test", "content": []any{map[string]any{"type": "tool_use", "id": call.ID, "name": call.Function.Name, "input": map[string]any{"executable": "go", "args": []string{"test", "./..."}}}}, "stop_reason": "tool_use", "usage": map[string]int{"input_tokens": 1, "output_tokens": 1}}
					raw, _ := json.Marshal(output)
					payload = raw
					if stream {
						payload = []byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg-governance\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-test\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":0}}}\n\n" +
							"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"call-governance\",\"name\":\"Bash\",\"input\":{}}}\n\n" +
							"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"executable\\\":\\\"go\\\",\\\"args\\\":[\\\"test\\\",\\\"./...\\\"]}\"}}\n\n" +
							"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n" +
							"event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":1}}\n\n" +
							"event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
					}
					resolver := &MockModelResolver{ModelRecord: &modelrouter.ModelRecord{ID: "model-native", ProviderID: "provider-native", ModelName: "claude-test", UpstreamModelID: "claude-test", ProviderType: "anthropic", ProviderBaseURL: "https://upstream.example/v1", Status: "active"}}
					native := NewMessagesHandler(&config.Config{SecurityAuditOnly: false}, resolver, &MockRateLimitChecker{}, &MockSecurityChecker{}, audit, &MockProviderAdapterFactory{MockProviderCaller: &MockProviderCaller{CallResponse: payload}}, chat.toolRiskClient, nil)
					handler = native.Handler()
					request = httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(fmt.Sprintf(`{"model":"claude-test","max_tokens":16,"stream":%t,"messages":[{"role":"user","content":"inspect"}]}`, stream)))
					request = request.WithContext(setAuthInfo(request.Context(), "tenant-1", "project-1", "user-1", "key-1", "session-1"))
				}
				recorder := httptest.NewRecorder()
				handler.ServeHTTP(recorder, request)
				if strings.Contains(recorder.Body.String(), `"executable"`) || strings.Contains(recorder.Body.String(), `"function_call"`) || strings.Contains(recorder.Body.String(), `"tool_use"`) {
					t.Fatalf("denied native call leaked: %s", recorder.Body.String())
				}
				proposed := false
				for _, entry := range *logs {
					if entry["event_kind"] == "invocation_proposed" && entry["effective_decision"] == "block" {
						proposed = true
					}
				}
				if !proposed {
					t.Fatalf("native path skipped call decision: status=%d logs=%+v body=%s", recorder.Code, *logs, recorder.Body.String())
				}
			})
		}
	}
}

func TestGovernanceMCPActualNamedDenialAndRecordCeiling(t *testing.T) {
	for _, record := range []bool{false, true} {
		t.Run(fmt.Sprintf("record=%t", record), func(t *testing.T) {
			env := newWS1Env(t, record, allowAll)
			env.handler.toolRiskClient.cache.set("tenant_test:demo__read", &ToolRiskConfigResponse{ID: "named-mcp", TenantID: "tenant_test", ToolName: "demo__read", ToolType: "mcp", RiskLevel: "medium", Action: "block"})
			response := env.post(t, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"read","arguments":{"path":"README.md"}}}`)
			if record {
				if rpcErrorCode(t, response.Body.String()) != 0 || atomic.LoadInt32(env.upstreamHits) != 1 {
					t.Fatalf("record mode blocked MCP call: %s", response.Body.String())
				}
			} else {
				if rpcErrorCode(t, response.Body.String()) != -32000 || atomic.LoadInt32(env.upstreamHits) != 0 {
					t.Fatalf("named MCP denial reached executor: %s", response.Body.String())
				}
			}
			env.mu.Lock()
			defer env.mu.Unlock()
			if len(env.toolLogs) == 0 {
				t.Fatal("actual MCP call audit absent")
			}
			if !record && env.toolLogs[0]["event_kind"] != "invocation_proposed" {
				t.Fatalf("denial claims execution: %+v", env.toolLogs)
			}
		})
	}
}
