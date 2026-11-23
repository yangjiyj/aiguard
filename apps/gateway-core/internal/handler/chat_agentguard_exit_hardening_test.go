package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

func TestChatAgentGuardFinalExitHonorsCurrentPosture(t *testing.T) {
	for _, tc := range []struct {
		name, action, tool, arguments string
	}{
		{"configured block", "block", "WebSearch", `{}`},
		{"configured confirm", "confirm", "WebSearch", `{}`},
		{"metadata floor", "audit", "network.get", `{"url":"http://169.254.169.254/latest/meta-data/"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			var client *ToolRiskClient
			var postureChanges, confirmationWrites atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/admin/v1/internal/agentguard/effective-policy":
					_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{
						"id": "posture-policy", "mode": "strict", "default_action": "audit", "confirm_channel_enabled": true,
						"rules": []map[string]any{{"id": "configured-rule", "tool_pattern": tc.tool, "action": tc.action, "enabled": true}},
					}})
				case "/admin/v1/internal/tools/config":
					// A signed runtime refresh can reach Record after analysis and before the final exit.
					client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
						Revision: strings.Repeat("1", 32), SecurityAuditOnly: true, SecurityExecutionModeManaged: true,
					})
					postureChanges.Add(1)
					_, _ = w.Write([]byte(`{"data":[]}`))
				case "/admin/v1/internal/tools/logs":
					w.WriteHeader(http.StatusCreated)
				default:
					if r.Method == http.MethodPost && strings.Contains(r.URL.Path, "confirmations") && !strings.Contains(r.URL.Path, "consume") {
						confirmationWrites.Add(1)
					}
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			client = NewToolRiskClient(server.URL, "internal")
			client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
				Revision: strings.Repeat("0", 32), SecurityAuditOnly: false, SecurityExecutionModeManaged: true,
			})
			h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, auditWriter: &MockAuditWriter{}}
			body := chatAgentGuardExitResponse(t, tc.tool, tc.arguments)
			secured, audit, err := h.applyOutputSecurity(context.Background(), &modelrouter.RequestEnvelope{TenantID: "tenant", RequestID: "request"}, nil, body)
			if err != nil {
				t.Fatalf("current Record posture must forward a previously strict tool verdict: %v", err)
			}
			var response ChatCompletionResponse
			if err := json.Unmarshal(secured, &response); err != nil || len(response.Choices) != 1 || len(response.Choices[0].Message.ToolCalls) != 1 {
				t.Fatalf("Record posture must preserve the tool call: body=%s err=%v", secured, err)
			}
			if postureChanges.Load() != 1 || confirmationWrites.Load() != 0 || audit.OutputAction != "audit" {
				t.Fatalf("Record exit must record without creating confirmation: changes=%d confirmations=%d audit=%+v", postureChanges.Load(), confirmationWrites.Load(), audit)
			}
		})
	}
}

func TestChatAgentGuardPolicyFailureHonorsExplicitFailurePolicy(t *testing.T) {
	for _, tc := range []struct {
		name, arguments        string
		closed, record         bool
		wantUnavailable, floor bool
	}{
		{"closed rejects unavailable policy", `{}`, true, false, true, false},
		{"open forwards with gap", `{}`, false, false, false, false},
		{"Record never rejects", `{}`, true, true, false, false},
		// 2.9.22：策略拉不到时防护项取注册表默认（告警放行），元数据命中不再单独阻断：
		// open 照常放行并记缺口，closed 按策略不可用拒绝。
		{"open metadata hit follows default protection", `{"url":"http://169.254.169.254/latest/meta-data/"}`, false, false, false, false},
		{"closed metadata hit rejects as unavailable", `{"url":"http://169.254.169.254/latest/meta-data/"}`, true, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", "false")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/admin/v1/internal/agentguard/effective-policy":
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
				case "/admin/v1/internal/tools/config":
					_, _ = w.Write([]byte(`{"data":[]}`))
				case "/admin/v1/internal/tools/logs":
					w.WriteHeader(http.StatusCreated)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()
			client := NewToolRiskClient(server.URL, "internal")
			client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
				Revision: strings.Repeat("0", 32), SecurityAuditOnly: tc.record, SecurityExecutionModeManaged: true,
				GuardrailFailClosedEnabled: tc.closed,
			})
			audit := &MockAuditWriter{}
			h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, auditWriter: audit}
			body := chatAgentGuardExitResponse(t, "network.get", tc.arguments)
			secured, result, err := h.applyOutputSecurity(context.Background(), &modelrouter.RequestEnvelope{TenantID: "tenant", RequestID: "request"}, nil, body)
			if isGuardrailDetectionUnavailable(err) != tc.wantUnavailable || (err != nil) != (tc.wantUnavailable || tc.floor) {
				t.Fatalf("policy failure must honor explicit mode while retaining independent floor: err=%v unavailable=%t wantUnavailable=%t floor=%t", err, isGuardrailDetectionUnavailable(err), tc.wantUnavailable, tc.floor)
			}
			if !tc.wantUnavailable && !tc.floor && len(secured) == 0 {
				t.Fatal("open/Record policy failure must forward")
			}
			if result == nil || result.ResponseMetadata == nil || result.ResponseMetadata["tool_policy_coverage_gap"] != true {
				t.Fatalf("every policy failure must expose the coverage gap: %+v", result)
			}
			structuredGap := false
			for _, finding := range result.OutputFindings {
				if finding["type"] == "coverage_gap" {
					structuredGap = true
				}
			}
			if !structuredGap {
				t.Fatalf("policy failure must preserve structured coverage evidence: %+v", result.OutputFindings)
			}
			found := false
			for _, event := range audit.SecurityEventWrites {
				if event.ActionTaken == agentGuardPolicyLoadFailureReason && strings.Contains(event.Summary, "coverage_gap=true") {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing policy failure coverage gap audit: %+v", audit.SecurityEventWrites)
			}
		})
	}
}

func TestChatAgentGuardPolicyFailureDoesNotOverrideSkillAdmissionFailOpen(t *testing.T) {
	t.Setenv("SECURITY_AUDIT_ONLY", "false")
	t.Setenv("SKILL_ADMISSION_FAIL_MODE", "open")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			_, _ = w.Write([]byte(`{"data":{"mode":"strict","default_action":"audit","rules":[],"exceptions":[]}}`))
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			w.WriteHeader(http.StatusCreated)
		default:
			http.Error(w, "admission unavailable", http.StatusServiceUnavailable)
		}
	}))
	defer server.Close()
	client := NewToolRiskClient(server.URL, "internal")
	client.runtimeCache.setSemanticConfig(semanticRuntimeConfig{
		Revision: strings.Repeat("0", 32), SecurityAuditOnly: false, SecurityExecutionModeManaged: true,
		GuardrailFailClosedEnabled: true,
	})
	audit := &MockAuditWriter{}
	h := &ChatCompletionsHandler{cfg: &config.Config{}, toolRiskClient: client, auditWriter: audit}
	body := chatAgentGuardExitResponse(t, "use_skill", `{"skill":"pdf","version":"1","bundle_hash":"`+strings.Repeat("a", 64)+`"}`)
	secured, _, err := h.applyOutputSecurity(context.Background(), &modelrouter.RequestEnvelope{TenantID: "tenant", RequestID: "request"}, nil, body)
	if err != nil || len(secured) == 0 {
		t.Fatalf("successful tool policy lookup must not override Skill's explicit fail-open: err=%v body=%s", err, secured)
	}
}

func chatAgentGuardExitResponse(t *testing.T, tool, arguments string) []byte {
	t.Helper()
	return mustMarshalChatResponse(t, ChatCompletionResponse{
		Choices: []Choice{{Message: ChoiceMessage{Role: "assistant", ToolCalls: []ToolCall{{
			ID: "call", Type: "function", Function: ToolCallFunc{Name: tool, Arguments: arguments},
		}}}, FinishReason: "tool_calls"}},
	})
}
