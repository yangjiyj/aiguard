package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 批次 2B：受限文件作用范围与例外在“用户消息提及的文件”环节也生效（原先这里不看例外）。
func restrictedScopeHandler(t *testing.T, scopes, exceptions string) *ChatCompletionsHandler {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/v1/internal/agentguard/effective-policy" {
			http.NotFound(w, r)
			return
		}
		scopeField := ""
		if scopes != "" {
			scopeField = `,"restricted_file_scopes":` + scopes
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"data":{"id":"p","mode":"audit","default_action":"allow","confirm_channel_enabled":true,"rules":[],"exceptions":%s,"restricted_file_patterns":["*.pdf"],"restricted_file_action":"block"%s}}`, exceptions, scopeField)
	}))
	t.Cleanup(server.Close)
	client := NewToolRiskClient(server.URL, "internal-secret")
	setToolGuardTestPosture(t, client, false, false)
	return &ChatCompletionsHandler{cfg: &config.Config{}, securityClient: &MockSecurityChecker{}, auditWriter: &MockAuditWriter{}, toolRiskClient: client}
}

func TestRestrictedFile2922UserMentionHonoursScopeAndExceptions(t *testing.T) {
	const exception = `[{"id":"e-contract","rule_id":"agent.restricted_file","target_pattern":"/home/u/合同.pdf","decision":"allow","expires_at":"2099-01-01T00:00:00Z"}]`
	for _, tc := range []struct {
		name, scopes, exceptions, path string
		blocked                        bool
	}{
		{"scopes not delivered keeps 2.9.21", "", `[]`, "/home/u/合同.pdf", true},
		{"user mention selected", `["user_mention"]`, `[]`, "/home/u/合同.pdf", true},
		{"user mention not selected", `["tool_call","proxy_output"]`, `[]`, "/home/u/合同.pdf", false},
		{"exception releases the named file", "", exception, "/home/u/合同.pdf", false},
		{"exception does not release another file", "", exception, "/home/u/报价.pdf", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := restrictedScopeHandler(t, tc.scopes, tc.exceptions)
			env := &modelrouter.RequestEnvelope{RequestID: "r", TenantID: "t", UserID: "u", AgentType: "openai-codex"}
			blocked, err := h.checkCodexMentionedFilesRestricted(context.Background(), env, []Message{userMessage(codexEnvelopeMsg(tc.path))})
			if blocked != tc.blocked || (err != nil) != tc.blocked {
				t.Fatalf("blocked=%v err=%v want blocked=%v", blocked, err, tc.blocked)
			}
		})
	}
}

func TestRestrictedFile2922ToolCallScopeFromEffectivePolicy(t *testing.T) {
	h := restrictedScopeHandler(t, `["user_mention"]`, `[]`)
	policy, err := h.toolRiskClient.GetAgentGuardPolicy(context.Background(), &modelrouter.RequestEnvelope{TenantID: "t", RequestID: "r"})
	if err != nil || policy == nil || policy.RestrictedFiles == nil {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	if policy.RestrictedFiles.Applies(agentguard.RestrictedFileScopeToolCall) || !policy.RestrictedFiles.Applies(agentguard.RestrictedFileScopeUserMention) {
		t.Fatalf("delivered scopes must be honoured: %+v", policy.RestrictedFiles)
	}
	if len(policy.RestrictedFiles.Scopes) != 1 {
		t.Fatalf("delivered scopes: %+v", policy.RestrictedFiles.Scopes)
	}
	cloned := cloneAgentGuardEffectivePolicy(policy)
	if cloned.RestrictedFiles == nil || len(cloned.RestrictedFiles.Scopes) != 1 {
		t.Fatalf("cloned scopes: %+v", cloned.RestrictedFiles)
	}
	cloned.RestrictedFiles.Scopes[0] = "tool_call"
	if policy.RestrictedFiles.Scopes[0] != "user_mention" {
		t.Fatal("cached policy scopes must not be shared with clones")
	}
}
