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

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 审查意见 3：非 MCP 协议的删除与破坏“确认”整条链。策略按控制面有效策略接口的真实下发形状
// （策略中心“删除与破坏”卡片选确认：租户范围、protocol 为空、模式取卡片默认 audit）给网关，
// 经 GetAgentGuardPolicy → convertAgentGuardPolicy → 结构化工具门 → chat 输出链路判定。
func destructiveConfirmChatHandler(t *testing.T, channel bool, protections string) (*ChatCompletionsHandler, *atomic.Int32, *atomic.Int32) {
	t.Helper()
	var confirmations, toolLogs atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/v1/internal/agentguard/effective-policy":
			if r.URL.Query().Get("protocol") != "chat" {
				t.Errorf("effective policy requested for protocol %q", r.URL.Query().Get("protocol"))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"data":{"protections":%s,"mode":"audit","default_action":"audit","fail_policy":"fail_open",`+
				`"confirm_channel_enabled":%t,"rules":[],"exceptions":[],"config_source":"tenant_policy","protocol":"",`+
				`"discardable_paths":[],"notify_channel_ids":[],"restricted_file_patterns":[],"restricted_file_action":"block",`+
				`"destructive":{"mode":"audit","action":"confirm","scope_type":"tenant","scope_ref":"","protocol":""}}}`, protections, channel)
		case "/admin/v1/internal/tools/config":
			_, _ = w.Write([]byte(`{"data":[]}`))
		case "/admin/v1/internal/tools/logs":
			toolLogs.Add(1)
			w.WriteHeader(http.StatusCreated)
		case "/admin/v1/internal/agentguard/confirmations":
			confirmations.Add(1)
			w.WriteHeader(http.StatusCreated)
		case "/admin/v1/internal/agentguard/confirmations/consume":
			_, _ = w.Write([]byte(`{"data":{"consumed":false}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	client := NewToolRiskClient(server.URL, "internal-secret")
	setToolGuardTestPosture(t, client, false, false)
	return &ChatCompletionsHandler{cfg: &config.Config{}, securityClient: &MockSecurityChecker{},
		auditWriter: &MockAuditWriter{}, toolRiskClient: client}, &confirmations, &toolLogs
}

func runDestructiveChat(t *testing.T, h *ChatCompletionsHandler) (ChatCompletionResponse, *AuditResult) {
	t.Helper()
	envelope := &modelrouter.RequestEnvelope{RequestID: "req-chat-confirm", TenantID: "tenant-1", UserID: "user-1", EndpointType: "chat"}
	call := ToolCall{ID: "call-rm", Type: "function", Function: ToolCallFunc{Name: "shell_command", Arguments: `{"command":"rm -rf /srv/isolated-fixture"}`}}
	secured, audit, err := h.applyOutputSecurity(context.Background(), envelope, nil, destructiveChatResponse(t, "", call))
	if err != nil {
		t.Fatalf("destructive chat call returned error: %v", err)
	}
	var response ChatCompletionResponse
	if err := json.Unmarshal(secured, &response); err != nil {
		t.Fatal(err)
	}
	return response, audit
}

func TestDestructiveConfirm2922ChatWithChannelCreatesConfirmationTicket(t *testing.T) {
	h, confirmations, _ := destructiveConfirmChatHandler(t, true, `{}`)
	response, audit := runDestructiveChat(t, h)
	if confirmations.Load() != 1 || audit.OutputAction != "block" || len(response.Choices[0].Message.ToolCalls) != 0 {
		t.Fatalf("chat + confirm card + channel must hold the call for confirmation: confirmations=%d audit=%+v response=%+v",
			confirmations.Load(), audit, response)
	}
	if !strings.Contains(response.Choices[0].Message.Content, "op_") {
		t.Fatalf("the notice must carry the operation id: %q", response.Choices[0].Message.Content)
	}
}

func TestDestructiveConfirm2922ChatWithoutChannelFollowsConfirmWithoutChannel(t *testing.T) {
	h, confirmations, _ := destructiveConfirmChatHandler(t, false, `{}`)
	response, audit := runDestructiveChat(t, h)
	if confirmations.Load() != 0 || audit.OutputAction == "block" || len(response.Choices[0].Message.ToolCalls) != 1 {
		t.Fatalf("no channel: agent.confirm_without_channel defaults to alert and allow: confirmations=%d audit=%+v", confirmations.Load(), audit)
	}
	h, confirmations, _ = destructiveConfirmChatHandler(t, false, `{"agent.confirm_without_channel":{"action":"block","params":{}}}`)
	response, audit = runDestructiveChat(t, h)
	if confirmations.Load() != 0 || audit.OutputAction != "block" || len(response.Choices[0].Message.ToolCalls) != 0 {
		t.Fatalf("no channel + confirm_without_channel=block must block: confirmations=%d audit=%+v", confirmations.Load(), audit)
	}
}

func TestConvertAgentGuardPolicy2922AcceptsNonMCPConfirm(t *testing.T) {
	var data agentGuardPolicyData
	raw := `{"mode":"audit","config_source":"tenant_policy","protocol":"","destructive":{"mode":"audit","action":"confirm","scope_type":"tenant","scope_ref":"","protocol":""}}`
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		t.Fatal(err)
	}
	policy := convertAgentGuardPolicy(&data)
	if policy.Destructive == nil || policy.Destructive.Action != "confirm" || policy.Mode != "audit" {
		t.Fatalf("a non-MCP confirm policy is valid now (was turned into a strict preset block): %+v", policy)
	}
}
