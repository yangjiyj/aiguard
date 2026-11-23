package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 审查意见 3（控制面）：删除与破坏选“确认”不再限定 MCP。策略中心“删除与破坏”卡片（租户范围）
// 能选确认；别的卡片仍是 仅记录/告警放行/阻断。高级设置接口在租户、应用、智能体范围都能选确认，
// protocol 为空表示所有协议。没有 AgentGuard 策略的租户确认通道照实下发。
func TestPolicyCenterDestructiveCard2922AcceptsConfirm(t *testing.T) {
	deps, operationRepo, _, user := consistencySensitiveFixture()
	item := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorDestructive)
	if !reflect.DeepEqual(item["allowed_actions"], []any{"record", "alert_allow", "confirm", "block"}) {
		t.Fatalf("the destructive card offers confirm: %#v", item["allowed_actions"])
	}
	rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorDestructive, map[string]any{"action": "confirm", "version": item["version"]})
	if rec.Code != http.StatusOK || operationRepo.saved.Action != "confirm" {
		t.Fatalf("confirm on the destructive card: status=%d body=%s saved=%+v", rec.Code, rec.Body.String(), operationRepo.saved)
	}
	fresh := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorDestructive)
	if fresh["health"] != "ok" || fresh["configured_action"] != "confirm" || fresh["current_action"] != "confirm" {
		t.Fatalf("a saved confirm is an ordinary card action now: %#v", fresh)
	}

	system := consistencyBehaviorItem(t, deps, user, policyCenterAgentBehaviorSystem)
	if !reflect.DeepEqual(system["allowed_actions"], []any{"record", "alert_allow", "block"}) {
		t.Fatalf("other cards keep their three actions: %#v", system["allowed_actions"])
	}
	if rec := consistencyPut(t, deps, user, policyCenterAgentBehaviorSystem, map[string]any{"action": "confirm", "version": system["version"]}); rec.Code != http.StatusBadRequest {
		t.Fatalf("confirm is not offered on other cards: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAgentOperationAPI2922ConfirmForAllProtocols(t *testing.T) {
	for _, raw := range []string{
		`{"scope_type":"tenant","mode":"audit","action":"confirm","version":1}`,
		`{"scope_type":"application","scope_ref":"app-chat","mode":"strict","action":"confirm","version":1}`,
		`{"scope_type":"agent","scope_ref":"mcp-client","mode":"strict","action":"confirm","protocol":"mcp","version":1}`,
	} {
		if _, err := decodeAgentOperationPolicyRequest(strings.NewReader(raw)); err != nil {
			t.Fatalf("confirm rejected: %s: %v", raw, err)
		}
	}
	if _, err := decodeAgentOperationPolicyRequest(strings.NewReader(`{"scope_type":"tenant","mode":"audit","action":"confirm","protocol":"chat","version":1}`)); err == nil {
		t.Fatal("protocol stays empty (all protocols) or mcp")
	}
}

func TestInternalEffectivePolicy2922ConfirmChannelWithoutAgentGuardPolicy(t *testing.T) {
	for _, protocol := range []string{"chat", "responses", "mcp"} {
		operationRepo := &fakeEffectiveAgentOperationRepo{effective: &repository.AgentOperationEffectivePolicy{
			Mode: "audit", Action: "confirm", ScopeType: "tenant", ConfigSource: "tenant_policy",
		}}
		deps := &Dependencies{AgentGuardPolicyRepo: newFakeAgentGuardPolicyRepo(), AgentOperationRepo: operationRepo}
		req := withAgentGuardUser(httptest.NewRequest(http.MethodGet, "/admin/v1/internal/agentguard/effective-policy?protocol="+protocol, nil))
		req.Header.Set("X-Tenant-ID", "tenant-a")
		rec := httptest.NewRecorder()
		GetInternalAgentGuardEffectivePolicy(deps)(rec, req)
		var response struct {
			Data struct {
				ConfirmChannelEnabled bool `json:"confirm_channel_enabled"`
				Destructive           struct {
					Action string `json:"action"`
				} `json:"destructive"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if !response.Data.ConfirmChannelEnabled || response.Data.Destructive.Action != "confirm" {
			t.Fatalf("%s: tenants without an AgentGuard policy still have the console confirmation channel: %s", protocol, rec.Body.String())
		}
	}
}
