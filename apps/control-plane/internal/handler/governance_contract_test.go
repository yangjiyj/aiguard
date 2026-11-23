package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestGovernanceToolBatchRejectsAllInputBeforeStorage(t *testing.T) {
	user := &repository.User{ID: "governance-admin", TenantID: "tenant-a", Role: "platform_admin"}
	for _, body := range []string{
		`{"preserve_existing":true,"configs":[{"tool_name":"Read","tool_type":"file"},{"tool_name":"Bash","tool_type":"invalid"}]}`,
		`{"configs":[{"tool_name":"Read","tool_type":"file"},{"tool_name":"Read","tool_type":"file"}]}`,
		`{"configs":[{"tool_name":"Bash","tool_type":"system","action":"disable"}]}`,
		`{"configs":[{"tool_name":"Bash","tool_type":"system"}],"unexpected":true}`,
		`{"configs":[{"tool_name":"Bash","tool_type":"system"}]} {}`,
	} {
		recorder := httptest.NewRecorder()
		BatchUpsertToolRiskConfigs(&Dependencies{})(recorder, withBehaviorUser(http.MethodPost, "/tools/config/batch", body, user))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("invalid batch reached storage: status=%d", recorder.Code)
		}
	}
}

func TestGovernanceToolDecodeRejectsUnknownAndTrailingObjects(t *testing.T) {
	for _, body := range []string{`{"tool_name":"Read","tool_type":"file","unknown":true}`, `{"tool_name":"Read","tool_type":"file"}{}`, strings.Repeat("x", 2<<20)} {
		request := httptest.NewRequest(http.MethodPost, "/tools/config", strings.NewReader(body))
		var candidate ToolRiskConfigCreateRequest
		if err := decodeToolRiskRequest(httptest.NewRecorder(), request, &candidate); err == nil {
			t.Fatal("unbounded/unknown/trailing input accepted")
		}
	}
}

func TestGovernanceBehaviorProjectionReportsActualMatchScope(t *testing.T) {
	for _, definition := range policyCenterAgentBehaviorDefinitions {
		state := policyCenterAgentBehaviorState{Definition: definition, ConfiguredAction: "record", CurrentAction: "record", Health: "ok"}
		item := state.customerProjection()
		if item["evaluation_stage"] != "invocation_proposed" {
			t.Fatalf("wrong stage for %s", definition.Key)
		}
		if definition.ToolPattern != "" && (item["match_scope"] != "tool_category" || item["match_pattern"] != definition.ToolPattern) {
			t.Fatalf("whole-category match hidden: %+v", item)
		}
	}
}

func TestGovernanceBehaviorRuleActionIsDeliveredToGateway(t *testing.T) {
	items := agentGuardRulesFromJSON(map[string]any{"rules": []any{map[string]any{"id": "policy-center-system_command", "tool_pattern": "system.*", "action": "audit", "policy_center_action": "alert_allow", "enabled": true}}})
	if len(items) != 1 || items[0]["policy_center_action"] != "alert_allow" {
		t.Fatalf("execution action metadata lost: %+v", items)
	}
}
