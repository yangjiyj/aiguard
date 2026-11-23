package handler

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestInternalToolLogRequestDecodesDestructiveLifecycleFields(t *testing.T) {
	var req InternalToolLogRequest
	err := json.Unmarshal([]byte(`{
		"tool_name":"shell_command",
		"tool_type":"system",
		"application_id":"application-1",
		"agent_type":"codex",
		"model":"gpt-5",
		"protocol":"responses",
		"operation_id":"op-public",
		"event_type":"tool_attempt_blocked",
		"risk_category":"destructive_change",
		"risk_subcategory":"filesystem_delete",
		"reason_summary":"deterministic_destructive_operation",
		"target_summary":"filesystem_delete:1-targets",
		"mode_default_action":"alert_allow",
		"custom_action":"block",
		"final_action":"block",
		"notification_required":true,
		"notification_status":"pending",
		"discardable_path_matched":false,
		"discardable_path_reason":"sensitive_target",
		"execution_forwarded":false
	}`), &req)
	if err != nil {
		t.Fatal(err)
	}
	value := reflect.ValueOf(req)
	for field, want := range map[string]string{
		"ApplicationID": "application-1", "AgentType": "codex", "Model": "gpt-5", "Protocol": "responses",
	} {
		got := value.FieldByName(field)
		if !got.IsValid() || got.Kind() != reflect.String || got.String() != want {
			t.Fatalf("context field %s = %#v, want %q", field, got, want)
		}
	}
	if req.OperationID != "op-public" || req.EventType != "tool_attempt_blocked" ||
		req.RiskCategory != "destructive_change" || req.RiskSubcategory != "filesystem_delete" ||
		req.ReasonSummary != "deterministic_destructive_operation" ||
		req.TargetSummary != "filesystem_delete:1-targets" {
		t.Fatalf("lifecycle identity/facts = %#v", req)
	}
	if req.ModeDefaultAction != "alert_allow" || req.CustomAction != "block" ||
		req.FinalAction != "block" || !req.NotificationRequired ||
		req.NotificationStatus != "pending" {
		t.Fatalf("governance/notification facts = %#v", req)
	}
	if req.DiscardablePathMatched || req.DiscardablePathReason != "sensitive_target" ||
		req.ExecutionForwarded {
		t.Fatalf("execution/discardable facts = %#v", req)
	}
}
