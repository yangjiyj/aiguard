package inspectionscope

import (
	"encoding/json"
	"testing"
)

func TestSecurityPostureProxyRuntimeRoundTrip(t *testing.T) {
	const raw = `{"component":"proxy-server","config_component":"gateway-core","posture":{"schema_version":1,"security_audit_only":true,"deployment_audit_only":true,"capacity_fail_closed":false,"detection_fail_mode":"open","whitelist_fail_mode":"closed","inspection_queue_wired":true,"inspect_user_input":true,"inspect_model_output":true,"inspect_tool_results":true,"mode_source_verified":true,"tls_inspection_capable":true}}`
	var status RuntimeStatus
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err := json.Unmarshal(encoded, &result); err != nil {
		t.Fatal(err)
	}
	facts, ok := result["posture"].(map[string]any)
	if !ok || facts["schema_version"] != float64(1) || facts["security_audit_only"] != true {
		t.Fatalf("runtime DTO dropped posture evidence: %s", encoded)
	}
}
