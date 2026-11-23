package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/packages/shared-go/headeraudit"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

func TestSecurityPostureProxyReceiptPreservesSafeConsumerFacts(t *testing.T) {
	const raw = `{"component":"proxy-server","config_component":"gateway-core","node_id":"proxy-1","status":"applied","config_loaded":true,"fresh":true,"applied_revision":"0123456789abcdef0123456789abcdef","posture":{"schema_version":1,"security_audit_only":true,"deployment_audit_only":true,"capacity_fail_closed":false,"detection_fail_mode":"open","whitelist_fail_mode":"closed","inspection_queue_wired":true,"inspect_user_input":true,"inspect_model_output":true,"inspect_tool_results":true,"mode_source_verified":true,"tls_inspection_capable":true}}`
	var status inspectionscope.RuntimeStatus
	if err := json.Unmarshal([]byte(raw), &status); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, InspectionRuntimeStatusPath, nil)
	r.Header.Set(headeraudit.InternalTokenHeader, "test-secret")
	w := httptest.NewRecorder()
	InspectionRuntimeStatusHandler(fakeRuntimeStatus{status}, "test-secret", nil)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	facts, ok := body["posture"].(map[string]any)
	if !ok || facts["security_audit_only"] != true || facts["whitelist_fail_mode"] != "closed" || facts["inspection_queue_wired"] != true {
		t.Fatalf("runtime receipt lost safe consumed controls: %s", w.Body.String())
	}
}
