package handler

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityPostureGatewayReportAcceptsValidatedSafeControls(t *testing.T) {
	resetSemanticRuntimeReportsForTest()
	t.Cleanup(resetSemanticRuntimeReportsForTest)
	const body = `{"component":"gateway-core","node_id":"gateway-1","applied_revision":"fedcba9876543210fedcba9876543210","desired_revision":"0123456789abcdef0123456789abcdef","config_loaded":true,"posture":{"schema_version":1,"security_audit_only":true,"execution_mode_source":"deployment","deployment_audit_only":true,"guardrail_fail_closed":true,"capacity_fail_closed":false,"mcp_policy_fail_mode":"closed","skill_admission_fail_mode":"closed","forward_proxy_mode":"deny_unlisted","whitelist_fail_mode":"closed","mcp_gateway_enabled":true,"mcp_result_guard_enabled":true,"mcp_result_checker_wired":true,"mcp_cache_invalidator_wired":true,"mcp_cache_invalidator_running":true,"security_action_header_enabled":false,"file_dlp_enabled":true,"inspect_user_input":true,"inspect_model_output":true,"inspect_tool_results":true,"agentguard_wired":true,"skill_admission_wired":true,"reverse_stream_guard_wired":true}}`
	r := httptest.NewRequest(http.MethodPost, "/admin/v1/internal/security/semantic-runtime-report/gateway", strings.NewReader(body))
	w := httptest.NewRecorder()
	ReportSemanticRuntimeComponent(&Dependencies{}, semanticGatewayComponent)(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("safe consumer posture receipt rejected: status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestSecurityPostureProxyProbeRejectsUnknownNestedFields(t *testing.T) {
	client := &http.Client{Transport: inspectionRoundTripFunc(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"component":"proxy-server","config_component":"gateway-core","posture":{"unexpected_secret":"hidden"}}`))}, nil
	})}
	if _, err := probeProxyInspectionScope(context.Background(), client, "test-token"); err == nil {
		t.Fatal("unknown posture fields accepted")
	}
}
