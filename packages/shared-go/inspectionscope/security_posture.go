package inspectionscope

import "fmt"

const SecurityPostureSchemaVersion = 1

// These fixed DTOs contain consumed switches only. Credentials, URLs, and raw
// settings cannot enter the public posture response through runtime receipts.
type GatewaySecurityPosture struct {
	SchemaVersion               int    `json:"schema_version"`
	SecurityAuditOnly           *bool  `json:"security_audit_only"`
	ExecutionModeSource         string `json:"execution_mode_source"`
	DeploymentAuditOnly         *bool  `json:"deployment_audit_only"`
	GuardrailFailClosed         *bool  `json:"guardrail_fail_closed"`
	CapacityFailClosed          *bool  `json:"capacity_fail_closed"`
	MCPPolicyFailMode           string `json:"mcp_policy_fail_mode"`
	SkillAdmissionFailMode      string `json:"skill_admission_fail_mode"`
	ForwardProxyMode            string `json:"forward_proxy_mode"`
	WhitelistFailMode           string `json:"whitelist_fail_mode"`
	MCPGatewayEnabled           *bool  `json:"mcp_gateway_enabled"`
	MCPResultGuardEnabled       *bool  `json:"mcp_result_guard_enabled"`
	MCPResultCheckerWired       *bool  `json:"mcp_result_checker_wired"`
	MCPCacheInvalidatorWired    *bool  `json:"mcp_cache_invalidator_wired"`
	MCPCacheInvalidatorRunning  *bool  `json:"mcp_cache_invalidator_running"`
	SecurityActionHeaderEnabled *bool  `json:"security_action_header_enabled"`
	FileDLPEnabled              *bool  `json:"file_dlp_enabled"`
	InspectUserInput            *bool  `json:"inspect_user_input"`
	InspectModelOutput          *bool  `json:"inspect_model_output"`
	InspectToolResults          *bool  `json:"inspect_tool_results"`
	AgentGuardWired             *bool  `json:"agentguard_wired"`
	SkillAdmissionWired         *bool  `json:"skill_admission_wired"`
	ReverseStreamGuardWired     *bool  `json:"reverse_stream_guard_wired"`
}

type ProxySecurityPosture struct {
	SchemaVersion        int    `json:"schema_version"`
	SecurityAuditOnly    *bool  `json:"security_audit_only"`
	DeploymentAuditOnly  *bool  `json:"deployment_audit_only"`
	CapacityFailClosed   *bool  `json:"capacity_fail_closed"`
	DetectionFailMode    string `json:"detection_fail_mode"`
	WhitelistFailMode    string `json:"whitelist_fail_mode"`
	InspectionQueueWired *bool  `json:"inspection_queue_wired"`
	InspectUserInput     *bool  `json:"inspect_user_input"`
	InspectModelOutput   *bool  `json:"inspect_model_output"`
	InspectToolResults   *bool  `json:"inspect_tool_results"`
	ModeSourceVerified   *bool  `json:"mode_source_verified"`
	TLSInspectionCapable *bool  `json:"tls_inspection_capable"`
}

func PostureBool(value bool) *bool { return &value }

func validPostureFailureMode(mode string) bool { return mode == "open" || mode == "closed" }

func validatePostureBools(values ...*bool) error {
	for _, value := range values {
		if value == nil {
			return fmt.Errorf("security posture has a missing boolean")
		}
	}
	return nil
}

func (p *GatewaySecurityPosture) Validate() error {
	if p == nil || p.SchemaVersion != SecurityPostureSchemaVersion {
		return fmt.Errorf("unsupported gateway security posture schema")
	}
	if !validPostureFailureMode(p.MCPPolicyFailMode) || !validPostureFailureMode(p.SkillAdmissionFailMode) || !validPostureFailureMode(p.WhitelistFailMode) || (p.ForwardProxyMode != "deny_unlisted" && p.ForwardProxyMode != "tunnel_audit") {
		return fmt.Errorf("invalid gateway security posture mode")
	}
	if p.ExecutionModeSource != "signed" && p.ExecutionModeSource != "legacy" && p.ExecutionModeSource != "startup" && p.ExecutionModeSource != "deployment" {
		return fmt.Errorf("invalid gateway execution mode source")
	}
	if err := validatePostureBools(p.SecurityAuditOnly, p.DeploymentAuditOnly, p.GuardrailFailClosed, p.CapacityFailClosed,
		p.MCPGatewayEnabled, p.MCPResultGuardEnabled, p.MCPResultCheckerWired, p.MCPCacheInvalidatorWired, p.MCPCacheInvalidatorRunning,
		p.SecurityActionHeaderEnabled, p.FileDLPEnabled, p.InspectUserInput, p.InspectModelOutput, p.InspectToolResults,
		p.AgentGuardWired, p.SkillAdmissionWired, p.ReverseStreamGuardWired); err != nil {
		return err
	}
	if *p.DeploymentAuditOnly && !*p.SecurityAuditOnly {
		return fmt.Errorf("gateway posture contradicts deployment recording lock")
	}
	if (*p.DeploymentAuditOnly != (p.ExecutionModeSource == "deployment")) || (p.ExecutionModeSource == "startup" && !*p.SecurityAuditOnly) {
		return fmt.Errorf("gateway posture contradicts execution mode source")
	}
	return nil
}

func (p *ProxySecurityPosture) Validate() error {
	if p == nil || p.SchemaVersion != SecurityPostureSchemaVersion {
		return fmt.Errorf("unsupported proxy security posture schema")
	}
	if !validPostureFailureMode(p.DetectionFailMode) || !validPostureFailureMode(p.WhitelistFailMode) {
		return fmt.Errorf("invalid proxy security posture mode")
	}
	if err := validatePostureBools(p.SecurityAuditOnly, p.DeploymentAuditOnly, p.CapacityFailClosed, p.InspectionQueueWired,
		p.InspectUserInput, p.InspectModelOutput, p.InspectToolResults, p.ModeSourceVerified, p.TLSInspectionCapable); err != nil {
		return err
	}
	if *p.DeploymentAuditOnly && !*p.SecurityAuditOnly {
		return fmt.Errorf("proxy posture contradicts deployment recording lock")
	}
	return nil
}
