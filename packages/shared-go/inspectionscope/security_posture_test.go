package inspectionscope

import "testing"

func validTestGatewayPosture() *GatewaySecurityPosture {
	b := PostureBool
	return &GatewaySecurityPosture{SchemaVersion: 1, SecurityAuditOnly: b(false), ExecutionModeSource: "signed", DeploymentAuditOnly: b(false), GuardrailFailClosed: b(false), CapacityFailClosed: b(false),
		MCPPolicyFailMode: "closed", SkillAdmissionFailMode: "closed", ForwardProxyMode: "deny_unlisted", WhitelistFailMode: "closed", MCPGatewayEnabled: b(true), MCPResultGuardEnabled: b(true), MCPResultCheckerWired: b(false),
		MCPCacheInvalidatorWired: b(true), MCPCacheInvalidatorRunning: b(false), SecurityActionHeaderEnabled: b(false), FileDLPEnabled: b(false), InspectUserInput: b(true), InspectModelOutput: b(true), InspectToolResults: b(true), AgentGuardWired: b(true), SkillAdmissionWired: b(true), ReverseStreamGuardWired: b(true)}
}

func TestSecurityPostureGatewayRejectsIncompleteOrContradictoryFacts(t *testing.T) {
	for _, name := range []string{"valid", "nil", "old-version", "missing-bool", "invalid-failure-mode", "invalid-forward-mode", "invalid-source", "lock-contradiction", "source-contradiction", "startup-protect"} {
		t.Run(name, func(t *testing.T) {
			p := validTestGatewayPosture()
			switch name {
			case "nil":
				p = nil
			case "old-version":
				p.SchemaVersion = 0
			case "missing-bool":
				p.InspectToolResults = nil
			case "invalid-failure-mode":
				p.MCPPolicyFailMode = "sometimes"
			case "invalid-forward-mode":
				p.ForwardProxyMode = "allow-all"
			case "invalid-source":
				p.ExecutionModeSource = "guessed"
			case "lock-contradiction":
				p.DeploymentAuditOnly = PostureBool(true)
				p.ExecutionModeSource = "deployment"
			case "source-contradiction":
				p.ExecutionModeSource = "deployment"
			case "startup-protect":
				p.ExecutionModeSource = "startup"
			}
			if (p.Validate() == nil) != (name == "valid") {
				t.Fatalf("invalid posture validation: %s %+v", name, p)
			}
		})
	}
}
