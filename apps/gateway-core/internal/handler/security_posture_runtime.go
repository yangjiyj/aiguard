package handler

import (
	"context"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/config"
	"github.com/yangjiyj/aiguard/packages/shared-go/inspectionscope"
)

// ConfigureSecurityPosture binds the report to the same initialized consumers
// used by requests. It is called before the background report loop starts.
func (c *ToolRiskClient) ConfigureSecurityPosture(cfg *config.Config, mcp *MCPProxyHandler, forward *ForwardProxyHandler) {
	if c == nil {
		return
	}
	c.postureProvider = func(ctx context.Context, runtime semanticRuntimeConfig) *inspectionscope.GatewaySecurityPosture {
		if cfg == nil || mcp == nil || forward == nil || runtime.Revision == "" || runtime.DesiredRevision == "" || len(runtime.SignedProjection) == 0 || runtime.InspectionPolicy == nil {
			return nil
		}
		policy := guardrailPolicy(ctx, c)
		auditOnly, modeSource := c.securityExecutionModeSnapshot()
		// 2.9.22（D7）：只有部署变量作初值真正生效时才算“部署记录模式”。
		deploymentRecord := modeSource == "deployment"
		return &inspectionscope.GatewaySecurityPosture{
			SchemaVersion:       inspectionscope.SecurityPostureSchemaVersion,
			SecurityAuditOnly:   inspectionscope.PostureBool(auditOnly),
			ExecutionModeSource: modeSource,
			DeploymentAuditOnly: inspectionscope.PostureBool(deploymentRecord),
			GuardrailFailClosed: inspectionscope.PostureBool(policy.FailClosedOnDetectionFailure),
			CapacityFailClosed:  inspectionscope.PostureBool(policy.FailClosedOnCapacity),
			MCPPolicyFailMode:   c.currentMCPPolicyFailMode(),
			// 2.9.22：准入服务不可用不再有部署级的 fail-closed，处置按防护项 skill.admission_unavailable。
			SkillAdmissionFailMode:      "open",
			ForwardProxyMode:            forward.runtimeForwardProxyMode(ctx),
			WhitelistFailMode:           forward.runtimeWhitelistFailMode(ctx),
			MCPGatewayEnabled:           inspectionscope.PostureBool(cfg.MCPGatewayEnabled),
			MCPResultGuardEnabled:       inspectionscope.PostureBool(cfg.MCPToolResultGuardEnabled),
			MCPResultCheckerWired:       inspectionscope.PostureBool(mcp.toolResultChecker != nil),
			MCPCacheInvalidatorWired:    inspectionscope.PostureBool(mcp.cacheInvalidatorWired.Load()),
			MCPCacheInvalidatorRunning:  inspectionscope.PostureBool(mcp.cacheInvalidatorRunning.Load()),
			SecurityActionHeaderEnabled: inspectionscope.PostureBool(cfg.SecurityActionHeaderEnabled(auditOnly)),
			FileDLPEnabled:              inspectionscope.PostureBool(runtime.FileContentDLPEnabled),
			InspectUserInput:            inspectionscope.PostureBool(runtime.InspectionPolicy.InspectUserInput),
			InspectModelOutput:          inspectionscope.PostureBool(runtime.InspectionPolicy.InspectModelOutput),
			InspectToolResults:          inspectionscope.PostureBool(runtime.InspectionPolicy.InspectToolResults),
			AgentGuardWired:             inspectionscope.PostureBool(mcp.toolRiskClient == c && forward.reverseProxy != nil),
			SkillAdmissionWired:         inspectionscope.PostureBool(c.skillAdmissionCache != nil),
			ReverseStreamGuardWired:     inspectionscope.PostureBool(forward.reverseProxy != nil),
		}
	}
}
