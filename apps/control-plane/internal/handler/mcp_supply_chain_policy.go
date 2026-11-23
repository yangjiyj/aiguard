package handler

import "github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"

func buildMCPEffectivePolicyResponse(policy *repository.MCPPolicy, supply repository.MCPSupplyChainResolution) map[string]any {
	response := map[string]any{
		"matched":                 false,
		"policy_id":               "",
		"tool_id":                 supply.ToolID,
		"mode":                    string(repository.AgentGuardModeAudit),
		"action":                  string(repository.AgentGuardActionAudit),
		"supply_chain_status":     supply.Status,
		"supply_chain_reasons":    supply.Reasons,
		"supply_chain_revision":   supply.Revision,
		"structural_block":        supply.StructuralBlock,
		"server_admission_status": supply.ServerStatus,
		"route_hash":              supply.RouteHash,
		"approved_route_hash":     supply.ApprovedRouteHash,
		"approved_schema_hash":    supply.ApprovedSchemaHash,
		"schema_hash":             supply.SchemaHash,
		"tool_admission_status":   supply.ToolStatus,
		"server_admission_source": supply.ServerAdmissionSource,
		"tool_admission_source":   supply.ToolAdmissionSource,
	}
	if policy != nil {
		response["matched"] = true
		response["policy_id"] = policy.ID
		response["mode"] = policy.Mode
		response["action"] = policy.DefaultAction
		response["scope_type"] = policy.ScopeType
		response["priority"] = policy.Priority
		response["updated_at"] = policy.UpdatedAt
	}
	// 2.9.22：供应链发现不再在这里强改成 strict/block。网关按来源和原因定动作：管理员手动隔离、撤销
	// 照拦（按 *_admission_source 判断）；未准入、地址/Schema 变化、投毒、同名不一致、扫描不可用按 mcp.* 防护项处置。
	return response
}
