package repository

import "strings"

// W1 1.2：非工具目标（resource/prompt/method）只继承服务器级供应链结论。
// 工具级准入（unknown/removed/tool_*、schema 绑定）按 tools/list 清单建档，
// 对 resources/read、prompts/get 等不适用；把它们套上会让所有非工具方法被「未知工具」结构阻断，
// 违反「管理员配了 block 才拦」。

// MCPServerLevelSupplyChain 从解析结果中只保留服务器级结构阻断（隔离/撤销/路由绑定不一致）。
func MCPServerLevelSupplyChain(in MCPSupplyChainResolution) MCPSupplyChainResolution {
	out := in
	out.ToolID = ""
	out.ToolStatus = ""
	out.ToolAdmissionSource = ""
	out.SchemaHash = ""
	out.ApprovedSchemaHash = ""
	var reasons []string
	for _, reason := range in.Reasons {
		switch reason {
		case "mcp_server_revoked", "mcp_server_quarantined", "mcp_server_unverified", "route_binding_mismatch":
			reasons = append(reasons, reason)
		}
	}
	switch in.ServerStatus {
	case "revoked", "quarantined":
		out.Status = in.ServerStatus
		out.StructuralBlock = true
		// 带上服务自己的原因：系统隔离时网关按它对应的 mcp.* 防护项处置；是不是管理员处置看 ServerAdmissionSource。
		reasons = []string{"mcp_server_" + in.ServerStatus}
		if strings.TrimSpace(in.ServerReason) != "" {
			reasons = append(reasons, in.ServerReason)
		}
	default:
		out.StructuralBlock = false
		out.Status = "not_applicable"
		for _, reason := range reasons {
			if reason == "route_binding_mismatch" {
				out.StructuralBlock = true
				out.Status = "quarantined"
			}
		}
	}
	if !out.StructuralBlock {
		reasons = nil
	}
	out.Reasons = nonNilStrings(reasons)
	return out
}
