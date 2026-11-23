package protection

// MCP 防护项（批次 3）。默认告警放行，不自动隔离；管理员手动隔离、撤销不在这里（照拦）。
// 原因码来自控制面供应链判定（mcp_supply_chain）、网关 tools/list 过滤和确认重放。
const (
	KeyMCPUnadmitted         = "mcp.unadmitted"
	KeyMCPDrift              = "mcp.drift"
	KeyMCPDescriptionPoison  = "mcp.description_poison"
	KeyMCPShadowDivergence   = "mcp.shadow_divergence"
	KeyMCPScanUnavailable    = "mcp.scan_unavailable"
	KeyMCPOversize           = "mcp.oversize"
	KeyMCPConfirmUnavailable = "mcp.confirm_unavailable"
	KeyMCPReplayChanged      = "mcp.replay_changed"
)

func init() {
	items = append(items,
		Item{Key: KeyMCPUnadmitted, Group: GroupMCP, Label: "未准入的服务或工具", Actions: racb, Default: ActionAlertAllow,
			Reasons: []string{"mcp_tool_unknown", "mcp_tool_removed", "mcp_server_unverified", "mcp_tool_unverified", "pending_administrator_review",
				"mcp_tool_not_approved", "mcp_server_not_approved"}},
		Item{Key: KeyMCPDrift, Group: GroupMCP, Label: "地址或 Schema 变化", Actions: racb, Default: ActionAlertAllow,
			Reasons: []string{"route_binding_mismatch", "schema_binding_mismatch", "gateway_route_binding_mismatch", "route_binding_changed",
				"rug_pull_schema_changed", "rug_pull_manifest_changed", "schema_hash_mismatch"}},
		Item{Key: KeyMCPDescriptionPoison, Group: GroupMCP, Label: "描述投毒", Actions: rab, Default: ActionAlertAllow,
			Reasons: []string{"description_poison"}},
		Item{Key: KeyMCPShadowDivergence, Group: GroupMCP, Label: "同名工具不一致", Actions: rab, Default: ActionAlertAllow,
			Reasons: []string{"shadow_schema_diverges"}},
		Item{Key: KeyMCPScanUnavailable, Group: GroupMCP, Label: "描述扫描超时或不可用", Actions: rab, Default: ActionAlertAllow,
			Reasons: []string{"description_scan_unavailable"},
			Params:  []Param{{Key: "timeout_seconds", Label: "超时（秒）", Kind: ParamInt, Default: 12, Min: 1, Max: 120}}},
		Item{Key: KeyMCPOversize, Group: GroupMCP, Label: "描述或 Schema 超长", Actions: rab, Default: ActionAlertAllow,
			Reasons: []string{"exceeds_admission_bounds"},
			Params: []Param{
				{Key: "max_name_bytes", Label: "名称上限（字节）", Kind: ParamInt, Default: 512, Min: 16, Max: 65536},
				{Key: "max_description_bytes", Label: "描述上限（字节）", Kind: ParamInt, Default: 8192, Min: 256, Max: 1 << 20},
				{Key: "max_schema_bytes", Label: "Schema 上限（字节）", Kind: ParamInt, Default: 65536, Min: 1024, Max: 4 << 20},
			}},
		Item{Key: KeyMCPConfirmUnavailable, Group: GroupMCP, Label: "确认单建不出来", Actions: rab, Default: ActionAlertAllow,
			Reasons: []string{"mcp_confirmation_unavailable"}},
		Item{Key: KeyMCPReplayChanged, Group: GroupMCP, Label: "批准后重放时环境变化", Actions: rab, Default: ActionAlertAllow,
			Reasons: []string{"approval_context_drift", "policy_runtime_unavailable"}},
	)
}
