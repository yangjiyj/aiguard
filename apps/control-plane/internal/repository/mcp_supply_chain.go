package repository

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/mcpadmission"
	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
	"github.com/jackc/pgx/v5"
)

var ErrMCPAdmissionSnapshotConflict = errors.New("MCP admission snapshot changed")

type MCPSupplyChainSyncInput struct {
	TenantID         string
	ServerID         string
	ManifestHash     string
	ManifestSnapshot json.RawMessage
	ProtocolVersion  string
	// CapabilityPatch 是同步协商产物（auto 探测到的 transport、前向兼容的原始协议版本等），
	// 以 jsonb 合并方式写入 capabilities_json；不含任何密钥。nil/空表示不合并。
	CapabilityPatch         map[string]interface{}
	Tools                   []*MCPTool
	DescriptionScanComplete bool
	// Protections 是租户的防护项设置：mcp.* 项设为阻断时同步照旧自动隔离，其余只打标记。
	Protections protection.Settings
}

type MCPSupplyChainSyncResult struct {
	ServerStatus            string   `json:"server_status"`
	ServerReason            string   `json:"server_reason,omitempty"`
	ApprovedCount           int      `json:"approved_tool_count"`
	QuarantinedCount        int      `json:"quarantined_tool_count"`
	RevokedCount            int      `json:"revoked_tool_count"`
	RemovedCount            int      `json:"removed_tool_count"`
	Reasons                 []string `json:"reasons"`
	DescriptionScanComplete bool     `json:"description_scan_complete"`
}

type MCPAdmissionMutation struct {
	AssetType string `json:"asset_type"`
	ID        string `json:"id"`
	Status    string `json:"status"`
	Hash      string `json:"hash"`
	Reason    string `json:"reason,omitempty"`
	RouteHash string `json:"route_hash,omitempty"`
	Revision  int64  `json:"revision"`
}

type MCPSupplyChainResolution struct {
	Status          string   `json:"status"`
	Reasons         []string `json:"reasons"`
	Revision        string   `json:"revision"`
	StructuralBlock bool     `json:"structural_block"`
	ToolID          string   `json:"tool_id,omitempty"`
	ServerStatus    string   `json:"server_status"`
	// ServerReason 是服务自己的隔离/撤销原因（系统隔离时网关按它对应的 mcp.* 防护项处置）。
	ServerReason string `json:"server_reason,omitempty"`
	// ServerAdmissionSource/ToolAdmissionSource 是隔离、撤销的来源（system 或 administrator，按
	// admission_reviewed_by 折算，见 mcpadmission）：网关据此区分管理员手动处置（照拦）和系统自动隔离。
	ServerAdmissionSource string `json:"server_admission_source,omitempty"`
	ToolAdmissionSource   string `json:"tool_admission_source,omitempty"`
	ToolStatus            string `json:"tool_status"`
	RouteHash             string `json:"route_hash"`
	ApprovedRouteHash     string `json:"approved_route_hash"`
	ApprovedSchemaHash    string `json:"approved_schema_hash"`
	SchemaHash            string `json:"schema_hash"`
}

type mcpToolAdmissionRecord struct {
	ID                 string
	SchemaHash         string
	Status             string
	ApprovedSchemaHash string
	ApprovedSnapshot   []byte
	QuarantineReason   string
	QuarantinedAt      *time.Time
	ReviewedBy         string
	ReviewedAt         *time.Time
	Revision           int64
	Removed            bool
	// ApprovedPoisonFlags 是管理员批准时工具已有的投毒标记：Schema 没变、标记也没新增时不打回。
	ApprovedPoisonFlags []string
}

type mcpAdmissionDecision struct {
	Status string
	Reason string
}

func validMCPAdmissionMutation(status string) bool {
	switch status {
	case "approved", "quarantined", "revoked":
		return true
	default:
		return false
	}
}

// decideMCPToolAdmission 给同步到的工具定准入状态。管理员手动隔离、撤销保留；投毒、同名
// 不一致、Schema 变化默认只打标记（未准入工具把发现原因写进 quarantine_reason，已批准工具保持
// 批准，Schema 变化由网关按 schema_binding_mismatch 处置），对应 mcp.* 防护项设为阻断时才像
// 2.9.21 那样自动隔离。已批准且 Schema 没变的工具，批准时已有的投毒标记不再打回。
func decideMCPToolAdmission(previous *mcpToolAdmissionRecord, incoming *MCPTool, divergentShadow bool, settings protection.Settings) mcpAdmissionDecision {
	if previous != nil {
		switch previous.Status {
		case "revoked":
			return mcpAdmissionDecision{Status: "revoked", Reason: previous.QuarantineReason}
		case "quarantined":
			return mcpAdmissionDecision{Status: "quarantined", Reason: previous.QuarantineReason}
		}
	}
	approved := previous != nil && previous.Status == "approved"
	blocks := func(key string) bool { return settings.ActionFor(key) == protection.ActionBlock }
	if incoming != nil && len(incoming.PoisonFlags) > 0 {
		alreadyApproved := approved && previous.SchemaHash == incoming.SchemaHash &&
			mcpFlagsSubset(incoming.PoisonFlags, previous.ApprovedPoisonFlags)
		if !alreadyApproved && blocks(protection.KeyMCPDescriptionPoison) {
			return mcpAdmissionDecision{Status: "quarantined", Reason: "description_poison"}
		}
		if !approved {
			return mcpAdmissionDecision{Status: "unverified", Reason: "description_poison"}
		}
	}
	if approved && previous.SchemaHash != "" && incoming != nil && incoming.SchemaHash != previous.SchemaHash &&
		blocks(protection.KeyMCPDrift) {
		return mcpAdmissionDecision{Status: "quarantined", Reason: "rug_pull_schema_changed"}
	}
	if divergentShadow {
		if blocks(protection.KeyMCPShadowDivergence) {
			return mcpAdmissionDecision{Status: "quarantined", Reason: "shadow_schema_diverges"}
		}
		if !approved {
			return mcpAdmissionDecision{Status: "unverified", Reason: "shadow_schema_diverges"}
		}
		// 已批准工具保持批准，把发现记在 quarantine_reason 里，解析时交给网关按防护项告警。
		return mcpAdmissionDecision{Status: "approved", Reason: "shadow_schema_diverges"}
	}
	if previous == nil || previous.Status == "" || previous.Status == "unverified" {
		return mcpAdmissionDecision{Status: "unverified", Reason: "pending_administrator_review"}
	}
	return mcpAdmissionDecision{Status: "approved"}
}

// mcpFlagsSubset 判断 flags 是否都在 approved 里。
func mcpFlagsSubset(flags, approved []string) bool {
	known := map[string]bool{}
	for _, flag := range approved {
		known[flag] = true
	}
	for _, flag := range flags {
		if !known[flag] {
			return false
		}
	}
	return true
}

// mcpFindingReasons 是同步时写进未准入工具 quarantine_reason 的发现原因，随解析结果下发给网关。
var mcpFindingReasons = map[string]bool{
	"description_poison": true, "shadow_schema_diverges": true, "description_scan_unavailable": true,
}

func mcpToolDefinitionSnapshot(tool *MCPTool) []byte {
	if tool == nil {
		return []byte("{}")
	}
	value := map[string]any{
		"tool_name": tool.ToolName, "description": tool.Description,
		"input_schema": tool.InputSchema, "schema_hash": tool.SchemaHash,
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return []byte("{}")
	}
	return raw
}

func mcpFallbackManifestSnapshot(tools []*MCPTool) []byte {
	type item struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		InputSchema map[string]any `json:"inputSchema"`
		SchemaHash  string         `json:"schema_hash"`
	}
	items := make([]item, 0, len(tools))
	for _, tool := range tools {
		if tool == nil || tool.ToolName == "" {
			continue
		}
		items = append(items, item{Name: tool.ToolName, Description: tool.Description, InputSchema: tool.InputSchema, SchemaHash: tool.SchemaHash})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	raw, _ := json.Marshal(items)
	return raw
}

func normalizeMCPManifestSnapshot(snapshot json.RawMessage, tools []*MCPTool) []byte {
	if len(snapshot) > 0 && json.Valid(snapshot) {
		var value any
		if err := json.Unmarshal(snapshot, &value); err == nil {
			raw, _ := json.Marshal(value)
			return raw
		}
	}
	return mcpFallbackManifestSnapshot(tools)
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func appendUniqueMCPReason(reasons []string, reason string) []string {
	if reason == "" {
		return reasons
	}
	for _, current := range reasons {
		if current == reason {
			return reasons
		}
	}
	return append(reasons, reason)
}

func resolveMCPSupplyChainState(serverStatus, serverReason string, serverRevision int64, toolStatus, toolReason string, toolRevision int64, removed, toolFound bool, toolID string) MCPSupplyChainResolution {
	resolution := MCPSupplyChainResolution{
		Status: "approved", ServerStatus: serverStatus, ToolStatus: toolStatus, ToolID: toolID,
		Revision: mcpSupplyChainRevision(serverRevision, toolRevision, serverStatus, toolStatus),
	}
	if !toolFound {
		resolution.Status, resolution.StructuralBlock = "unknown", true
		resolution.Reasons = []string{"mcp_tool_unknown"}
		return resolution
	}
	if removed {
		resolution.Status, resolution.StructuralBlock = "removed", true
		resolution.Reasons = []string{"mcp_tool_removed"}
		return resolution
	}
	if serverStatus == "revoked" || toolStatus == "revoked" {
		resolution.Status, resolution.StructuralBlock = "revoked", true
		if serverStatus == "revoked" {
			resolution.Reasons = append(resolution.Reasons, "mcp_server_revoked")
			resolution.Reasons = appendUniqueMCPReason(resolution.Reasons, serverReason)
		}
		if toolStatus == "revoked" {
			resolution.Reasons = append(resolution.Reasons, "mcp_tool_revoked")
			resolution.Reasons = appendUniqueMCPReason(resolution.Reasons, toolReason)
		}
		return resolution
	}
	if serverStatus == "quarantined" || toolStatus == "quarantined" {
		resolution.Status, resolution.StructuralBlock = "quarantined", true
		if serverStatus == "quarantined" {
			resolution.Reasons = append(resolution.Reasons, "mcp_server_quarantined")
			resolution.Reasons = appendUniqueMCPReason(resolution.Reasons, serverReason)
		}
		if toolStatus == "quarantined" {
			resolution.Reasons = append(resolution.Reasons, "mcp_tool_quarantined")
			resolution.Reasons = appendUniqueMCPReason(resolution.Reasons, toolReason)
		}
		return resolution
	}
	if serverStatus == "approved" && toolStatus == "approved" && mcpFindingReasons[toolReason] {
		// 已批准工具上的系统发现（如同名不一致）：保持批准，原因下发给网关按 mcp.* 防护项处置。
		resolution.StructuralBlock = true
		resolution.Reasons = append(resolution.Reasons, toolReason)
	}
	if serverStatus != "approved" || toolStatus != "approved" {
		resolution.Status, resolution.StructuralBlock = "unverified", true
		if serverStatus != "approved" {
			resolution.Reasons = append(resolution.Reasons, "mcp_server_unverified")
		}
		if toolStatus != "approved" {
			resolution.Reasons = append(resolution.Reasons, "mcp_tool_unverified")
			if mcpFindingReasons[toolReason] {
				resolution.Reasons = appendUniqueMCPReason(resolution.Reasons, toolReason)
			}
		}
	}
	return resolution
}

func mcpSupplyChainRevision(serverRevision, toolRevision int64, serverStatus, toolStatus string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%d:%s", serverRevision, serverStatus, toolRevision, toolStatus)))
	return "mcpsc_" + hex.EncodeToString(sum[:8])
}

func (r *MCPToolsRepository) ResolveMCPSupplyChain(ctx context.Context, tenantID, serverID, toolName string) (MCPSupplyChainResolution, error) {
	if r == nil || r.db == nil || tenantID == "" || serverID == "" || toolName == "" {
		return resolveMCPSupplyChainState("", "", 0, "", "", 0, false, false, ""), nil
	}
	var serverStatus, serverReason, toolID, toolStatus, toolReason, routeHash, approvedRouteHash, schemaHash, approvedSchemaHash string
	var serverRevision, toolRevision int64
	var removed, toolFound bool
	var serverReviewedBy, toolReviewedBy string
	err := r.db.QueryRow(ctx, `
		SELECT s.admission_status,s.quarantine_reason,s.admission_revision,
		       s.observed_route_hash,s.approved_route_hash,
		       COALESCE(t.id,''),COALESCE(t.admission_status,''),COALESCE(t.quarantine_reason,''),
		       COALESCE(t.admission_revision,0),COALESCE(t.schema_hash,''),COALESCE(t.approved_schema_hash,''),COALESCE(t.removed,FALSE),(t.id IS NOT NULL),
		       COALESCE(s.admission_reviewed_by,''),COALESCE(t.admission_reviewed_by,'')
		FROM mcp_servers s
		LEFT JOIN mcp_tools t ON t.tenant_id=s.tenant_id AND t.server_id=s.id AND t.tool_name=$3
		WHERE s.tenant_id=$1 AND s.id=$2`,
		tenantID, serverID, toolName,
	).Scan(&serverStatus, &serverReason, &serverRevision, &routeHash, &approvedRouteHash,
		&toolID, &toolStatus, &toolReason, &toolRevision, &schemaHash, &approvedSchemaHash, &removed, &toolFound, &serverReviewedBy, &toolReviewedBy)
	if errors.Is(err, pgx.ErrNoRows) {
		return resolveMCPSupplyChainState("", "", 0, "", "", 0, false, false, ""), nil
	}
	if err != nil {
		return MCPSupplyChainResolution{}, err
	}
	resolution := resolveMCPSupplyChainState(serverStatus, serverReason, serverRevision, toolStatus, toolReason, toolRevision, removed, toolFound, toolID)
	resolution = WithMCPAdmissionSources(resolution, serverReviewedBy, toolReviewedBy)
	resolution.ServerReason = serverReason
	resolution.RouteHash = routeHash
	resolution.ApprovedRouteHash = approvedRouteHash
	resolution.SchemaHash = schemaHash
	resolution.ApprovedSchemaHash = approvedSchemaHash
	// 服务和工具都已批准时才比对绑定（发现原因与绑定失配可以同时存在）。
	approvedPair := resolution.ServerStatus == "approved" && resolution.ToolStatus == "approved" && toolFound && !removed
	if approvedPair && (routeHash == "" || approvedRouteHash == "" || routeHash != approvedRouteHash) {
		resolution.Status, resolution.StructuralBlock = "quarantined", true
		resolution.Reasons = append(resolution.Reasons, "route_binding_mismatch")
	}
	if approvedPair && (schemaHash == "" || approvedSchemaHash == "" || schemaHash != approvedSchemaHash) {
		resolution.Status, resolution.StructuralBlock = "quarantined", true
		resolution.Reasons = append(resolution.Reasons, "schema_binding_mismatch")
	}
	resolution.Revision = mcpBoundSupplyChainRevision(
		resolution.Revision, routeHash, approvedRouteHash, schemaHash, approvedSchemaHash, resolution.Status, strings.Join(resolution.Reasons, ","),
	)
	return resolution, nil

}
func mcpBoundSupplyChainRevision(base, routeHash, approvedRouteHash, schemaHash, approvedSchemaHash, status, reasons string) string {
	sum := sha256.Sum256([]byte(base + ":" + routeHash + ":" + approvedRouteHash + ":" + schemaHash + ":" + approvedSchemaHash + ":" + status + ":" + reasons))
	return "mcpsc_" + hex.EncodeToString(sum[:8])
}

// WithMCPAdmissionSources 按 admission_reviewed_by 写入服务、工具的处置来源（见 mcpadmission）。
func WithMCPAdmissionSources(resolution MCPSupplyChainResolution, serverReviewedBy, toolReviewedBy string) MCPSupplyChainResolution {
	resolution.ServerAdmissionSource = mcpadmission.Source(serverReviewedBy)
	resolution.ToolAdmissionSource = mcpadmission.Source(toolReviewedBy)
	return resolution
}
