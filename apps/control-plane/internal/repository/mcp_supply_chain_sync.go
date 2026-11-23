package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/protection"
	"github.com/google/uuid"
)

// ApplySupplyChainSync atomically stores the observed manifest and evaluates admission.
// Synchronization may escalate a state, but never clears quarantine/revocation or rewrites
// the last administrator-approved snapshots.
func (r *MCPToolsRepository) ApplySupplyChainSync(ctx context.Context, input MCPSupplyChainSyncInput) (*MCPSupplyChainSyncResult, error) {
	if r == nil || r.db == nil || input.TenantID == "" || input.ServerID == "" || input.ManifestHash == "" {
		return nil, fmt.Errorf("invalid MCP supply-chain sync input")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin MCP supply-chain sync: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var previousManifest, serverStatus, approvedManifestHash, approvedSnapshotText, serverReason, serverReviewedBy, observedRouteHash, approvedRouteHash string
	var serverQuarantinedAt, serverReviewedAt *time.Time
	var ignoredServerRevision int64
	err = tx.QueryRow(ctx, `
		SELECT manifest_hash,admission_status,approved_manifest_hash,approved_manifest_snapshot::text,
		       quarantine_reason,quarantined_at,admission_reviewed_by,admission_reviewed_at,admission_revision,
		       observed_route_hash,approved_route_hash
		FROM mcp_servers WHERE id=$1 AND tenant_id=$2 FOR UPDATE`,
		input.ServerID, input.TenantID,
	).Scan(&previousManifest, &serverStatus, &approvedManifestHash, &approvedSnapshotText,
		&serverReason, &serverQuarantinedAt, &serverReviewedBy, &serverReviewedAt, &ignoredServerRevision,
		&observedRouteHash, &approvedRouteHash)
	if err != nil {
		return nil, err
	}
	approvedManifestSnapshot := []byte(approvedSnapshotText)

	existing := map[string]*mcpToolAdmissionRecord{}
	rows, err := tx.Query(ctx, `
		SELECT id,tool_name,schema_hash,admission_status,approved_schema_hash,
		       approved_schema_snapshot::text,quarantine_reason,quarantined_at,
		       admission_reviewed_by,admission_reviewed_at,admission_revision,removed,
		       COALESCE(approved_poison_flags,'[]'::jsonb)::text
		FROM mcp_tools WHERE tenant_id=$1 AND server_id=$2 FOR UPDATE`,
		input.TenantID, input.ServerID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name, snapshotText, approvedFlagsText string
		record := &mcpToolAdmissionRecord{}
		if err := rows.Scan(&record.ID, &name, &record.SchemaHash, &record.Status,
			&record.ApprovedSchemaHash, &snapshotText, &record.QuarantineReason,
			&record.QuarantinedAt, &record.ReviewedBy, &record.ReviewedAt,
			&record.Revision, &record.Removed, &approvedFlagsText); err != nil {
			rows.Close()
			return nil, err
		}
		_ = json.Unmarshal([]byte(approvedFlagsText), &record.ApprovedPoisonFlags)
		record.ApprovedSnapshot = []byte(snapshotText)
		existing[name] = record
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	shadowHashes := map[string]map[string]struct{}{}
	rows, err = tx.Query(ctx, `
		SELECT tool_name,schema_hash FROM mcp_tools
		WHERE tenant_id=$1 AND server_id<>$2 AND removed=FALSE`,
		input.TenantID, input.ServerID)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var name, hash string
		if err := rows.Scan(&name, &hash); err != nil {
			rows.Close()
			return nil, err
		}
		if shadowHashes[name] == nil {
			shadowHashes[name] = map[string]struct{}{}
		}
		shadowHashes[name][hash] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	result := &MCPSupplyChainSyncResult{DescriptionScanComplete: input.DescriptionScanComplete}
	names := make([]string, 0, len(input.Tools))
	now := time.Now().UTC()
	for _, tool := range input.Tools {
		if tool == nil || strings.TrimSpace(tool.ToolName) == "" {
			continue
		}
		tool.ToolName = strings.TrimSpace(tool.ToolName)
		names = append(names, tool.ToolName)
		previous := existing[tool.ToolName]
		// 同名不一致只对首次出现的工具比对：别的服务后来新增同名工具时，不回头标记这里已批准、
		// 自身没变的工具（那条新工具自己会被标记）。
		divergentShadow := false
		if previous == nil {
			for hash := range shadowHashes[tool.ToolName] {
				if hash != tool.SchemaHash {
					divergentShadow = true
					break
				}
			}
		} else if previous.Status == "unverified" && previous.QuarantineReason == "shadow_schema_diverges" &&
			previous.SchemaHash == tool.SchemaHash {
			// 首次出现时标记过、仍未准入且 Schema 没变：保留这个发现，之后改成阻断也对它生效。
			divergentShadow = true
		}
		decision := decideMCPToolAdmission(previous, tool, divergentShadow, input.Protections)
		decision = applyMCPDescriptionScanGate(previous, decision, input.DescriptionScanComplete, input.Protections)
		switch decision.Status {
		case "approved":
			result.ApprovedCount++
		case "quarantined":
			result.QuarantinedCount++
			result.Reasons = appendUniqueMCPReason(result.Reasons, decision.Reason)
		case "unverified":
			if mcpFindingReasons[decision.Reason] {
				result.Reasons = appendUniqueMCPReason(result.Reasons, decision.Reason)
			}
		case "revoked":
			result.RevokedCount++
		}

		id := "mcpt_" + uuid.New().String()[:8]
		approvedHash, approvedSnapshot, reviewedBy := "", []byte("{}"), ""
		var reviewedAt, quarantinedAt *time.Time
		if previous != nil {
			id, approvedHash, approvedSnapshot = previous.ID, previous.ApprovedSchemaHash, previous.ApprovedSnapshot
			reviewedBy, reviewedAt, quarantinedAt = previous.ReviewedBy, previous.ReviewedAt, previous.QuarantinedAt
		}
		if decision.Status == "quarantined" && (previous == nil || previous.Status != "quarantined") {
			reviewedBy, reviewedAt, quarantinedAt = "system", &now, &now
		}
		if len(approvedSnapshot) == 0 || !json.Valid(approvedSnapshot) {
			approvedSnapshot = []byte("{}")
		}
		schemaJSON, err := json.Marshal(tool.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("marshal input schema for %s: %w", tool.ToolName, err)
		}
		riskJSON, _ := json.Marshal(nonNilStrings(tool.RiskTags))
		poisonJSON, _ := json.Marshal(nonNilStrings(tool.PoisonFlags))
		_, err = tx.Exec(ctx, `
			INSERT INTO mcp_tools(
				id,server_id,tenant_id,tool_name,description,input_schema,risk_tags,schema_hash,poison_flags,
				admission_status,approved_schema_hash,approved_schema_snapshot,quarantine_reason,
				quarantined_at,admission_reviewed_by,admission_reviewed_at,removed)
			VALUES($1,$2,$3,$4,$5,$6::jsonb,$7::jsonb,$8,$9::jsonb,$10,$11,$12::jsonb,$13,$14,$15,$16,FALSE)
			ON CONFLICT(server_id,tool_name) DO UPDATE SET
				description=EXCLUDED.description,input_schema=EXCLUDED.input_schema,risk_tags=EXCLUDED.risk_tags,
				schema_hash=EXCLUDED.schema_hash,poison_flags=EXCLUDED.poison_flags,last_seen_at=NOW(),removed=FALSE,
				admission_status=EXCLUDED.admission_status,approved_schema_hash=EXCLUDED.approved_schema_hash,
				approved_schema_snapshot=EXCLUDED.approved_schema_snapshot,quarantine_reason=EXCLUDED.quarantine_reason,
				quarantined_at=EXCLUDED.quarantined_at,admission_reviewed_by=EXCLUDED.admission_reviewed_by,
				admission_reviewed_at=EXCLUDED.admission_reviewed_at
			WHERE mcp_tools.tenant_id=EXCLUDED.tenant_id`,
			id, input.ServerID, input.TenantID, tool.ToolName, tool.Description, string(schemaJSON),
			string(riskJSON), tool.SchemaHash, string(poisonJSON), decision.Status, approvedHash,
			string(approvedSnapshot), decision.Reason, quarantinedAt, reviewedBy, reviewedAt)
		if err != nil {
			return nil, fmt.Errorf("upsert admitted MCP tool %s: %w", tool.ToolName, err)
		}
	}
	tag, err := tx.Exec(ctx, `
		UPDATE mcp_tools SET removed=TRUE,last_seen_at=NOW()
		WHERE tenant_id=$1 AND server_id=$2 AND removed=FALSE AND NOT(tool_name=ANY($3))`,
		input.TenantID, input.ServerID, names)
	if err != nil {
		return nil, err
	}
	result.RemovedCount = int(tag.RowsAffected())

	manifestSnapshot := normalizeMCPManifestSnapshot(input.ManifestSnapshot, input.Tools)
	newServerStatus, newServerReason := serverStatus, serverReason
	if serverStatus == "approved" && previousManifest != "" && previousManifest != input.ManifestHash &&
		input.Protections.ActionFor(protection.KeyMCPDrift) == protection.ActionBlock {
		// 清单变化默认不隔离服务：变化的工具由 Schema 绑定、新增工具由未准入各自按防护项处置；
		// mcp.drift 设为阻断时照 2.9.21 隔离整个服务。
		newServerStatus, newServerReason = "quarantined", "rug_pull_manifest_changed"
		serverQuarantinedAt, serverReviewedBy, serverReviewedAt = &now, "system", &now
	} else if serverStatus == "" || serverStatus == "unverified" {
		newServerStatus, newServerReason = "unverified", "pending_administrator_review"
	}
	if len(approvedManifestSnapshot) == 0 || !json.Valid(approvedManifestSnapshot) {
		approvedManifestSnapshot = []byte("[]")
	}
	capabilityPatch := []byte("{}")
	if len(input.CapabilityPatch) > 0 {
		if b, jerr := json.Marshal(input.CapabilityPatch); jerr == nil {
			capabilityPatch = b
		}
	}
	_, err = tx.Exec(ctx, `
		UPDATE mcp_servers SET
			manifest_hash=$3,observed_manifest_snapshot=$4::jsonb,last_synced_at=NOW(),
			last_manifest_changed_at=CASE WHEN manifest_hash<>'' AND manifest_hash<>$3 THEN NOW() ELSE last_manifest_changed_at END,
			capabilities_json=jsonb_set(COALESCE(capabilities_json,'{}'::jsonb),'{protocol_version}',to_jsonb($5::text),true)
				- 'protocol_version_raw' - 'protocol_version_forward_compat' || $14::jsonb,
			admission_status=$6,approved_manifest_hash=$7,approved_manifest_snapshot=$8::jsonb,
			quarantine_reason=$9,quarantined_at=$10,admission_reviewed_by=$11,admission_reviewed_at=$12,approved_route_hash=$13,
			updated_at=NOW()
		WHERE id=$1 AND tenant_id=$2`,
		input.ServerID, input.TenantID, input.ManifestHash, string(manifestSnapshot), input.ProtocolVersion,
		newServerStatus, approvedManifestHash, string(approvedManifestSnapshot), newServerReason,
		serverQuarantinedAt, serverReviewedBy, serverReviewedAt, approvedRouteHash, string(capabilityPatch))
	if err != nil {
		return nil, fmt.Errorf("update admitted MCP manifest: %w", err)
	}
	if err := tx.QueryRow(ctx, `
		SELECT admission_status,quarantine_reason FROM mcp_servers WHERE id=$1 AND tenant_id=$2`,
		input.ServerID, input.TenantID).Scan(&result.ServerStatus, &result.ServerReason); err != nil {
		return nil, err
	}
	result.Reasons = appendUniqueMCPReason(result.Reasons, result.ServerReason)
	if err := tx.Commit(ctx); err != nil {
		return nil, err

	}
	return result, nil
}

// applyMCPDescriptionScanGate：描述扫描没跑完时，未准入的工具记一个 description_scan_unavailable
// （不覆盖更具体的发现）；mcp.scan_unavailable 设为阻断时隔离。已批准的工具不受影响。
func applyMCPDescriptionScanGate(previous *mcpToolAdmissionRecord, decision mcpAdmissionDecision, complete bool, settings protection.Settings) mcpAdmissionDecision {
	if complete || decision.Status == "approved" || decision.Status == "revoked" || decision.Status == "quarantined" {
		return decision
	}
	if previous != nil && previous.Status == "approved" {
		return decision
	}
	if settings.ActionFor(protection.KeyMCPScanUnavailable) == protection.ActionBlock {
		return mcpAdmissionDecision{Status: "quarantined", Reason: "description_scan_unavailable"}
	}
	if decision.Reason == "" || decision.Reason == "pending_administrator_review" {
		decision.Reason = "description_scan_unavailable"
	}
	return decision
}
