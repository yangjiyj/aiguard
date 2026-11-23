package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

func (r *MCPToolsRepository) SetMCPServerAdmission(ctx context.Context, tenantID, id, status, expectedHash, expectedRouteHash, reason, actor string) (*MCPAdmissionMutation, error) {
	if r == nil || r.db == nil || !validMCPAdmissionMutation(status) || tenantID == "" || id == "" || expectedHash == "" || expectedRouteHash == "" || actor == "" {
		return nil, fmt.Errorf("invalid MCP server admission mutation")
	}
	if reason == "" && status != "approved" {
		reason = "manual_" + status
	}
	var mutation MCPAdmissionMutation
	err := r.db.QueryRow(ctx, `
		UPDATE mcp_servers SET
			admission_status=$3,
			approved_manifest_hash=CASE WHEN $3='approved' THEN manifest_hash ELSE approved_manifest_hash END,
			approved_manifest_snapshot=CASE WHEN $3='approved' THEN observed_manifest_snapshot ELSE approved_manifest_snapshot END,
			approved_route_hash=CASE WHEN $3='approved' THEN observed_route_hash ELSE approved_route_hash END,
			quarantine_reason=CASE WHEN $3='approved' THEN '' ELSE $6 END,
			quarantined_at=CASE WHEN $3='approved' THEN NULL ELSE NOW() END,
			admission_reviewed_by=$7,admission_reviewed_at=NOW()
		WHERE tenant_id=$1 AND id=$2 AND manifest_hash=$4 AND observed_route_hash=$5
		RETURNING id,admission_status,manifest_hash,observed_route_hash,quarantine_reason,admission_revision`,
		tenantID, id, status, expectedHash, expectedRouteHash, reason, actor,
	).Scan(&mutation.ID, &mutation.Status, &mutation.Hash, &mutation.RouteHash, &mutation.Reason, &mutation.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, r.mcpAdmissionNoRows(ctx, tenantID, "mcp_servers", id)
	}
	if err != nil {
		return nil, err
	}
	mutation.AssetType = "server"
	return &mutation, nil
}

func (r *MCPToolsRepository) SetMCPToolAdmission(ctx context.Context, tenantID, id, status, expectedHash, reason, actor string) (*MCPAdmissionMutation, error) {
	if r == nil || r.db == nil || !validMCPAdmissionMutation(status) || tenantID == "" || id == "" || expectedHash == "" || actor == "" {
		return nil, fmt.Errorf("invalid MCP tool admission mutation")
	}
	if reason == "" && status != "approved" {
		reason = "manual_" + status
	}
	var mutation MCPAdmissionMutation
	err := r.db.QueryRow(ctx, `
		UPDATE mcp_tools SET
			admission_status=$3,
			approved_schema_hash=CASE WHEN $3='approved' THEN schema_hash ELSE approved_schema_hash END,
			approved_schema_snapshot=CASE WHEN $3='approved'
				THEN jsonb_build_object('tool_name',tool_name,'description',description,'input_schema',input_schema,'schema_hash',schema_hash)
				ELSE approved_schema_snapshot END,
			quarantine_reason=CASE WHEN $3='approved' THEN '' ELSE $5 END,
			quarantined_at=CASE WHEN $3='approved' THEN NULL ELSE NOW() END,
			approved_poison_flags=CASE WHEN $3='approved' THEN COALESCE(poison_flags,'[]'::jsonb) ELSE approved_poison_flags END,
			admission_reviewed_by=$6,admission_reviewed_at=NOW()
		WHERE tenant_id=$1 AND id=$2 AND schema_hash=$4
		RETURNING id,admission_status,schema_hash,quarantine_reason,admission_revision`,
		tenantID, id, status, expectedHash, reason, actor,
	).Scan(&mutation.ID, &mutation.Status, &mutation.Hash, &mutation.Reason, &mutation.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, r.mcpAdmissionNoRows(ctx, tenantID, "mcp_tools", id)
	}
	if err != nil {
		return nil, err
	}
	mutation.AssetType = "tool"
	return &mutation, nil
}

func (r *MCPToolsRepository) mcpAdmissionNoRows(ctx context.Context, tenantID, table, id string) error {
	query := "SELECT EXISTS(SELECT 1 FROM " + table + " WHERE tenant_id=$1 AND id=$2)"
	var exists bool
	if err := r.db.QueryRow(ctx, query, tenantID, id).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrMCPAdmissionSnapshotConflict
	}
	return pgx.ErrNoRows
}
