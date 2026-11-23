package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// BlockRequestMetadata deliberately has no prompt, response or tool arguments.
// The content endpoints enforce their own content-evidence authorization.
type BlockRequestMetadata struct {
	RecordID        string     `json:"record_id"`
	RequestID       string     `json:"request_id"`
	CreatedAt       time.Time  `json:"created_at"`
	ProjectID       string     `json:"project_id"`
	SessionID       string     `json:"session_id"`
	ConversationID  string     `json:"conversation_id"`
	TraceID         string     `json:"trace_id"`
	Status          string     `json:"status"`
	HTTPStatus      int        `json:"http_status"`
	InputTokens     int        `json:"input_tokens"`
	OutputTokens    int        `json:"output_tokens"`
	LatencyMs       int        `json:"latency_ms"`
	ContentRetained bool       `json:"-"`
	RetentionUntil  *time.Time `json:"-"`
}

type BlockContentRecord struct {
	ID        string    `json:"id"`
	Role      string    `json:"role"`
	Tokens    int       `json:"tokens"`
	CreatedAt time.Time `json:"created_at"`
}

type BlockToolRecord struct {
	ID          string    `json:"id"`
	ToolName    string    `json:"tool_name"`
	ToolType    string    `json:"tool_type"`
	EventType   string    `json:"event_type"`
	Status      string    `json:"status"`
	OperationID string    `json:"operation_id"`
	CreatedAt   time.Time `json:"created_at"`
}

type BlockAuditMetadata struct {
	Request        *BlockRequestMetadata `json:"request"`
	ContentRecords []BlockContentRecord  `json:"content_records"`
	ToolRecords    []BlockToolRecord     `json:"tool_records"`
	ContentCount   int                   `json:"content_count"`
	ToolCount      int                   `json:"tool_count"`
	HasContent     bool                  `json:"-"`
}

// GetBlockAuditMetadata follows only the exact tenant + request. It projects
// record identifiers, times and usage, and checks content presence in SQL
// without reading any content bodies into the response or process.
func (r *SecurityEventRepository) GetBlockAuditMetadata(ctx context.Context, tenantID, requestID string, projectIDs []string) (*BlockAuditMetadata, error) {
	metadata := &BlockAuditMetadata{ContentRecords: []BlockContentRecord{}, ToolRecords: []BlockToolRecord{}}
	request := &BlockRequestMetadata{}
	where := "rl.tenant_id = $1 AND rl.request_id = $2"
	args := []any{tenantID, requestID}
	if projectIDs != nil {
		where += " AND rl.project_id = ANY($3::text[])"
		args = append(args, projectIDs)
	}
	err := r.db.QueryRow(ctx, `SELECT rl.id, rl.request_id, rl.created_at,
		COALESCE(rl.project_id, ''), COALESCE(rl.session_id, ''),
		''::text, COALESCE(rl.trace_id, ''),
		rl.request_status, COALESCE(rl.upstream_status_code, 0),
		COALESCE(rl.input_tokens, 0), COALESCE(rl.output_tokens, 0),
		COALESCE(rl.latency_ms, 0), COALESCE(rl.proxy_content_retained, FALSE),
		rl.content_evidence_retention_until
		FROM request_logs rl WHERE `+where, args...).Scan(
		&request.RecordID, &request.RequestID, &request.CreatedAt, &request.ProjectID,
		&request.SessionID, &request.ConversationID, &request.TraceID,
		&request.Status, &request.HTTPStatus, &request.InputTokens, &request.OutputTokens,
		&request.LatencyMs, &request.ContentRetained, &request.RetentionUntil,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		// A persisted security event may outlive the request log. Do not use
		// another request as substitute evidence.
		return metadata, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read block request metadata: %w", err)
	}
	metadata.Request = request
	contentRows, err := r.db.Query(ctx, `WITH records AS (
		SELECT c.id, c.role, COALESCE(c.tokens, 0) AS tokens, c.created_at,
			BTRIM(COALESCE(c.content, '')) <> '' AS has_content, ''::text AS conversation_id
		FROM content_logs c
		WHERE c.tenant_id = $1 AND (c.request_id = $2 OR c.request_id = $3)
			AND c.environment_scope = ANY($4::text[])
		UNION ALL
		SELECT a.id, 'request_response', 0, a.created_at,
			BTRIM(COALESCE(a.request_content_redacted, '')) <> ''
			OR BTRIM(COALESCE(a.response_content_redacted, '')) <> ''
			OR COALESCE(a.file_metadata_json, '[]'::jsonb) NOT IN ('[]'::jsonb, 'null'::jsonb), COALESCE(a.conversation_id, '')
		FROM access_content_logs a
		WHERE a.tenant_id = $1 AND a.request_id = $2
			AND a.environment_scope = ANY($4::text[])
	) SELECT id, role, tokens, created_at, COUNT(*) OVER (), BOOL_OR(has_content) OVER (),
		COALESCE(MIN(NULLIF(conversation_id, '')) OVER (), '')
		FROM records ORDER BY created_at, id LIMIT 200`, tenantID, requestID, request.RecordID, EnvironmentScopesForRead("customer"))
	if err != nil {
		return metadata, fmt.Errorf("read block content metadata: %w", err)
	}
	for contentRows.Next() {
		var record BlockContentRecord
		if err := contentRows.Scan(&record.ID, &record.Role, &record.Tokens, &record.CreatedAt, &metadata.ContentCount, &metadata.HasContent, &metadata.Request.ConversationID); err != nil {
			contentRows.Close()
			return metadata, err
		}
		metadata.ContentRecords = append(metadata.ContentRecords, record)
	}
	err = contentRows.Err()
	contentRows.Close()
	if err != nil {
		return metadata, err
	}
	toolRows, err := r.db.Query(ctx, `SELECT id, COALESCE(tool_name, ''), COALESCE(tool_type, ''),
		COALESCE(event_type, ''), COALESCE(status, ''), COALESCE(operation_id, ''), created_at,
		COUNT(*) OVER () FROM tool_call_logs WHERE tenant_id = $1 AND request_id = $2
		ORDER BY created_at, id LIMIT 200`, tenantID, requestID)
	if err != nil {
		return metadata, fmt.Errorf("read block tool metadata: %w", err)
	}
	defer toolRows.Close()
	for toolRows.Next() {
		var record BlockToolRecord
		if err := toolRows.Scan(&record.ID, &record.ToolName, &record.ToolType, &record.EventType, &record.Status, &record.OperationID, &record.CreatedAt, &metadata.ToolCount); err != nil {
			return metadata, err
		}
		metadata.ToolRecords = append(metadata.ToolRecords, record)
	}
	return metadata, toolRows.Err()
}
