package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// RetainedArtifact is the customer-safe linkage record for a retained original.
// Object keys stay repository-internal and are never serialized by the control API.
type RetainedArtifact struct {
	ID                   string
	TenantID             string
	EnvironmentScope     string
	LinkEnvironmentScope string
	RequestID            string
	Direction            string
	Ordinal              int
	Kind                 string
	DisplayName          string
	MediaType            string
	ByteSize             int64
	SHA256               string
	Status               string
	FailureCode          string
	OriginalObjectKey    string
	PreviewObjectKey     string
	RetentionUntil       *time.Time
	RequestCreatedAt     time.Time
	LinkCreatedAt        time.Time
}

func appendRetainedArtifactReadFilters(where []string, args []interface{}, environmentScope string, start, end time.Time) ([]string, []interface{}) {
	if environmentScope != "" {
		args = append(args, EnvironmentScopesForRead(environmentScope))
		where = append(where, fmt.Sprintf("l.environment_scope = ANY($%d)", len(args)))
		where = append(where, fmt.Sprintf("a.environment_scope = ANY($%d)", len(args)))
		where = append(where, fmt.Sprintf("rl.environment_scope = ANY($%d)", len(args)))
	}
	if !start.IsZero() {
		args = append(args, start)
		where = append(where, fmt.Sprintf("l.created_at >= $%d", len(args)))
		where = append(where, fmt.Sprintf("rl.created_at >= $%d", len(args)))
	}
	if !end.IsZero() {
		args = append(args, end)
		where = append(where, fmt.Sprintf("l.created_at < $%d", len(args)))
		where = append(where, fmt.Sprintf("rl.created_at < $%d", len(args)))
	}
	return where, args
}

const retainedArtifactSelect = `
SELECT
	a.id, a.tenant_id, l.request_id, l.direction, a.kind,
	COALESCE(a.display_name, ''), COALESCE(a.media_type, ''),
	COALESCE(a.byte_size, 0), COALESCE(a.sha256, ''),
	a.retention_status, COALESCE(a.failure_code, ''),
	COALESCE(a.original_object_key, ''), COALESCE(a.preview_object_key, ''),
	a.retention_until, a.environment_scope, l.environment_scope,
	rl.created_at, l.created_at, l.ordinal
FROM access_content_artifact_links l
JOIN retained_artifacts a
	ON a.id = l.artifact_id
	AND a.tenant_id = l.tenant_id
JOIN request_logs rl
	ON rl.request_id = l.request_id
	AND rl.tenant_id = l.tenant_id
WHERE l.tenant_id = $1
	AND l.request_id = $2`

func scanRetainedArtifact(scanner interface{ Scan(...any) error }) (*RetainedArtifact, error) {
	var item RetainedArtifact
	var until sql.NullTime
	if err := scanner.Scan(
		&item.ID, &item.TenantID, &item.RequestID, &item.Direction, &item.Kind,
		&item.DisplayName, &item.MediaType, &item.ByteSize, &item.SHA256,
		&item.Status, &item.FailureCode, &item.OriginalObjectKey, &item.PreviewObjectKey,
		&until, &item.EnvironmentScope, &item.LinkEnvironmentScope,
		&item.RequestCreatedAt, &item.LinkCreatedAt, &item.Ordinal,
	); err != nil {
		return nil, err
	}
	if until.Valid {
		item.RetentionUntil = &until.Time
	}
	return &item, nil
}

const retainedArtifactsChronologicalOrder = ` ORDER BY rl.created_at ASC, l.created_at ASC, l.direction ASC, l.ordinal ASC, a.id ASC, l.request_id ASC`

// ListRetainedArtifacts reads only artifact links owned by tenant and request.
// A bare artifact id is deliberately insufficient for customer access.
func (r *RequestLogRepository) ListRetainedArtifacts(ctx context.Context, tenantID, requestID string) ([]RetainedArtifact, error) {
	rows, err := r.db.Query(ctx, retainedArtifactSelect+retainedArtifactsChronologicalOrder, tenantID, requestID)
	if err != nil {
		return nil, fmt.Errorf("list retained artifacts: %w", err)
	}
	defer rows.Close()

	out := []RetainedArtifact{}
	for rows.Next() {
		item, err := scanRetainedArtifact(rows)
		if err != nil {
			return nil, fmt.Errorf("scan retained artifact: %w", err)
		}
		out = append(out, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate retained artifacts: %w", err)
	}
	return out, nil
}

func (r *RequestLogRepository) ListRetainedArtifactsScoped(
	ctx context.Context,
	tenantID, requestID string,
	start, end time.Time,
	environmentScope string,
) ([]RetainedArtifact, error) {
	args := []interface{}{tenantID, requestID}
	where := []string{"l.tenant_id = $1", "l.request_id = $2"}
	where, args = appendRetainedArtifactReadFilters(where, args, environmentScope, start, end)
	query := retainedArtifactSelect
	for _, clause := range where[2:] {
		query += " AND " + clause
	}
	rows, err := r.db.Query(ctx, query+retainedArtifactsChronologicalOrder, args...)
	if err != nil {
		return nil, fmt.Errorf("list scoped retained artifacts: %w", err)
	}
	defer rows.Close()
	out := []RetainedArtifact{}
	for rows.Next() {
		item, err := scanRetainedArtifact(rows)
		if err != nil {
			return nil, fmt.Errorf("scan scoped retained artifact: %w", err)
		}
		out = append(out, *item)
	}
	return out, rows.Err()
}

func (r *RequestLogRepository) ListRetainedArtifactsByRequests(ctx context.Context, tenantID string, requestIDs []string) ([]RetainedArtifact, error) {
	if len(requestIDs) == 0 {
		return []RetainedArtifact{}, nil
	}
	query := strings.Replace(retainedArtifactSelect, "l.request_id = $2", "l.request_id = ANY($2)", 1)
	rows, err := r.db.Query(ctx, query+retainedArtifactsChronologicalOrder, tenantID, requestIDs)
	if err != nil {
		return nil, fmt.Errorf("list retained artifacts by requests: %w", err)
	}
	defer rows.Close()
	out := []RetainedArtifact{}
	for rows.Next() {
		item, err := scanRetainedArtifact(rows)
		if err != nil {
			return nil, fmt.Errorf("scan retained artifact: %w", err)
		}
		out = append(out, *item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate retained artifacts: %w", err)
	}
	return out, nil
}

func (r *RequestLogRepository) ListRetainedArtifactsByRequestsScoped(
	ctx context.Context,
	tenantID string,
	requestIDs []string,
	start, end time.Time,
	environmentScope string,
) ([]RetainedArtifact, error) {
	if len(requestIDs) == 0 {
		return []RetainedArtifact{}, nil
	}
	args := []interface{}{tenantID, requestIDs}
	where := []string{"l.tenant_id = $1", "l.request_id = ANY($2)"}
	where, args = appendRetainedArtifactReadFilters(where, args, environmentScope, start, end)
	query := strings.Replace(retainedArtifactSelect, "l.request_id = $2", "l.request_id = ANY($2)", 1)
	for _, clause := range where[2:] {
		query += " AND " + clause
	}
	rows, err := r.db.Query(ctx, query+retainedArtifactsChronologicalOrder, args...)
	if err != nil {
		return nil, fmt.Errorf("list scoped retained artifacts by requests: %w", err)
	}
	defer rows.Close()
	out := []RetainedArtifact{}
	for rows.Next() {
		item, err := scanRetainedArtifact(rows)
		if err != nil {
			return nil, fmt.Errorf("scan scoped retained artifact: %w", err)
		}
		out = append(out, *item)
	}
	return out, rows.Err()
}

// GetRetainedArtifact proves tenant, request link, and artifact ownership in one query.
func (r *RequestLogRepository) GetRetainedArtifact(ctx context.Context, tenantID, requestID, artifactID string) (*RetainedArtifact, error) {
	item, err := scanRetainedArtifact(r.db.QueryRow(ctx, retainedArtifactSelect+` AND a.id = $3 LIMIT 1`, tenantID, requestID, artifactID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get retained artifact: %w", err)
	}
	return item, nil
}

func (r *RequestLogRepository) GetRetainedArtifactScoped(
	ctx context.Context,
	tenantID, requestID, artifactID string,
	start, end time.Time,
	environmentScope string,
) (*RetainedArtifact, error) {
	where, args := appendRetainedArtifactReadFilters(
		[]string{"a.id = $3"},
		[]interface{}{tenantID, requestID, artifactID},
		environmentScope, start.UTC(), end.UTC(),
	)
	query := retainedArtifactSelect + " AND " + strings.Join(where, " AND ") + " LIMIT 1"
	item, err := scanRetainedArtifact(r.db.QueryRow(ctx, query, args...))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get scoped retained artifact: %w", err)
	}
	return item, nil
}
