package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identitybinding"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type identityMappingQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

type IdentityDepartmentMappingRepository struct {
	db *pgxpool.Pool
}

func NewIdentityDepartmentMappingRepository(db *pgxpool.Pool) *IdentityDepartmentMappingRepository {
	return &IdentityDepartmentMappingRepository{db: db}
}

func (r *IdentityDepartmentMappingRepository) FindMatches(
	ctx context.Context,
	identity identitybinding.ExternalIdentity,
) ([]identitybinding.DepartmentMapping, error) {
	return findIdentityDepartmentMappings(ctx, r.db, identity)
}

func findIdentityDepartmentMappings(
	ctx context.Context,
	db identityMappingQuerier,
	identity identitybinding.ExternalIdentity,
) ([]identitybinding.DepartmentMapping, error) {
	rows, err := db.Query(ctx, `
		WITH matched AS (
			SELECT
				m.id,
				m.tenant_id,
				m.source_kind,
				m.source_id,
				m.match_type,
				m.match_value,
				m.target_department_id,
				m.priority,
				m.enabled,
				CASE WHEN m.source_id = $3 THEN 0 ELSE 1 END AS source_rank
			FROM identity_department_mappings m
			JOIN teams department
			  ON department.tenant_id = m.tenant_id
			 AND department.id = m.target_department_id
			WHERE m.tenant_id = $1
			  AND m.source_kind = $2
			  AND m.enabled = TRUE
			  AND m.source_id IN ($3, '')
			  AND (
				(m.match_type = 'department' AND m.match_value = ANY($4::text[]))
				OR (m.match_type = 'ou' AND m.match_value = ANY($5::text[]))
				OR (m.match_type = 'member_of' AND m.match_value = ANY($6::text[]))
				OR (m.match_type = 'groups' AND m.match_value = ANY($7::text[]))
			  )
		), explicit AS (
			SELECT id, tenant_id, source_kind, source_id, match_type, match_value,
			       target_department_id, priority, enabled
			FROM matched
			WHERE source_rank = (SELECT MIN(source_rank) FROM matched)
		), fallback AS (
			SELECT
			  'identity_default:' || defaults.default_department_id AS id,
			  defaults.tenant_id,
			  $2::varchar AS source_kind,
			  ''::varchar AS source_id,
			  'department'::varchar AS match_type,
			  '*'::varchar AS match_value,
			  defaults.default_department_id AS target_department_id,
			  2147483647 AS priority,
			  TRUE AS enabled
			FROM tenant_identity_defaults defaults
			JOIN teams department
			  ON department.tenant_id = defaults.tenant_id
			 AND department.id = defaults.default_department_id
			WHERE defaults.tenant_id = $1
			  AND defaults.enabled = TRUE
			  AND $2 = ANY(defaults.fallback_source_types)
		)
		SELECT id, tenant_id, source_kind, source_id, match_type, match_value,
		       target_department_id, priority, enabled
		FROM explicit
		UNION ALL
		SELECT id, tenant_id, source_kind, source_id, match_type, match_value,
		       target_department_id, priority, enabled
		FROM fallback
		WHERE NOT EXISTS (SELECT 1 FROM explicit)
		ORDER BY priority ASC, id ASC
	`, identity.TenantID, identity.SourceType, identity.SourceID, identity.Departments, identity.OUs, identity.MemberOf, identity.Groups)
	if err != nil {
		return nil, fmt.Errorf("find identity department mappings: %w", err)
	}
	defer rows.Close()

	mappings := make([]identitybinding.DepartmentMapping, 0)
	for rows.Next() {
		var mapping identitybinding.DepartmentMapping
		if err := rows.Scan(
			&mapping.ID,
			&mapping.TenantID,
			&mapping.SourceType,
			&mapping.SourceID,
			&mapping.MatchType,
			&mapping.MatchValue,
			&mapping.DepartmentID,
			&mapping.Priority,
			&mapping.Enabled,
		); err != nil {
			return nil, fmt.Errorf("scan identity department mapping: %w", err)
		}
		mappings = append(mappings, mapping)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate identity department mappings: %w", err)
	}
	return mappings, nil
}

// ErrIdentityDepartmentMappingNotFound signals a Get/Delete miss within tenant.
var ErrIdentityDepartmentMappingNotFound = errors.New("identity department mapping not found")

// ErrIdentityDepartmentMappingConflict signals a natural-key uniqueness clash
// with a different primary key during Upsert.
var ErrIdentityDepartmentMappingConflict = errors.New("identity department mapping conflict")

// IdentityDepartmentMapping is the CRUD view of identity_department_mappings.
type IdentityDepartmentMapping struct {
	ID                 string
	TenantID           string
	SourceKind         string
	SourceID           string
	MatchType          string
	MatchValue         string
	TargetDepartmentID string
	Priority           int
	Enabled            bool
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

const idmCols = `id, tenant_id, source_kind, source_id, match_type, match_value,
	target_department_id, priority, enabled, created_at, updated_at`

// List returns mappings for a tenant, optionally filtered by source kind/id.
// An empty sourceKind or sourceID disables that filter.
func (r *IdentityDepartmentMappingRepository) List(
	ctx context.Context, tenantID, sourceKind, sourceID string,
) ([]*IdentityDepartmentMapping, error) {
	rows, err := r.db.Query(ctx, `
		SELECT `+idmCols+`
		FROM identity_department_mappings
		WHERE tenant_id = $1
		  AND ($2 = '' OR source_kind = $2)
		  AND ($3 = '' OR source_id = $3)
		ORDER BY source_kind ASC, source_id ASC, priority ASC, match_value ASC`,
		tenantID, sourceKind, sourceID)
	if err != nil {
		return nil, fmt.Errorf("list identity department mappings: %w", err)
	}
	defer rows.Close()
	out := make([]*IdentityDepartmentMapping, 0)
	for rows.Next() {
		var m IdentityDepartmentMapping
		if err := rows.Scan(
			&m.ID, &m.TenantID, &m.SourceKind, &m.SourceID, &m.MatchType, &m.MatchValue,
			&m.TargetDepartmentID, &m.Priority, &m.Enabled, &m.CreatedAt, &m.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan identity department mapping: %w", err)
		}
		out = append(out, &m)
	}
	return out, rows.Err()
}

// Get returns a single mapping by id within the tenant, or nil,nil when absent.
func (r *IdentityDepartmentMappingRepository) Get(
	ctx context.Context, tenantID, id string,
) (*IdentityDepartmentMapping, error) {
	var m IdentityDepartmentMapping
	err := r.db.QueryRow(ctx, `
		SELECT `+idmCols+`
		FROM identity_department_mappings
		WHERE tenant_id = $1 AND id = $2`, tenantID, id).Scan(
		&m.ID, &m.TenantID, &m.SourceKind, &m.SourceID, &m.MatchType, &m.MatchValue,
		&m.TargetDepartmentID, &m.Priority, &m.Enabled, &m.CreatedAt, &m.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("get identity department mapping: %w", err)
	}
	return &m, nil
}

// Upsert inserts (m.ID empty) or updates (m.ID set) a mapping. A natural-key
// collision with a different id yields ErrIdentityDepartmentMappingConflict;
// an update to a missing id yields ErrIdentityDepartmentMappingNotFound.
func (r *IdentityDepartmentMappingRepository) Upsert(
	ctx context.Context, m *IdentityDepartmentMapping,
) error {
	if m == nil {
		return fmt.Errorf("nil identity department mapping")
	}
	if m.Priority == 0 {
		m.Priority = 100
	}
	if m.ID == "" {
		m.ID = "idm_" + uuid.NewString()[:12]
		_, err := r.db.Exec(ctx, `
			INSERT INTO identity_department_mappings (
				id, tenant_id, source_kind, source_id, match_type, match_value,
				target_department_id, priority, enabled
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			m.ID, m.TenantID, m.SourceKind, m.SourceID, m.MatchType, m.MatchValue,
			m.TargetDepartmentID, m.Priority, m.Enabled)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrIdentityDepartmentMappingConflict
			}
			return fmt.Errorf("create identity department mapping: %w", err)
		}
		return nil
	}
	ct, err := r.db.Exec(ctx, `
		UPDATE identity_department_mappings
		SET source_kind=$3, source_id=$4, match_type=$5, match_value=$6,
		    target_department_id=$7, priority=$8, enabled=$9, updated_at=now()
		WHERE tenant_id=$1 AND id=$2`,
		m.TenantID, m.ID, m.SourceKind, m.SourceID, m.MatchType, m.MatchValue,
		m.TargetDepartmentID, m.Priority, m.Enabled)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrIdentityDepartmentMappingConflict
		}
		return fmt.Errorf("update identity department mapping: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrIdentityDepartmentMappingNotFound
	}
	return nil
}

// Delete removes a mapping by id within the tenant.
func (r *IdentityDepartmentMappingRepository) Delete(
	ctx context.Context, tenantID, id string,
) error {
	ct, err := r.db.Exec(ctx,
		`DELETE FROM identity_department_mappings WHERE tenant_id=$1 AND id=$2`,
		tenantID, id)
	if err != nil {
		return fmt.Errorf("delete identity department mapping: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrIdentityDepartmentMappingNotFound
	}
	return nil
}
