package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ModelPolicy represents a model policy
type ModelPolicy struct {
	ID        string
	TenantID  string
	ProjectID string
	ScopeType string
	ScopeRef  string
	AllowList []string
	DenyList  []string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ModelPolicyRepository handles model policy database operations
type ModelPolicyRepository struct {
	db *pgxpool.Pool
}

// NewModelPolicyRepository creates a new model policy repository
func NewModelPolicyRepository(db *pgxpool.Pool) *ModelPolicyRepository {
	return &ModelPolicyRepository{db: db}
}

// GetByProject retrieves model policy for a project within a tenant.
func (r *ModelPolicyRepository) GetByProject(ctx context.Context, tenantID, projectID string) (*ModelPolicy, error) {
	query := `
		SELECT id, tenant_id, COALESCE(project_id, '') AS project_id, scope_type, COALESCE(scope_ref, '') AS scope_ref, allow_models_json, deny_models_json, created_at, updated_at
		FROM model_policies
		WHERE tenant_id = $1 AND project_id = $2 AND scope_type = 'project'
	`

	row := r.db.QueryRow(ctx, query, tenantID, projectID)
	var policy ModelPolicy
	var allowJSON, denyJSON []byte
	err := row.Scan(
		&policy.ID,
		&policy.TenantID,
		&policy.ProjectID,
		&policy.ScopeType,
		&policy.ScopeRef,
		&allowJSON,
		&denyJSON,
		&policy.CreatedAt,
		&policy.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get model policy: %w", err)
	}

	// Parse JSON arrays
	if len(allowJSON) > 0 {
		json.Unmarshal(allowJSON, &policy.AllowList)
	}
	if len(denyJSON) > 0 {
		json.Unmarshal(denyJSON, &policy.DenyList)
	}

	return &policy, nil
}

// List retrieves model policies for a tenant
func (r *ModelPolicyRepository) List(ctx context.Context, tenantID string) ([]*ModelPolicy, error) {
	query := `
		SELECT id, tenant_id, COALESCE(project_id, '') AS project_id, scope_type, COALESCE(scope_ref, '') AS scope_ref, allow_models_json, deny_models_json, created_at, updated_at
		FROM model_policies
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list model policies: %w", err)
	}
	defer rows.Close()

	policies := []*ModelPolicy{}
	for rows.Next() {
		var policy ModelPolicy
		var allowJSON, denyJSON []byte
		err := rows.Scan(
			&policy.ID,
			&policy.TenantID,
			&policy.ProjectID,
			&policy.ScopeType,
			&policy.ScopeRef,
			&allowJSON,
			&denyJSON,
			&policy.CreatedAt,
			&policy.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		if len(allowJSON) > 0 {
			json.Unmarshal(allowJSON, &policy.AllowList)
		}
		if len(denyJSON) > 0 {
			json.Unmarshal(denyJSON, &policy.DenyList)
		}

		policies = append(policies, &policy)
	}
	return policies, nil
}

// CreateOrUpdate creates or updates a model policy
func (r *ModelPolicyRepository) CreateOrUpdate(ctx context.Context, policy *ModelPolicy) error {
	allowJSON, _ := json.Marshal(policy.AllowList)
	denyJSON, _ := json.Marshal(policy.DenyList)
	projectID := nullableString(policy.ProjectID)
	scopeRef := nullableString(policy.ScopeRef)
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	var existingID string
	err = tx.QueryRow(ctx, `
		SELECT id
		FROM model_policies
		WHERE tenant_id = $1
		  AND project_id IS NOT DISTINCT FROM $2::varchar
		  AND scope_type = $3
		LIMIT 1
	`, policy.TenantID, projectID, policy.ScopeType).Scan(&existingID)

	switch err {
	case nil:
		policy.ID = existingID
		_, err = tx.Exec(ctx, `
			UPDATE model_policies
			SET scope_ref = $2,
				allow_models_json = $3,
				deny_models_json = $4,
				updated_at = NOW()
			WHERE id = $1
		`, policy.ID, scopeRef, allowJSON, denyJSON)
		if err != nil {
			return fmt.Errorf("failed to update model policy: %w", err)
		}
	case pgx.ErrNoRows:
		if policy.ID == "" {
			policy.ID = "mpol_" + uuid.New().String()[:8]
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO model_policies (id, tenant_id, project_id, scope_type, scope_ref, allow_models_json, deny_models_json)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`, policy.ID, policy.TenantID, projectID, policy.ScopeType, scopeRef, allowJSON, denyJSON)
		if err != nil {
			return fmt.Errorf("failed to create model policy: %w", err)
		}
	default:
		return fmt.Errorf("failed to lookup model policy: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit model policy: %w", err)
	}
	return nil
}

// IsModelAllowed checks if a model is allowed by policy
func (p *ModelPolicy) IsModelAllowed(modelName string) bool {
	// Check deny list first
	for _, m := range p.DenyList {
		if m == modelName {
			return false
		}
	}

	// If allow list is empty, all models are allowed (except deny list)
	if len(p.AllowList) == 0 {
		return true
	}

	// Check allow list
	for _, m := range p.AllowList {
		if m == modelName {
			return true
		}
	}

	return false
}

func nullableString(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}
