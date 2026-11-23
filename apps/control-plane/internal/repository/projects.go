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

// Project represents a project record
type Project struct {
	ID             string
	TenantID       string
	Name           string
	Code           string
	Environment    string
	OwnerUserID    string
	TeamID         string
	Status         string
	ModelWhitelist []string       // JSONB array of allowed model IDs
	QuotaLimits    map[string]any // JSONB object for quota limits
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// ProjectRepository handles project database operations
type ProjectRepository struct {
	db *pgxpool.Pool
}

// NewProjectRepository creates a new project repository
func NewProjectRepository(db *pgxpool.Pool) *ProjectRepository {
	return &ProjectRepository{db: db}
}

// GetByID retrieves a project by ID within a tenant.
func (r *ProjectRepository) GetByID(ctx context.Context, tenantID, id string) (*Project, error) {
	query := `
		SELECT id, tenant_id, name, code, environment, COALESCE(owner_user_id,''), COALESCE(team_id,''), status, model_whitelist, quota_limits, created_at, updated_at
		FROM projects
		WHERE tenant_id = $1 AND id = $2 AND status <> 'deleted'
	`

	row := r.db.QueryRow(ctx, query, tenantID, id)
	var project Project
	var modelWhitelistJSON, quotaLimitsJSON []byte
	err := row.Scan(
		&project.ID,
		&project.TenantID,
		&project.Name,
		&project.Code,
		&project.Environment,
		&project.OwnerUserID,
		&project.TeamID,
		&project.Status,
		&modelWhitelistJSON,
		&quotaLimitsJSON,
		&project.CreatedAt,
		&project.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get project: %w", err)
	}

	// Parse JSONB fields
	if len(modelWhitelistJSON) > 0 {
		if err := json.Unmarshal(modelWhitelistJSON, &project.ModelWhitelist); err != nil {
			project.ModelWhitelist = []string{}
		}
	} else {
		project.ModelWhitelist = []string{}
	}

	if len(quotaLimitsJSON) > 0 {
		if err := json.Unmarshal(quotaLimitsJSON, &project.QuotaLimits); err != nil {
			project.QuotaLimits = map[string]any{}
		}
	} else {
		project.QuotaLimits = map[string]any{}
	}

	return &project, nil
}

// List retrieves projects for a tenant
func (r *ProjectRepository) List(ctx context.Context, tenantID string) ([]*Project, error) {
	query := `
		SELECT id, tenant_id, name, code, environment, COALESCE(owner_user_id,''), COALESCE(team_id,''), status, model_whitelist, quota_limits, created_at, updated_at
		FROM projects
		WHERE tenant_id = $1 AND status <> 'deleted'
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list projects: %w", err)
	}
	defer rows.Close()

	projects := []*Project{}
	for rows.Next() {
		var project Project
		var modelWhitelistJSON, quotaLimitsJSON []byte
		err := rows.Scan(
			&project.ID,
			&project.TenantID,
			&project.Name,
			&project.Code,
			&project.Environment,
			&project.OwnerUserID,
			&project.TeamID,
			&project.Status,
			&modelWhitelistJSON,
			&quotaLimitsJSON,
			&project.CreatedAt,
			&project.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}

		// Parse JSONB fields
		if len(modelWhitelistJSON) > 0 {
			if err := json.Unmarshal(modelWhitelistJSON, &project.ModelWhitelist); err != nil {
				project.ModelWhitelist = []string{}
			}
		} else {
			project.ModelWhitelist = []string{}
		}

		if len(quotaLimitsJSON) > 0 {
			if err := json.Unmarshal(quotaLimitsJSON, &project.QuotaLimits); err != nil {
				project.QuotaLimits = map[string]any{}
			}
		} else {
			project.QuotaLimits = map[string]any{}
		}

		projects = append(projects, &project)
	}
	return projects, nil
}

// CountByTenant returns the number of projects in a tenant without scanning full rows.
func (r *ProjectRepository) CountByTenant(ctx context.Context, tenantID string) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `
		SELECT COUNT(*)
		FROM projects
		WHERE tenant_id = $1 AND status <> 'deleted'
	`, tenantID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count projects by tenant: %w", err)
	}
	return count, nil
}

// Create creates a new project
func (r *ProjectRepository) Create(ctx context.Context, project *Project) error {
	if project.ID == "" {
		project.ID = "proj_" + uuid.New().String()[:8]
	}

	// Initialize default values for new fields
	if project.ModelWhitelist == nil {
		project.ModelWhitelist = []string{}
	}
	if project.QuotaLimits == nil {
		project.QuotaLimits = map[string]any{}
	}

	modelWhitelistJSON, err := json.Marshal(project.ModelWhitelist)
	if err != nil {
		return fmt.Errorf("failed to marshal model_whitelist: %w", err)
	}

	quotaLimitsJSON, err := json.Marshal(project.QuotaLimits)
	if err != nil {
		return fmt.Errorf("failed to marshal quota_limits: %w", err)
	}

	query := `
		INSERT INTO projects (id, tenant_id, name, code, environment, owner_user_id, status, model_whitelist, quota_limits)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`

	// owner_user_id 是 users(id) 外键：空串会撞 FK。机器通道（门户代建）无会话 owner，
	// 空 owner 落 NULL；会话端一贯带 owner，行为不变。
	var ownerVal interface{}
	if project.OwnerUserID != "" {
		ownerVal = project.OwnerUserID
	}

	_, err = r.db.Exec(ctx, query,
		project.ID,
		project.TenantID,
		project.Name,
		project.Code,
		project.Environment,
		ownerVal,
		project.Status,
		modelWhitelistJSON,
		quotaLimitsJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to create project: %w", err)
	}
	return nil
}

// Update updates a project
func (r *ProjectRepository) Update(ctx context.Context, project *Project) error {
	// Initialize default values for new fields
	if project.ModelWhitelist == nil {
		project.ModelWhitelist = []string{}
	}
	if project.QuotaLimits == nil {
		project.QuotaLimits = map[string]any{}
	}

	modelWhitelistJSON, err := json.Marshal(project.ModelWhitelist)
	if err != nil {
		return fmt.Errorf("failed to marshal model_whitelist: %w", err)
	}

	quotaLimitsJSON, err := json.Marshal(project.QuotaLimits)
	if err != nil {
		return fmt.Errorf("failed to marshal quota_limits: %w", err)
	}

	query := `
		UPDATE projects
		SET name = $2, code = $3, environment = $4, owner_user_id = $5, status = $6, model_whitelist = $7, quota_limits = $8, updated_at = NOW()
		WHERE id = $1 AND tenant_id = $9
	`

	// 同 Create：空 owner 落 NULL，避免会话端编辑门户代建（无 owner）项目时撞 FK。
	var ownerVal interface{}
	if project.OwnerUserID != "" {
		ownerVal = project.OwnerUserID
	}

	result, err := r.db.Exec(ctx, query,
		project.ID,
		project.Name,
		project.Code,
		project.Environment,
		ownerVal,
		project.Status,
		modelWhitelistJSON,
		quotaLimitsJSON,
		project.TenantID,
	)

	if err != nil {
		return fmt.Errorf("failed to update project: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("project not found")
	}
	return nil
}

// UpdateModelConfig updates the model whitelist and quota limits for a project
func (r *ProjectRepository) UpdateModelConfig(ctx context.Context, id string, whitelist, quotaLimits string) error {
	query := `
		UPDATE projects
		SET model_whitelist = $1, quota_limits = $2, updated_at = CURRENT_TIMESTAMP
		WHERE id = $3
	`
	result, err := r.db.Exec(ctx, query, whitelist, quotaLimits, id)
	if err != nil {
		return fmt.Errorf("failed to update model config: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("project not found")
	}
	return nil
}

// Delete removes a project by ID
func (r *ProjectRepository) Delete(ctx context.Context, tenantID, id string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin project deletion: %w", err)
	}
	defer tx.Rollback(ctx)

	result, err := tx.Exec(ctx, `
		UPDATE projects
		SET status = 'deleted', updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2 AND status <> 'deleted'
	`, tenantID, id)
	if err != nil {
		return fmt.Errorf("mark project deleted: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("project not found")
	}

	_, err = tx.Exec(ctx, `
		UPDATE internal_keys
		SET status = 'revoked', last_used_at = NOW()
		WHERE tenant_id = $1 AND project_id = $2 AND status <> 'revoked'
	`, tenantID, id)
	if err != nil {
		return fmt.Errorf("revoke project keys: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit project deletion: %w", err)
	}
	return nil
}

// UpdateTeam sets the team_id for a project (pass empty string to unassign).
func (r *ProjectRepository) UpdateTeam(ctx context.Context, tenantID, projectID, teamID string) error {
	var teamIDVal interface{}
	if teamID != "" {
		teamIDVal = teamID
	}
	result, err := r.db.Exec(ctx,
		`UPDATE projects SET team_id = $1, updated_at = NOW() WHERE tenant_id = $2 AND id = $3`,
		teamIDVal, tenantID, projectID)
	if err != nil {
		return fmt.Errorf("update project team: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("project not found")
	}
	return nil
}

// ListByTeam returns all projects belonging to a team.
func (r *ProjectRepository) ListByTeam(ctx context.Context, tenantID, teamID string) ([]*Project, error) {
	query := `
		SELECT id, tenant_id, name, code, environment, COALESCE(owner_user_id,''), COALESCE(team_id,''), status, model_whitelist, quota_limits, created_at, updated_at
		FROM projects
		WHERE tenant_id = $1 AND team_id = $2 AND status <> 'deleted'
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(ctx, query, tenantID, teamID)
	if err != nil {
		return nil, fmt.Errorf("list projects by team: %w", err)
	}
	defer rows.Close()

	var projects []*Project
	for rows.Next() {
		var project Project
		var modelWhitelistJSON, quotaLimitsJSON []byte
		err := rows.Scan(
			&project.ID, &project.TenantID, &project.Name, &project.Code,
			&project.Environment, &project.OwnerUserID, &project.TeamID, &project.Status,
			&modelWhitelistJSON, &quotaLimitsJSON, &project.CreatedAt, &project.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		if len(modelWhitelistJSON) > 0 {
			if err := json.Unmarshal(modelWhitelistJSON, &project.ModelWhitelist); err != nil {
				project.ModelWhitelist = []string{}
			}
		} else {
			project.ModelWhitelist = []string{}
		}
		if len(quotaLimitsJSON) > 0 {
			if err := json.Unmarshal(quotaLimitsJSON, &project.QuotaLimits); err != nil {
				project.QuotaLimits = map[string]any{}
			}
		} else {
			project.QuotaLimits = map[string]any{}
		}
		projects = append(projects, &project)
	}
	return projects, rows.Err()
}
