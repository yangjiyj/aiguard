package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Team represents an organisational team (department node in the tree).
type Team struct {
	ID           string    `json:"id"`
	TenantID     string    `json:"tenant_id"`
	Name         string    `json:"name"`
	ParentTeamID string    `json:"parent_team_id,omitempty"`
	Path         string    `json:"path"`
	CreatedAt    time.Time `json:"created_at"`
}

// TeamRepository handles team database operations.
type TeamRepository struct {
	db *pgxpool.Pool
}

func (r *TeamRepository) GetBySystemKey(ctx context.Context, tenantID, systemKey string) (*Team, error) {
	var team Team
	var parentID *string
	err := r.db.QueryRow(ctx, `
		SELECT id,tenant_id,name,parent_team_id,path,created_at
		FROM teams
		WHERE tenant_id=$1 AND system_key=$2
	`, tenantID, systemKey).Scan(
		&team.ID, &team.TenantID, &team.Name, &parentID, &team.Path, &team.CreatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get team by system key: %w", err)
	}
	if parentID != nil {
		team.ParentTeamID = *parentID
	}
	return &team, nil
}

// NewTeamRepository creates a new TeamRepository.
func NewTeamRepository(db *pgxpool.Pool) *TeamRepository {
	return &TeamRepository{db: db}
}

// Create inserts a new team. parentPath is the materialised path of the parent
// (empty string for a root team). The team's Path field is set on success.
func (r *TeamRepository) Create(ctx context.Context, team *Team, parentPath string) error {
	path := parentPath + "/" + team.ID
	parentID := nullableString(team.ParentTeamID)
	_, err := r.db.Exec(ctx, `
		INSERT INTO teams (id, tenant_id, name, parent_team_id, path)
		VALUES ($1, $2, $3, $4, $5)
	`, team.ID, team.TenantID, team.Name, parentID, path)
	if err != nil {
		return fmt.Errorf("create team: %w", err)
	}
	team.Path = path
	return nil
}

// GetByID retrieves a single team by primary key. Returns nil, nil when not found.
func (r *TeamRepository) GetByID(ctx context.Context, id string) (*Team, error) {
	var t Team
	var parentID *string
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, name, parent_team_id, path, created_at
		FROM teams WHERE id = $1 AND is_system = FALSE
	`, id).Scan(&t.ID, &t.TenantID, &t.Name, &parentID, &t.Path, &t.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get team: %w", err)
	}
	if parentID != nil {
		t.ParentTeamID = *parentID
	}
	return &t, nil
}

// ListByTenant returns all teams for a tenant, ordered by materialised path.
func (r *TeamRepository) ListByTenant(ctx context.Context, tenantID string) ([]*Team, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, name, parent_team_id, path, created_at
		FROM teams
		WHERE tenant_id = $1 AND is_system = FALSE
		ORDER BY path
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list teams: %w", err)
	}
	defer rows.Close()
	return scanTeamRows(rows)
}

// ListSubtree returns all descendants of basePath (exclusive), ordered by path.
// basePath should be the team's own path, e.g. "/root_id".
func (r *TeamRepository) ListSubtree(ctx context.Context, basePath string) ([]*Team, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, name, parent_team_id, path, created_at
		FROM teams WHERE path LIKE $1 ORDER BY path
	`, basePath+"/%")
	if err != nil {
		return nil, fmt.Errorf("list subtree: %w", err)
	}
	defer rows.Close()
	return scanTeamRows(rows)
}

// UpdateName renames a team.
func (r *TeamRepository) UpdateName(ctx context.Context, id, name string) error {
	_, err := r.db.Exec(ctx, `UPDATE teams SET name = $1 WHERE id = $2`, name, id)
	if err != nil {
		return fmt.Errorf("update team name: %w", err)
	}
	return nil
}

// TeamDeleteBlockers 是删除部门前必须先清掉的东西：还挂在部门下的成员（用户的 department_id 是
// RESTRICT 外键，库不会放行）和下级部门（删掉父部门会让它们悄悄变成一级部门，path 还停在旧父级下）。
// 部门下的应用不算：projects.team_id 是 ON DELETE SET NULL，应用本身保留，只是不再归属任何部门。
type TeamDeleteBlockers struct {
	Members    int `json:"members"`
	ChildTeams int `json:"child_teams"`
}

// DeleteBlockers 统计删除部门前的占用。已退役（status=deleted）的用户已不在任何列表里，不算。
func (r *TeamRepository) DeleteBlockers(ctx context.Context, tenantID, id string) (TeamDeleteBlockers, error) {
	var b TeamDeleteBlockers
	err := r.db.QueryRow(ctx, `
		SELECT
			(SELECT count(*) FROM users u
			  WHERE u.tenant_id = $1 AND u.status <> 'deleted'
			    AND (u.department_id = $2
			         OR EXISTS (SELECT 1 FROM team_members tm WHERE tm.team_id = $2 AND tm.user_id = u.id)))::int,
			(SELECT count(*) FROM teams c
			  WHERE c.tenant_id = $1 AND c.parent_team_id = $2 AND c.is_system = FALSE)::int
	`, tenantID, id).Scan(&b.Members, &b.ChildTeams)
	if err != nil {
		return TeamDeleteBlockers{}, fmt.Errorf("count team delete blockers: %w", err)
	}
	return b, nil
}

// Delete removes a team by ID. Child teams' parent_team_id is set to NULL by
// the ON DELETE SET NULL FK, but their path is not updated here.
func (r *TeamRepository) Delete(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM teams WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete team: %w", err)
	}
	return nil
}

// scanTeamRows is a shared row scanner for ListByTenant / ListSubtree.
func scanTeamRows(rows pgx.Rows) ([]*Team, error) {
	var teams []*Team
	for rows.Next() {
		var t Team
		var parentID *string
		if err := rows.Scan(&t.ID, &t.TenantID, &t.Name, &parentID, &t.Path, &t.CreatedAt); err != nil {
			return nil, err
		}
		if parentID != nil {
			t.ParentTeamID = *parentID
		}
		teams = append(teams, &t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return teams, nil
}

// TeamWithBudget extends Team with budget fields.
type TeamWithBudget struct {
	Team
	MonthlyBudgetCNY float64 `json:"monthly_budget_cny"`
	DailyBudgetCNY   float64 `json:"daily_budget_cny"`
}

// UpdateBudget updates the monthly and daily budget for a team.
func (r *TeamRepository) UpdateBudget(ctx context.Context, id string, monthlyBudget, dailyBudget float64) error {
	_, err := r.db.Exec(ctx,
		`UPDATE teams SET monthly_budget_cny = $1, daily_budget_cny = $2 WHERE id = $3`,
		monthlyBudget, dailyBudget, id)
	if err != nil {
		return fmt.Errorf("update team budget: %w", err)
	}
	return nil
}

// GetWithBudget retrieves a team including its budget fields.
func (r *TeamRepository) GetWithBudget(ctx context.Context, tenantID, id string) (*TeamWithBudget, error) {
	var t TeamWithBudget
	var parentID *string
	err := r.db.QueryRow(ctx, `
		SELECT id, tenant_id, name, parent_team_id, path, created_at,
		       COALESCE(monthly_budget_cny, 0), COALESCE(daily_budget_cny, 0)
		FROM teams WHERE tenant_id = $1 AND id = $2 AND is_system = FALSE
	`, tenantID, id).Scan(&t.ID, &t.TenantID, &t.Name, &parentID, &t.Path, &t.CreatedAt,
		&t.MonthlyBudgetCNY, &t.DailyBudgetCNY)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get team with budget: %w", err)
	}
	if parentID != nil {
		t.ParentTeamID = *parentID
	}
	return &t, nil
}

// ListByTenantWithBudget returns all teams with budget info for a tenant.
func (r *TeamRepository) ListByTenantWithBudget(ctx context.Context, tenantID string) ([]*TeamWithBudget, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, tenant_id, name, parent_team_id, path, created_at,
		       COALESCE(monthly_budget_cny, 0), COALESCE(daily_budget_cny, 0)
		FROM teams
		WHERE tenant_id = $1 AND COALESCE(is_system, FALSE) = FALSE
		ORDER BY path
	`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list teams with budget: %w", err)
	}
	defer rows.Close()
	var teams []*TeamWithBudget
	for rows.Next() {
		var t TeamWithBudget
		var parentID *string
		if err := rows.Scan(&t.ID, &t.TenantID, &t.Name, &parentID, &t.Path, &t.CreatedAt,
			&t.MonthlyBudgetCNY, &t.DailyBudgetCNY); err != nil {
			return nil, err
		}
		if parentID != nil {
			t.ParentTeamID = *parentID
		}
		teams = append(teams, &t)
	}
	return teams, rows.Err()
}
