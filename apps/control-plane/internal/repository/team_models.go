package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TeamModel represents a team's model whitelist entry.
type TeamModel struct {
	TeamID          string    `json:"team_id"`
	ModelID         string    `json:"model_id"`
	Allowed         bool      `json:"allowed"`
	DailyTokenLimit *int64    `json:"daily_token_limit,omitempty"`
	GrantedBy       string    `json:"granted_by,omitempty"`
	GrantedAt       time.Time `json:"granted_at"`
}

// TeamModelRepository handles team_models database operations.
type TeamModelRepository struct {
	db *pgxpool.Pool
}

// NewTeamModelRepository creates a new TeamModelRepository.
func NewTeamModelRepository(db *pgxpool.Pool) *TeamModelRepository {
	return &TeamModelRepository{db: db}
}

// ListByTeam returns all model whitelist entries for a team.
func (r *TeamModelRepository) ListByTeam(ctx context.Context, teamID string) ([]*TeamModel, error) {
	rows, err := r.db.Query(ctx, `
		SELECT team_id, model_id, allowed, daily_token_limit, COALESCE(granted_by,''), granted_at
		FROM team_models
		WHERE team_id = $1
		ORDER BY model_id
	`, teamID)
	if err != nil {
		return nil, fmt.Errorf("list team models: %w", err)
	}
	defer rows.Close()
	return scanTeamModelRows(rows)
}

// ListAllowedModelNames returns data-plane model names allowed for a team.
func (r *TeamModelRepository) ListAllowedModelNames(ctx context.Context, tenantID, teamID string) ([]string, error) {
	rows, err := r.db.Query(ctx, `
		SELECT DISTINCT m.model_name
		FROM teams t
		JOIN providers p ON p.tenant_id = t.tenant_id
		JOIN models m ON m.provider_id = p.id
		LEFT JOIN team_models tm ON tm.team_id = t.id AND tm.model_id = m.id
		WHERE t.id = $1
		  AND t.tenant_id = $2
		  AND p.tenant_id = $2
		  AND p.status = 'active'
		  AND m.status = 'active'
		  AND (
		    t.model_access_mode = 'all_active'
		    OR (t.model_access_mode = 'allowlist' AND tm.allowed = TRUE)
		  )
		ORDER BY m.model_name
	`, teamID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list allowed team model names: %w", err)
	}
	defer rows.Close()

	names := make([]string, 0)
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("scan allowed team model name: %w", err)
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list allowed team model names: %w", err)
	}
	return names, nil
}

// Upsert inserts or updates a team_model entry.
func (r *TeamModelRepository) Upsert(ctx context.Context, tm *TeamModel) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO team_models (team_id, model_id, allowed, daily_token_limit, granted_by, granted_at)
		VALUES ($1, $2, $3, $4, $5, NOW())
		ON CONFLICT (team_id, model_id) DO UPDATE
		  SET allowed = EXCLUDED.allowed,
		      daily_token_limit = EXCLUDED.daily_token_limit,
		      granted_by = EXCLUDED.granted_by,
		      granted_at = NOW()
	`, tm.TeamID, tm.ModelID, tm.Allowed, tm.DailyTokenLimit, nullableString(tm.GrantedBy))
	if err != nil {
		return fmt.Errorf("upsert team model: %w", err)
	}
	return nil
}

// UpsertBatch inserts or updates multiple team_model entries in a single transaction.
func (r *TeamModelRepository) UpsertBatch(ctx context.Context, teamID string, entries []*TeamModel) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	for _, tm := range entries {
		tm.TeamID = teamID
		_, err := tx.Exec(ctx, `
			INSERT INTO team_models (team_id, model_id, allowed, daily_token_limit, granted_by, granted_at)
			VALUES ($1, $2, $3, $4, $5, NOW())
			ON CONFLICT (team_id, model_id) DO UPDATE
			  SET allowed = EXCLUDED.allowed,
			      daily_token_limit = EXCLUDED.daily_token_limit,
			      granted_by = EXCLUDED.granted_by,
			      granted_at = NOW()
		`, tm.TeamID, tm.ModelID, tm.Allowed, tm.DailyTokenLimit, nullableString(tm.GrantedBy))
		if err != nil {
			return fmt.Errorf("upsert team model %s: %w", tm.ModelID, err)
		}
	}
	return tx.Commit(ctx)
}

// ReplaceAllowlist atomically switches a department from a dynamic policy to
// an explicit allowlist and replaces its entries. An empty list is deny-all.
func (r *TeamModelRepository) ReplaceAllowlist(ctx context.Context, teamID string, entries []*TeamModel) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin replace team model policy: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if tag, err := tx.Exec(ctx, `UPDATE teams SET model_access_mode='allowlist',model_access_configured=true WHERE id=$1`, teamID); err != nil {
		return fmt.Errorf("set team model access mode: %w", err)
	} else if tag.RowsAffected() != 1 {
		return fmt.Errorf("team not found")
	}
	if _, err := tx.Exec(ctx, `DELETE FROM team_models WHERE team_id=$1`, teamID); err != nil {
		return fmt.Errorf("clear team model allowlist: %w", err)
	}
	for _, tm := range entries {
		if _, err := tx.Exec(ctx, `
			INSERT INTO team_models (team_id,model_id,allowed,daily_token_limit,granted_by,granted_at)
			VALUES ($1,$2,$3,$4,$5,NOW())
		`, teamID, tm.ModelID, tm.Allowed, tm.DailyTokenLimit, nullableString(tm.GrantedBy)); err != nil {
			return fmt.Errorf("replace team model %s: %w", tm.ModelID, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit replace team model policy: %w", err)
	}
	return nil
}

// Delete removes a model from a team's whitelist.
func (r *TeamModelRepository) Delete(ctx context.Context, teamID, modelID string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin delete team model: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var tenantID, accessMode string
	if err := tx.QueryRow(ctx, `SELECT tenant_id,model_access_mode FROM teams WHERE id=$1 FOR UPDATE`, teamID).Scan(&tenantID, &accessMode); err != nil {
		return fmt.Errorf("read team model policy: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE teams SET model_access_configured=true WHERE id=$1`, teamID); err != nil {
		return err
	}
	if accessMode == "all_active" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO team_models (team_id,model_id,allowed,granted_at)
			SELECT $1,m.id,TRUE,NOW()
			FROM models m JOIN providers p ON p.id=m.provider_id
			WHERE p.tenant_id=$2 AND p.status='active' AND m.status='active' AND m.id<>$3
			ON CONFLICT (team_id,model_id) DO UPDATE SET allowed=TRUE,granted_at=NOW()
		`, teamID, tenantID, modelID); err != nil {
			return fmt.Errorf("materialize all-active team policy: %w", err)
		}
		if _, err := tx.Exec(ctx, `UPDATE teams SET model_access_mode='allowlist',model_access_configured=true WHERE id=$1`, teamID); err != nil {
			return fmt.Errorf("switch team model policy to allowlist: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM team_models WHERE team_id=$1 AND model_id=$2`, teamID, modelID); err != nil {
		return fmt.Errorf("delete team model: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit delete team model: %w", err)
	}
	return nil
}

// DeleteAllForTeam removes all model entries for a team.
func (r *TeamModelRepository) DeleteAllForTeam(ctx context.Context, teamID string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM team_models WHERE team_id = $1`, teamID)
	if err != nil {
		return fmt.Errorf("delete all team models: %w", err)
	}
	return nil
}

// HasModel returns true if the team has the model in its whitelist (allowed=true).
func (r *TeamModelRepository) HasModel(ctx context.Context, teamID, modelID string) (bool, error) {
	var allowed bool
	err := r.db.QueryRow(ctx, `
		SELECT allowed FROM team_models WHERE team_id = $1 AND model_id = $2
	`, teamID, modelID).Scan(&allowed)
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("has model: %w", err)
	}
	return allowed, nil
}

func scanTeamModelRows(rows pgx.Rows) ([]*TeamModel, error) {
	var items []*TeamModel
	for rows.Next() {
		var tm TeamModel
		var limit *int64
		if err := rows.Scan(&tm.TeamID, &tm.ModelID, &tm.Allowed, &limit, &tm.GrantedBy, &tm.GrantedAt); err != nil {
			return nil, err
		}
		tm.DailyTokenLimit = limit
		items = append(items, &tm)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func (r *TeamModelRepository) GetAccessMode(ctx context.Context, tenant, team string) (string, bool, error) {
	var mode string
	var configured bool
	err := r.db.QueryRow(ctx, `SELECT model_access_mode,model_access_configured FROM teams WHERE tenant_id=$1 AND id=$2`, tenant, team).Scan(&mode, &configured)
	return mode, configured, err
}

func (r *TeamModelRepository) SetAccessMode(ctx context.Context, tenant, team, mode string) error {
	if mode != "all_active" && mode != "deny_all" {
		return fmt.Errorf("invalid department model access mode")
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE teams SET model_access_mode=$3,model_access_configured=true WHERE tenant_id=$1 AND id=$2 AND NOT is_system`, tenant, team, mode)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	if _, err = tx.Exec(ctx, `DELETE FROM team_models WHERE team_id=$1`, team); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
