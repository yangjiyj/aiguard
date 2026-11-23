package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// RuleSet represents a rule set record
type RuleSet struct {
	ID         string
	TenantID   string
	Name       string
	Version    string
	SourceType string
	Published  bool
	CreatedBy  string
	CreatedAt  time.Time
}

// RuntimePolicyCapability is the compact detector contract compiled into a
// tenant rule pack. It deliberately excludes management-only labels and IDs.
type RuntimePolicyCapability struct {
	Category        string   `json:"category"`
	BindingMode     string   `json:"binding_mode"`
	Enabled         bool     `json:"enabled"`
	SupportedStages []string `json:"supported_stages"`
	AllowedActions  []string `json:"allowed_actions"`
	MaskCapable     bool     `json:"mask_capable"`
}

// Rule represents a rule within a rule set
type Rule struct {
	ID                  string
	PolicyCode          string
	RuleSetID           string
	RuleType            string
	Name                string
	Priority            int
	Severity            string
	ScopeJSON           []byte
	MatchConfigJSON     []byte
	Action              string
	Enabled             bool
	Description         string
	CreatedAt           time.Time
	RuntimeCapabilities []RuntimePolicyCapability
}

// RuleSetRepository handles rule set database operations
type RuleSetRepository struct {
	db *pgxpool.Pool
}

// NewRuleSetRepository creates a new rule set repository
func NewRuleSetRepository(db *pgxpool.Pool) *RuleSetRepository {
	return &RuleSetRepository{db: db}
}

// List retrieves rule sets for a tenant
func (r *RuleSetRepository) List(ctx context.Context, tenantID string) ([]*RuleSet, error) {
	query := `
		SELECT id, tenant_id, name, version, source_type, published, created_by, created_at
		FROM rule_sets
		WHERE tenant_id = $1
		ORDER BY created_at DESC
	`

	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list rule sets: %w", err)
	}
	defer rows.Close()

	ruleSets := []*RuleSet{}
	for rows.Next() {
		var rs RuleSet
		err := rows.Scan(
			&rs.ID,
			&rs.TenantID,
			&rs.Name,
			&rs.Version,
			&rs.SourceType,
			&rs.Published,
			&rs.CreatedBy,
			&rs.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		ruleSets = append(ruleSets, &rs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate rule sets: %w", err)
	}
	return ruleSets, nil
}

// GetByID retrieves a rule set by ID with tenant scope
func (r *RuleSetRepository) GetByID(ctx context.Context, tenantID, id string) (*RuleSet, error) {
	query := `
		SELECT id, tenant_id, name, version, source_type, published, created_by, created_at
		FROM rule_sets
		WHERE tenant_id = $1 AND id = $2
	`

	row := r.db.QueryRow(ctx, query, tenantID, id)
	var rs RuleSet
	err := row.Scan(
		&rs.ID,
		&rs.TenantID,
		&rs.Name,
		&rs.Version,
		&rs.SourceType,
		&rs.Published,
		&rs.CreatedBy,
		&rs.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get rule set: %w", err)
	}
	return &rs, nil
}

// Create creates a new rule set
func (r *RuleSetRepository) Create(ctx context.Context, tenantID string, ruleSet *RuleSet) error {
	ruleSet.TenantID = tenantID
	if ruleSet.ID == "" {
		ruleSet.ID = "rs_" + uuid.New().String()[:8]
	}

	query := `
		INSERT INTO rule_sets (id, tenant_id, name, version, source_type, published, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := r.db.Exec(ctx, query,
		ruleSet.ID,
		tenantID,
		ruleSet.Name,
		ruleSet.Version,
		ruleSet.SourceType,
		ruleSet.Published,
		ruleSet.CreatedBy,
	)

	if err != nil {
		return fmt.Errorf("failed to create rule set: %w", err)
	}
	return nil
}

// Ensure atomically creates a stable rule-set ID when absent and returns the
// tenant-owned persisted row. A conflicting ID owned by another tenant is never
// treated as success.
func (r *RuleSetRepository) Ensure(ctx context.Context, tenantID string, ruleSet *RuleSet) (*RuleSet, bool, error) {
	ruleSet.TenantID = tenantID
	if ruleSet.ID == "" {
		ruleSet.ID = "rs_" + uuid.New().String()[:8]
	}

	result, err := r.db.Exec(ctx, `
		INSERT INTO rule_sets (id, tenant_id, name, version, source_type, published, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (id) DO NOTHING
	`, ruleSet.ID, tenantID, ruleSet.Name, ruleSet.Version, ruleSet.SourceType, ruleSet.Published, ruleSet.CreatedBy)
	if err != nil {
		return nil, false, fmt.Errorf("failed to ensure rule set: %w", err)
	}

	persisted, err := r.GetByID(ctx, tenantID, ruleSet.ID)
	if err != nil {
		return nil, false, err
	}
	if persisted == nil {
		return nil, false, ErrRuleSetNotFound
	}
	return persisted, result.RowsAffected() == 1, nil
}

// Publish marks a rule set as published
func (r *RuleSetRepository) Publish(ctx context.Context, tenantID, id string) error {
	query := `
		UPDATE rule_sets
		SET published = true
		WHERE tenant_id = $1 AND id = $2
	`

	result, err := r.db.Exec(ctx, query, tenantID, id)
	if err != nil {
		return fmt.Errorf("failed to publish rule set: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("rule set not found or not owned by tenant")
	}
	return nil
}

// ListRules retrieves rules for a rule set
func (r *RuleSetRepository) ListRules(ctx context.Context, tenantID, ruleSetID string) ([]*Rule, error) {
	var owned bool
	if err := r.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM rule_sets WHERE id=$1 AND tenant_id=$2)`,
		ruleSetID, tenantID,
	).Scan(&owned); err != nil {
		return nil, fmt.Errorf("verify rule set ownership: %w", err)
	}
	if !owned {
		return nil, ErrRuleSetNotFound
	}
	query := `
		SELECT r.id, r.rule_set_id, r.rule_type, r.name, r.priority, r.severity, r.scope_json, r.match_config_json, r.action, r.enabled, r.description, r.created_at
		FROM rules r
		JOIN rule_sets rs ON rs.id=r.rule_set_id
		WHERE r.rule_set_id = $1 AND rs.tenant_id=$2
		  AND NOT jsonb_exists(COALESCE(r.scope_json,'{}'::jsonb),'deleted_at')
		ORDER BY r.priority DESC, r.created_at
	`

	rows, err := r.db.Query(ctx, query, ruleSetID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list rules: %w", err)
	}
	defer rows.Close()

	rules := []*Rule{}
	for rows.Next() {
		var rule Rule
		err := rows.Scan(
			&rule.ID,
			&rule.RuleSetID,
			&rule.RuleType,
			&rule.Name,
			&rule.Priority,
			&rule.Severity,
			&rule.ScopeJSON,
			&rule.MatchConfigJSON,
			&rule.Action,
			&rule.Enabled,
			&rule.Description,
			&rule.CreatedAt,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, &rule)
	}
	return rules, nil
}
