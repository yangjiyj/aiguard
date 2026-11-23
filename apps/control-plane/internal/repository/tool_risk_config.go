package repository

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ToolRiskConfig represents a tool risk configuration record
type ToolRiskConfig struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	ToolName    string    `json:"tool_name"`
	ToolType    string    `json:"tool_type"`  // file, network, database, mcp, system
	RiskLevel   string    `json:"risk_level"` // low, medium, high, critical
	Action      string    `json:"action"`     // allow, audit, block
	Description string    `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ToolRiskConfigRepository handles tool risk config database operations
type ToolRiskConfigRepository struct {
	db *pgxpool.Pool
}

// NewToolRiskConfigRepository creates a new tool risk config repository
func NewToolRiskConfigRepository(db *pgxpool.Pool) *ToolRiskConfigRepository {
	return &ToolRiskConfigRepository{db: db}
}

// GetByToolName retrieves a tool config by tool name for a tenant
func (r *ToolRiskConfigRepository) GetByToolName(ctx context.Context, tenantID, toolName string) (*ToolRiskConfig, error) {
	query := `
		SELECT id, tenant_id, tool_name, tool_type, risk_level, action, description, created_at, updated_at
		FROM tool_risk_config
		WHERE tenant_id = $1 AND tool_name = $2
	`
	row := r.db.QueryRow(ctx, query, tenantID, toolName)
	var c ToolRiskConfig
	err := row.Scan(&c.ID, &c.TenantID, &c.ToolName, &c.ToolType, &c.RiskLevel, &c.Action, &c.Description, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tool config: %w", err)
	}
	return &c, nil
}

// GetByID retrieves a tool config by ID
func (r *ToolRiskConfigRepository) GetByID(ctx context.Context, tenantID, id string) (*ToolRiskConfig, error) {
	query := `
		SELECT id, tenant_id, tool_name, tool_type, risk_level, action, description, created_at, updated_at
		FROM tool_risk_config
		WHERE tenant_id = $1 AND id = $2
	`
	row := r.db.QueryRow(ctx, query, tenantID, id)
	var c ToolRiskConfig
	err := row.Scan(&c.ID, &c.TenantID, &c.ToolName, &c.ToolType, &c.RiskLevel, &c.Action, &c.Description, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get tool config: %w", err)
	}
	return &c, nil
}

// List retrieves all tool configs for a tenant
func (r *ToolRiskConfigRepository) List(ctx context.Context, tenantID string) ([]ToolRiskConfig, error) {
	query := `
		SELECT id, tenant_id, tool_name, tool_type, risk_level, action, description, created_at, updated_at
		FROM tool_risk_config
		WHERE tenant_id = $1
		ORDER BY tool_name
	`
	rows, err := r.db.Query(ctx, query, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list tool configs: %w", err)
	}
	defer rows.Close()

	var configs []ToolRiskConfig
	for rows.Next() {
		var c ToolRiskConfig
		if err := rows.Scan(&c.ID, &c.TenantID, &c.ToolName, &c.ToolType, &c.RiskLevel, &c.Action, &c.Description, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		configs = append(configs, c)
	}
	return configs, nil
}

// Create creates a new tool risk config
func (r *ToolRiskConfigRepository) Create(ctx context.Context, config *ToolRiskConfig) error {
	if err := ValidateToolRiskConfig(config); err != nil {
		return err
	}
	if config.ID == "" {
		config.ID = "tr_" + uuid.New().String()[:8]
	}

	// Default values
	if config.RiskLevel == "" {
		config.RiskLevel = "medium"
	}
	if config.Action == "" {
		config.Action = "audit"
	}

	query := `
		INSERT INTO tool_risk_config (id, tenant_id, tool_name, tool_type, risk_level, action, description)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at, updated_at
	`
	err := r.db.QueryRow(ctx, query,
		config.ID, config.TenantID, config.ToolName, config.ToolType,
		config.RiskLevel, config.Action, config.Description,
	).Scan(&config.CreatedAt, &config.UpdatedAt)
	if err != nil {
		return fmt.Errorf("failed to create tool config: %w", err)
	}
	return nil
}

// Update updates an existing tool risk config
func (r *ToolRiskConfigRepository) Update(ctx context.Context, tenantID, id string, toolType, riskLevel, action, description string) error {
	config := &ToolRiskConfig{ToolName: id, ToolType: toolType, RiskLevel: riskLevel, Action: action, Description: description}
	if err := ValidateToolRiskConfig(config); err != nil {
		return err
	}
	query := `
		UPDATE tool_risk_config
		SET tool_type = $3, risk_level = $4, action = $5, description = $6, updated_at = NOW()
		WHERE tenant_id = $1 AND id = $2
	`
	result, err := r.db.Exec(ctx, query, tenantID, id, toolType, riskLevel, action, description)
	if err != nil {
		return fmt.Errorf("failed to update tool config: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("tool config not found")
	}
	return nil
}

// Delete removes a tool risk config
func (r *ToolRiskConfigRepository) Delete(ctx context.Context, tenantID, id string) error {
	query := `DELETE FROM tool_risk_config WHERE tenant_id = $1 AND id = $2`
	result, err := r.db.Exec(ctx, query, tenantID, id)
	if err != nil {
		return fmt.Errorf("failed to delete tool config: %w", err)
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("tool config not found")
	}
	return nil
}

// BatchUpsert creates or updates multiple tool configs in batch
func (r *ToolRiskConfigRepository) BatchUpsert(ctx context.Context, tenantID string, configs []ToolRiskConfig) (int, error) {
	applied, _, err := r.BatchUpsertPreserving(ctx, tenantID, configs, false)
	return applied, err
}

// ValidateToolRiskConfig validates the whole candidate before any write and applies
// only the documented defaults. Tool names retain their exact matching identity.
func ValidateToolRiskConfig(config *ToolRiskConfig) error {
	if config == nil || strings.TrimSpace(config.ToolName) == "" || len(config.ToolName) > 255 || !utf8.ValidString(config.ToolName) || strings.IndexFunc(config.ToolName, unicode.IsControl) >= 0 {
		return fmt.Errorf("tool_name must be a non-empty name of at most 255 bytes without control characters")
	}
	switch config.ToolType {
	case "file", "network", "database", "mcp", "system":
	default:
		return fmt.Errorf("tool_type must be file, network, database, mcp, or system")
	}
	if config.RiskLevel == "" {
		config.RiskLevel = "medium"
	}
	switch config.RiskLevel {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("risk_level must be low, medium, high, or critical")
	}
	if config.Action == "" {
		config.Action = "audit"
	}
	switch config.Action {
	case "allow", "audit", "block":
	default:
		return fmt.Errorf("action must be allow, audit, or block")
	}
	if len(config.Description) > 2048 || !utf8.ValidString(config.Description) {
		return fmt.Errorf("description must be valid text of at most 2048 bytes")
	}
	return nil
}

func validateToolRiskBatch(tenantID string, configs []ToolRiskConfig) error {
	if strings.TrimSpace(tenantID) == "" || len(configs) == 0 || len(configs) > 200 {
		return fmt.Errorf("tenant_id and 1 to 200 configs are required")
	}
	seen := make(map[string]bool, len(configs))
	for i := range configs {
		if err := ValidateToolRiskConfig(&configs[i]); err != nil {
			return fmt.Errorf("configs[%d]: %w", i, err)
		}
		if seen[configs[i].ToolName] {
			return fmt.Errorf("configs[%d]: duplicate tool_name", i)
		}
		seen[configs[i].ToolName] = true
	}
	return nil
}

// BatchUpsertPreserving makes selected additions atomic. A concurrent existing
// policy wins when preserveExisting is true; its action and type are never reset.
func (r *ToolRiskConfigRepository) BatchUpsertPreserving(ctx context.Context, tenantID string, configs []ToolRiskConfig, preserveExisting bool) (applied, skipped int, err error) {
	if err := validateToolRiskBatch(tenantID, configs); err != nil {
		return 0, 0, err
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("begin tool config batch: %w", err)
	}
	defer tx.Rollback(ctx)
	conflict := `DO UPDATE SET tool_type=EXCLUDED.tool_type, risk_level=EXCLUDED.risk_level,
		action=EXCLUDED.action, description=EXCLUDED.description, updated_at=NOW()`
	if preserveExisting {
		conflict = "DO NOTHING"
	}
	query := `INSERT INTO tool_risk_config (id,tenant_id,tool_name,tool_type,risk_level,action,description)
		VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (tenant_id,tool_name) ` + conflict
	for _, config := range configs {
		id := "tr_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:24]
		result, writeErr := tx.Exec(ctx, query, id, tenantID, config.ToolName, config.ToolType, config.RiskLevel, config.Action, config.Description)
		if writeErr != nil {
			return 0, 0, fmt.Errorf("write tool config batch: %w", writeErr)
		}
		if result.RowsAffected() == 0 {
			skipped++
		} else {
			applied++
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, 0, fmt.Errorf("commit tool config batch: %w", err)
	}
	return applied, skipped, nil
}
