package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GroupMappingRule 部门(SSO department) → 分组/网关项目/团队 映射规则。
// 从 portal-proxy SQLite 迁入网关；网关为权威、portal-proxy 读它（带兜底）。
type GroupMappingRule struct {
	ID               string
	TenantID         string
	MatchType        string
	MatchValue       string
	MappedGroup      string
	GatewayProjectID string
	GatewayTeamID    string // "" 表示 NULL（惰性回填语义）
	Priority         int
	Enabled          bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

type GroupMappingRuleRepository struct {
	db *pgxpool.Pool
}

func NewGroupMappingRuleRepository(db *pgxpool.Pool) *GroupMappingRuleRepository {
	return &GroupMappingRuleRepository{db: db}
}

const gmrCols = `id, tenant_id, match_type, match_value, mapped_group, gateway_project_id, COALESCE(gateway_team_id,''), priority, enabled, created_at, updated_at`

func scanGMR(row pgx.Row) (*GroupMappingRule, error) {
	var r GroupMappingRule
	if err := row.Scan(&r.ID, &r.TenantID, &r.MatchType, &r.MatchValue, &r.MappedGroup,
		&r.GatewayProjectID, &r.GatewayTeamID, &r.Priority, &r.Enabled, &r.CreatedAt, &r.UpdatedAt); err != nil {
		return nil, err
	}
	return &r, nil
}

// ListByTenant 列某租户全部规则，priority 升序（portal-proxy 读侧与后台列表共用）。
func (r *GroupMappingRuleRepository) ListByTenant(ctx context.Context, tenantID string) ([]*GroupMappingRule, error) {
	rows, err := r.db.Query(ctx, `SELECT `+gmrCols+` FROM group_mapping_rules WHERE tenant_id = $1 ORDER BY priority ASC, match_value ASC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("list group mapping rules: %w", err)
	}
	defer rows.Close()
	out := []*GroupMappingRule{}
	for rows.Next() {
		g, err := scanGMR(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// GetByID 取单条（校验租户）。
func (r *GroupMappingRuleRepository) GetByID(ctx context.Context, tenantID, id string) (*GroupMappingRule, error) {
	g, err := scanGMR(r.db.QueryRow(ctx, `SELECT `+gmrCols+` FROM group_mapping_rules WHERE tenant_id=$1 AND id=$2`, tenantID, id))
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	return g, err
}

// Create 建规则（id 为空则生成 gmr_ 前缀）。
func (r *GroupMappingRuleRepository) Create(ctx context.Context, g *GroupMappingRule) error {
	if g.ID == "" {
		g.ID = "gmr_" + uuid.New().String()[:8]
	}
	if g.MatchType == "" {
		g.MatchType = "department"
	}
	if g.Priority == 0 {
		g.Priority = 100
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO group_mapping_rules (id, tenant_id, match_type, match_value, mapped_group, gateway_project_id, gateway_team_id, priority, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		g.ID, g.TenantID, g.MatchType, g.MatchValue, g.MappedGroup, g.GatewayProjectID, nullableString(g.GatewayTeamID), g.Priority, g.Enabled)
	if err != nil {
		return fmt.Errorf("create group mapping rule: %w", err)
	}
	return nil
}

// Update 全字段更新（按 id+tenant）。
func (r *GroupMappingRuleRepository) Update(ctx context.Context, g *GroupMappingRule) error {
	ct, err := r.db.Exec(ctx, `
		UPDATE group_mapping_rules
		SET match_type=$3, match_value=$4, mapped_group=$5, gateway_project_id=$6, gateway_team_id=$7, priority=$8, enabled=$9, updated_at=now()
		WHERE tenant_id=$1 AND id=$2`,
		g.TenantID, g.ID, g.MatchType, g.MatchValue, g.MappedGroup, g.GatewayProjectID, nullableString(g.GatewayTeamID), g.Priority, g.Enabled)
	if err != nil {
		return fmt.Errorf("update group mapping rule: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("group mapping rule not found")
	}
	return nil
}

// Delete 删规则（按 id+tenant）。
func (r *GroupMappingRuleRepository) Delete(ctx context.Context, tenantID, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM group_mapping_rules WHERE tenant_id=$1 AND id=$2`, tenantID, id)
	if err != nil {
		return fmt.Errorf("delete group mapping rule: %w", err)
	}
	return nil
}
