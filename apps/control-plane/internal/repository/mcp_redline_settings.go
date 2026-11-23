package repository

// W1 1.11：内置 MCP 红线的租户级处置配置（迁移 862 mcp_redline_settings）。
// 缺行 = alert（只留证），与基线一致。

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	MCPRedlineActionOff    = "off"
	MCPRedlineActionRecord = "record"
	MCPRedlineActionAlert  = "alert"
	MCPRedlineActionBlock  = "block"
)

// MCPConfigurableRedlines 是可配置处置的网关内置红线规则名，须与 gateway-core
// mcp_proxy.go 的 mcpRedlineRules 同步（网关对未知名一律忽略，按 alert 处理）。
var MCPConfigurableRedlines = []string{
	"destructive_command",
	"cloud_metadata",
	"private_key_egress",
	"cloud_credential_file",
	"system_secret_file",
	"container_runtime_socket",
	"reverse_shell",
	"remote_script_pipe",
}

// MCPRedlineSetting 是一条红线的当前处置。
type MCPRedlineSetting struct {
	RuleName  string     `json:"rule_name"`
	Action    string     `json:"action"`
	UpdatedBy string     `json:"updated_by,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

// IsMCPConfigurableRedline 判断规则名是否可配置。
func IsMCPConfigurableRedline(name string) bool {
	for _, n := range MCPConfigurableRedlines {
		if n == name {
			return true
		}
	}
	return false
}

// NormalizeMCPRedlineUpdates 校验并归一化更新请求（纯函数）：未知规则或非法动作报错。
func NormalizeMCPRedlineUpdates(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, fmt.Errorf("actions must not be empty")
	}
	out := make(map[string]string, len(in))
	for name, action := range in {
		name = strings.TrimSpace(name)
		action = strings.ToLower(strings.TrimSpace(action))
		if !IsMCPConfigurableRedline(name) {
			return nil, fmt.Errorf("unknown redline %q", name)
		}
		switch action {
		case MCPRedlineActionOff, MCPRedlineActionRecord, MCPRedlineActionAlert, MCPRedlineActionBlock:
		default:
			return nil, fmt.Errorf("action for %q must be off, record, alert or block", name)
		}
		out[name] = action
	}
	return out, nil
}

// MCPRedlineSettingsRepository 读写 mcp_redline_settings。
type MCPRedlineSettingsRepository struct {
	db *pgxpool.Pool
}

func NewMCPRedlineSettingsRepository(db *pgxpool.Pool) *MCPRedlineSettingsRepository {
	return &MCPRedlineSettingsRepository{db: db}
}

// List 返回全部可配置红线的当前处置（缺行补 alert），按规则表顺序。
func (r *MCPRedlineSettingsRepository) List(ctx context.Context, tenantID string) ([]MCPRedlineSetting, error) {
	rows, err := r.db.Query(ctx, `SELECT rule_name, action, updated_by, updated_at FROM mcp_redline_settings WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	stored := map[string]MCPRedlineSetting{}
	for rows.Next() {
		var s MCPRedlineSetting
		var at time.Time
		if err := rows.Scan(&s.RuleName, &s.Action, &s.UpdatedBy, &at); err != nil {
			return nil, err
		}
		s.UpdatedAt = &at
		stored[s.RuleName] = s
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]MCPRedlineSetting, 0, len(MCPConfigurableRedlines))
	for _, name := range MCPConfigurableRedlines {
		if s, ok := stored[name]; ok {
			out = append(out, s)
			continue
		}
		out = append(out, MCPRedlineSetting{RuleName: name, Action: MCPRedlineActionAlert})
	}
	return out, nil
}

// Actions 返回 rule_name → action 映射（只含已知规则）。
func (r *MCPRedlineSettingsRepository) Actions(ctx context.Context, tenantID string) (map[string]string, error) {
	list, err := r.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(list))
	for _, s := range list {
		out[s.RuleName] = s.Action
	}
	return out, nil
}

// Upsert 在一个事务内写入多条处置，返回变更前的动作（供审计留痕）。
func (r *MCPRedlineSettingsRepository) Upsert(ctx context.Context, tenantID, actor string, actions map[string]string) (map[string]string, error) {
	names := make([]string, 0, len(actions))
	for name := range actions {
		names = append(names, name)
	}
	sort.Strings(names)
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	before := make(map[string]string, len(names))
	for _, name := range names {
		prev := MCPRedlineActionAlert
		err := tx.QueryRow(ctx, `SELECT action FROM mcp_redline_settings WHERE tenant_id=$1 AND rule_name=$2 FOR UPDATE`,
			tenantID, name).Scan(&prev)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO mcp_redline_settings (tenant_id, rule_name, action, updated_by, updated_at)
			VALUES ($1,$2,$3,$4,NOW())
			ON CONFLICT (tenant_id, rule_name) DO UPDATE
			  SET action=EXCLUDED.action, updated_by=EXCLUDED.updated_by, updated_at=NOW()`,
			tenantID, name, actions[name], actor); err != nil {
			return nil, err
		}
		before[name] = prev
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return before, nil
}
