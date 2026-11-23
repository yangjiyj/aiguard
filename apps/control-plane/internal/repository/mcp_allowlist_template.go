package repository

// W1 1.6（D2）：可选"只允许勾选的工具"模板。
//
// 默认行为不变：未命中任何策略仍按 audit 放行留痕。本模板只在管理员对某个 server
// 显式套用时生效，落地为一组普通 mcp_policies 行，不引入新的决策语义：
//   - 一条 server 级 tool_pattern="*"、mode=strict、default_action=block 的兜底拒绝；
//   - 每个勾选工具一条精确 tool_pattern、mode=strict、default_action=allow 的放行。
// 精确模式特异性（rank 2）高于通配（rank 0），所以勾选工具走 allow、其余走 block，
// 解析口径与网关运行时同源（ResolveMCPPolicy）。
//
// 模板策略用 note 标记（MCPAllowlistTemplateNote），重复套用 = 整组替换，撤销 = 整组删除；
// 管理员手写的策略永远不被模板触碰。

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// MCPAllowlistTemplateNotePrefix 是模板策略 note 的固定前缀，后接 server_id。
const MCPAllowlistTemplateNotePrefix = "mcp_allowlist_template:"

// MCPAllowlistTemplateNote 返回某 server 的模板策略标记。
func MCPAllowlistTemplateNote(serverID string) string {
	return MCPAllowlistTemplateNotePrefix + serverID
}

// IsMCPAllowlistTemplatePolicy 判断策略是否由模板生成。
func IsMCPAllowlistTemplatePolicy(p *MCPPolicy) bool {
	return p != nil && strings.HasPrefix(p.Note, MCPAllowlistTemplateNotePrefix)
}

// BuildMCPAllowlistTemplatePolicies 纯函数：生成模板策略集（不落库，供预览与落库共用）。
// toolNames 去重、去空白后按字典序输出，保证预览与落库结果稳定。
func BuildMCPAllowlistTemplatePolicies(tenantID, serverID, actor string, toolNames []string, enabled bool) ([]*MCPPolicy, error) {
	if strings.TrimSpace(tenantID) == "" || strings.TrimSpace(serverID) == "" {
		return nil, errors.New("tenant_id and server_id are required")
	}
	seen := map[string]bool{}
	var names []string
	for _, raw := range toolNames {
		name := strings.TrimSpace(raw)
		if name == "" || seen[name] {
			continue
		}
		if name == "*" || strings.HasSuffix(name, ".*") {
			return nil, fmt.Errorf("tool name %q must be exact, not a pattern", name)
		}
		seen[name] = true
		names = append(names, name)
	}
	if len(names) == 0 {
		return nil, errors.New("at least one tool must be selected")
	}
	sort.Strings(names)
	note := MCPAllowlistTemplateNote(serverID)
	out := make([]*MCPPolicy, 0, len(names)+1)
	out = append(out, &MCPPolicy{
		TenantID: tenantID, ScopeType: "tenant", ScopeRef: "", ServerID: serverID,
		ToolPattern: "*", TargetKind: "tool", Mode: AgentGuardModeStrict,
		DefaultAction: AgentGuardActionBlock, Priority: 0, Enabled: enabled,
		Note: note, CreatedBy: actor,
	})
	for _, name := range names {
		out = append(out, &MCPPolicy{
			TenantID: tenantID, ScopeType: "tenant", ScopeRef: "", ServerID: serverID,
			ToolPattern: name, TargetKind: "tool", Mode: AgentGuardModeStrict,
			DefaultAction: AgentGuardActionAllow, Priority: 0, Enabled: enabled,
			Note: note, CreatedBy: actor,
		})
	}
	return out, nil
}

// ReplaceMCPAllowlistTemplate 事务内删除该 server 旧的模板策略并写入新的一组。
// 只删 note 精确等于模板标记的行，管理员手写策略不受影响。
func (r *MCPPoliciesRepository) ReplaceMCPAllowlistTemplate(ctx context.Context, policies []*MCPPolicy) error {
	if len(policies) == 0 {
		return errors.New("empty template")
	}
	tenantID, serverID := policies[0].TenantID, policies[0].ServerID
	note := MCPAllowlistTemplateNote(serverID)
	for _, p := range policies {
		if p == nil || p.TenantID != tenantID || p.ServerID != serverID || p.Note != note {
			return errors.New("template policies must share tenant, server and template note")
		}
	}
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `DELETE FROM mcp_policies WHERE tenant_id = $1 AND server_id = $2 AND note = $3`,
		tenantID, serverID, note); err != nil {
		return err
	}
	for _, p := range policies {
		if p.ID == "" {
			p.ID = "mcppol_" + uuid.New().String()[:8]
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO mcp_policies
				(id, tenant_id, scope_type, scope_ref, server_id, tool_pattern,
				 mode, default_action, priority, enabled, note, created_by, target_kind)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
			RETURNING created_at, updated_at`,
			p.ID, p.TenantID, p.ScopeType, p.ScopeRef, p.ServerID, p.ToolPattern,
			p.Mode, p.DefaultAction, p.Priority, p.Enabled, p.Note, p.CreatedBy, p.TargetKind,
		).Scan(&p.CreatedAt, &p.UpdatedAt); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// RemoveMCPAllowlistTemplate 删除该 server 的全部模板策略，返回删除行数（0 表示未套用）。
func (r *MCPPoliciesRepository) RemoveMCPAllowlistTemplate(ctx context.Context, tenantID, serverID string) (int64, error) {
	tag, err := r.db.Exec(ctx, `DELETE FROM mcp_policies WHERE tenant_id = $1 AND server_id = $2 AND note = $3`,
		tenantID, serverID, MCPAllowlistTemplateNote(serverID))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
