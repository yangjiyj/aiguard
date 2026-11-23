package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
)

// alertVisibleRuleIDsSQL 与阻断记录判断“规则仍存在且可见”同口径：规则未被墓碑标记、
// 规则集已发布、属于本租户或系统预置。只按主键批量查，不在投影里逐行子查询。
const alertVisibleRuleIDsSQL = `
SELECT r.id FROM rules r
JOIN rule_sets rs ON rs.id = r.rule_set_id
WHERE r.id = ANY($1::text[])
  AND rs.published = TRUE
  AND ` + ruleNotDeletedSQL + `
  AND (rs.tenant_id = $2 OR (rs.tenant_id = '` + SystemTenantID + `' AND rs.source_type = 'builtin'))`

// fillManagedBehaviors 把页面 JSON 里的 managed_behavior 填到同序的条目上。
// 该字段只用于推导链接，AlertOccurrence 不对外输出它，所以单独解一遍。
func fillManagedBehaviors(rowsJSON []byte, items []AlertOccurrence) error {
	var extras []struct {
		ManagedBehavior string `json:"managed_behavior"`
	}
	if err := json.Unmarshal(rowsJSON, &extras); err != nil {
		return err
	}
	if len(extras) != len(items) {
		return fmt.Errorf("alert page shape mismatch: %d rows, %d items", len(extras), len(items))
	}
	for index := range items {
		items[index].ManagedBehavior = extras[index].ManagedBehavior
	}
	return nil
}

// attachAlertPolicyLinks 给一页告警填跳转目标；指向 rules 表的策略链接要确认规则还在且可见，
// 否则改成“已删除”。一页只查一次。核对失败（上下文已取消除外）时记日志，这些链接降为 nil，
// 不标“已删除”，列表照常返回。
func (r *AlertOccurrenceRepository) attachAlertPolicyLinks(ctx context.Context, tenantID string, items []AlertOccurrence) error {
	seen := map[string]bool{}
	var candidates []string
	for index := range items {
		link := alertPolicyLink(&items[index])
		items[index].PolicyLink = link
		id := strings.TrimSpace(items[index].RuleID)
		if link != nil && link.Kind == "policy" && strings.HasPrefix(id, rulesTableIDPrefix) && !seen[id] {
			seen[id] = true
			candidates = append(candidates, id)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	visible, err := r.visibleRuleIDs(ctx, tenantID, candidates)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		log.Printf("alert policy links: visibility lookup failed tenant=%s candidates=%d: %v", tenantID, len(candidates), err)
		for index := range items {
			if link := items[index].PolicyLink; link != nil && link.Kind == "policy" && seen[strings.TrimSpace(items[index].RuleID)] {
				items[index].PolicyLink = nil
			}
		}
		return nil
	}
	for index := range items {
		link := items[index].PolicyLink
		id := strings.TrimSpace(items[index].RuleID)
		if link != nil && link.Kind == "policy" && seen[id] && !visible[id] {
			items[index].PolicyLink = &PolicyLink{Kind: "deleted", Label: items[index].RuleName}
		}
	}
	return nil
}

func (r *AlertOccurrenceRepository) visibleRuleIDs(ctx context.Context, tenantID string, ids []string) (map[string]bool, error) {
	rows, err := r.db.Query(ctx, alertVisibleRuleIDsSQL, ids, tenantID)
	if err != nil {
		return nil, fmt.Errorf("check alert policy visibility: %w", err)
	}
	defer rows.Close()
	visible := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan alert policy visibility: %w", err)
		}
		visible[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read alert policy visibility: %w", err)
	}
	return visible, nil
}
