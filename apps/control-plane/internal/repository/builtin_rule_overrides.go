package repository

import (
	"context"
	"fmt"
)

func (r *RuleRepository) UpsertBuiltinRuleAction(ctx context.Context, tenantID, ruleID, action string) error {
	if action != "audit" && action != "mask" && action != "block" {
		return fmt.Errorf("unsupported builtin rule action")
	}
	result, err := r.db.Exec(ctx, `
		INSERT INTO builtin_rule_overrides (tenant_id, rule_id, action, updated_at)
		SELECT $1, r.id, $3, NOW()
		FROM rules r
		JOIN rule_sets rs ON rs.id = r.rule_set_id
		WHERE r.id = $2
		  AND rs.tenant_id = $4
		  AND rs.source_type = 'builtin'
		  AND rs.published = TRUE
		  AND `+executableRulePredicateSQL+`
		ON CONFLICT (tenant_id, rule_id)
		DO UPDATE SET action = EXCLUDED.action, updated_at = NOW()
	`, tenantID, ruleID, action, SystemTenantID)
	if err != nil {
		return fmt.Errorf("upsert builtin rule action: %w", err)
	}
	if result.RowsAffected() == 0 {
		return ErrRuleNotFound
	}
	return nil
}
