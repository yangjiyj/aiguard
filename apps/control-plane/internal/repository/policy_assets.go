package repository

import (
	"context"
	"fmt"
	"strings"
)

type PolicyAsset struct {
	ID          string `json:"id"`
	RuleType    string `json:"rule_type"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Action      string `json:"action"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description,omitempty"`
	Source      string `json:"source"`
	Industry    string `json:"industry"`
	Applicable  bool   `json:"applicable"`
	Executable  bool   `json:"executable"`
	Writable    bool   `json:"writable"`
}

// ListPolicyAssets returns the customer-visible inventory without confusing it
// with the executable custom-rule pack. Tenant-owned published rules and every
// published system industry asset are visible to platform administrators.
func (r *RuleRepository) ListPolicyAssets(ctx context.Context, tenantID, tenantIndustry string) ([]PolicyAsset, error) {
	rows, err := r.db.Query(ctx, `
		SELECT r.id, r.rule_type, r.name, COALESCE(bro.severity, r.severity), COALESCE(bro.action, r.action), COALESCE(bro.enabled, r.enabled),
		       COALESCE(r.description, ''), rs.tenant_id, rs.source_type, COALESCE(rs.industry, 'generic'),
		       r.match_config_json
		FROM rules r
		JOIN rule_sets rs ON rs.id = r.rule_set_id
		LEFT JOIN builtin_rule_overrides bro ON bro.tenant_id = $1 AND bro.rule_id = r.id
		WHERE rs.published = TRUE
		  AND NOT jsonb_exists(COALESCE(r.scope_json,'{}'::jsonb),'deleted_at')
		  AND (rs.tenant_id = $1 OR (rs.tenant_id = $2 AND rs.source_type = 'builtin'))
		ORDER BY CASE WHEN rs.tenant_id = $1 THEN 0 ELSE 1 END, rs.industry, r.priority DESC, r.created_at
	`, tenantID, SystemTenantID)
	if err != nil {
		return nil, fmt.Errorf("list policy assets: %w", err)
	}
	defer rows.Close()

	industry := strings.TrimSpace(tenantIndustry)
	if industry == "" {
		industry = "generic"
	}
	assets := make([]PolicyAsset, 0)
	for rows.Next() {
		var asset PolicyAsset
		var ownerTenant, sourceType string
		var matchConfig []byte
		if err := rows.Scan(&asset.ID, &asset.RuleType, &asset.Name, &asset.Severity, &asset.Action,
			&asset.Enabled, &asset.Description, &ownerTenant, &sourceType, &asset.Industry, &matchConfig); err != nil {
			return nil, fmt.Errorf("scan policy asset: %w", err)
		}
		tenantOwned := ownerTenant == tenantID
		asset.Source = "tenant"
		if sourceType == "builtin" {
			asset.Source = "industry"
		}
		asset.Applicable = tenantOwned || asset.Industry == "generic" || asset.Industry == industry
		asset.Executable = RuleHasSupportedMatcher(&Rule{RuleType: asset.RuleType, MatchConfigJSON: matchConfig})
		asset.Writable = asset.Applicable && asset.Executable
		assets = append(assets, asset)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate policy assets: %w", err)
	}
	return assets, nil
}
