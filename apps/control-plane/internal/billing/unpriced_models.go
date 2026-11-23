package billing

import (
	"context"
	"fmt"
	"time"
)

// UnpricedModel 是近期被实际调用、但当前没有生效价格的模型。
type UnpricedModel struct {
	TenantID     string    `json:"tenant_id,omitempty"`
	ModelName    string    `json:"model_name"`
	RequestCount int64     `json:"request_count"`
	LastSeenAt   time.Time `json:"last_seen_at"`
}

// ListUnpricedModels 列出 [since, until] 内被调用过（计费事实没有价格快照）且当前仍没有生效价格的模型，
// 按调用次数从多到少排序。失败请求不计入：它们没有产生可计价的用量。
func (s *Store) ListUnpricedModels(ctx context.Context, tenantID string, since, until time.Time) ([]UnpricedModel, error) {
	if tenantID == "" {
		return nil, ErrInvalidPrice
	}
	return s.listUnpricedModels(ctx, tenantID, since, until)
}

// ListUnpricedModelsAllTenants provides the same read-only listing across tenants.
func (s *Store) ListUnpricedModelsAllTenants(ctx context.Context, since, until time.Time) ([]UnpricedModel, error) {
	return s.listUnpricedModels(ctx, "", since, until)
}

func (s *Store) listUnpricedModels(ctx context.Context, tenantID string, since, until time.Time) ([]UnpricedModel, error) {
	rows, err := s.db.Query(ctx, `
		SELECT f.tenant_id, f.model_name, COUNT(*) AS request_count, MAX(f.occurred_at) AS last_seen_at
		FROM billing_usage_facts f
		WHERE ($1 = '' OR f.tenant_id = $1)
		  AND f.occurred_at >= $2 AND f.occurred_at <= $3
		  AND f.usage_source NOT IN ('forward_proxy','reverse_proxy')
		  AND f.price_id IS NULL
		  AND f.status IN ('unpriced', 'settled')
		  AND f.model_name <> ''
		  AND NOT EXISTS (
		    SELECT 1 FROM billing_model_prices p
		    WHERE p.tenant_id = f.tenant_id AND p.model_name = f.model_name
		      AND p.status = 'active' AND p.customer_group = 'default'
		      AND p.effective_at <= $3 AND (p.expires_at IS NULL OR p.expires_at > $3)
		  )
		GROUP BY f.tenant_id, f.model_name
		ORDER BY request_count DESC, f.tenant_id ASC, f.model_name ASC
		LIMIT 1000
	`, tenantID, since, until)
	if err != nil {
		return nil, fmt.Errorf("list unpriced models: %w", err)
	}
	defer rows.Close()
	result := []UnpricedModel{}
	for rows.Next() {
		var item UnpricedModel
		if err := rows.Scan(&item.TenantID, &item.ModelName, &item.RequestCount, &item.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan unpriced model: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}
