package billing

import (
	"context"
	"fmt"
)

// Output reservation defaults (7.6). A request without max_tokens used to
// reserve a flat 4096 output tokens, which over-froze prepaid balances and
// refused affordable calls. The reservation now follows the model's observed
// P95 output on provider-metered charges; the flat ceiling remains the upper
// bound and the fallback while history is too thin to be meaningful.
const (
	DefaultOutputTokenCeiling  = 4096
	outputEstimateMinSamples   = 20
	outputEstimateSampleWindow = 200
)

// Output estimate sources reported back to the gateway.
const (
	OutputEstimateHistoryP95 = "history_p95"
	OutputEstimateCeiling    = "default_ceiling"
)

// EstimateOutputTokens returns the output tokens to reserve for a request that
// did not bound its completion. Only charges whose usage came from the
// provider are sampled, so estimated or recovered charges cannot feed back
// into their own estimate.
func (s *Store) EstimateOutputTokens(ctx context.Context, tenantID, modelName string) (int64, string, error) {
	if s == nil || s.db == nil || tenantID == "" || modelName == "" {
		return DefaultOutputTokenCeiling, OutputEstimateCeiling, nil
	}
	var samples int64
	var p95 *int64
	if err := s.db.QueryRow(ctx, `
		SELECT COUNT(*), percentile_disc(0.95) WITHIN GROUP (ORDER BY output_tokens)
		FROM (
			SELECT output_tokens
			FROM billing_charge_records
			WHERE tenant_id = $1 AND model_name = $2 AND status = 'settled'
			  AND raw_usage_json->>'usage_source' IN ('upstream', 'upstream_total_adjusted')
			  AND created_at > NOW() - INTERVAL '30 days'
			ORDER BY created_at DESC
			LIMIT $3
		) recent
	`, tenantID, modelName, outputEstimateSampleWindow).Scan(&samples, &p95); err != nil {
		return 0, "", fmt.Errorf("estimate billing output tokens: %w", err)
	}
	if samples < outputEstimateMinSamples || p95 == nil {
		return DefaultOutputTokenCeiling, OutputEstimateCeiling, nil
	}
	estimate := *p95
	if estimate < 1 {
		estimate = 1
	}
	if estimate > DefaultOutputTokenCeiling {
		estimate = DefaultOutputTokenCeiling
	}
	return estimate, OutputEstimateHistoryP95, nil
}
