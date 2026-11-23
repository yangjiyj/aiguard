package saving

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// FxProvider returns current USD→CNY exchange rate.
type FxProvider interface {
	Current(ctx context.Context) (float64, error)
}

// WatermarkStore persists incremental processing progress.
type WatermarkStore interface {
	Init(ctx context.Context) error
	Get(ctx context.Context, worker string) (time.Time, error)
	Set(ctx context.Context, worker string, t time.Time) error
}

// Calculator aggregates saving_metrics from request_logs incrementally.
type Calculator struct {
	db *pgxpool.Pool
	fx FxProvider
	wm WatermarkStore
}

// NewCalculator creates a new Calculator.
func NewCalculator(db *pgxpool.Pool, fx FxProvider, wm WatermarkStore) *Calculator {
	return &Calculator{db: db, fx: fx, wm: wm}
}

const workerName = "saving_calculator"

// aggrow holds aggregated data for one (tenant,team,project,user,date,source) combination.
type aggrow struct {
	tenantID, teamID, projectID, userID, source string
	date         time.Time
	savingUSD    float64
	requestCount int
}

// RunOnce incrementally scans request_logs and writes aggregated data to saving_metrics.
// Returns the number of rows upserted.
//
// NULL semantics note: saving_metrics UNIQUE(tenant_id, team_id, project_id, user_id, date, source)
// uses standard B-tree where NULL != NULL, breaking ON CONFLICT. To guarantee UPSERT semantics,
// team_id and user_id are stored as empty string  when absent (saving_metrics has no FK on these).
func (c *Calculator) RunOnce(ctx context.Context) (int, error) {
	_ = c.wm.Init(ctx)
	last, err := c.wm.Get(ctx, workerName)
	if err != nil {
		// First run: start from 30 days ago.
		last = time.Now().UTC().AddDate(0, 0, -30)
	}
	now := time.Now().UTC()

	fxRate, _ := c.fx.Current(ctx)
	if fxRate <= 0 {
		fxRate = 7.20 // fallback rate
	}

	rowCount := 0

	// 1) Aggregate cache_hit savings.
	// cache_hit 节省口径：实际成本 = 0（网关响应缓存命中，未调用上游），节省 = 原请求的完整成本。
	// 网关命中时把原请求的实际计费成本与省下的 token 写进 output_audit_result.response_metadata.cache，
	// 自身的 input/output_tokens 记 0（不计入用量）。优先用实际计费成本；没有时按省下的 token 乘模型定价。
	// provider 侧的 prompt cache 折扣不经过这里（cache_hit 只由网关响应缓存写入）。
	cacheRows, err := c.db.Query(ctx, `
		SELECT rl.tenant_id, COALESCE(p.team_id, '') AS team_id,
		       rl.project_id, COALESCE(rl.user_id, '') AS user_id,
		       DATE(rl.created_at) AS date,
		       COALESCE(NULLIF(rl.input_tokens, 0), (rl.output_audit_result->'response_metadata'->'cache'->>'saved_input_tokens')::bigint, 0),
		       COALESCE(NULLIF(rl.output_tokens, 0), (rl.output_audit_result->'response_metadata'->'cache'->>'saved_output_tokens')::bigint, 0),
		       m.pricing_json,
		       (rl.output_audit_result->'response_metadata'->'cache'->>'saved_cost_micros')::bigint,
		       COALESCE(rl.output_audit_result->'response_metadata'->'cache'->>'currency', '')
		FROM request_logs rl
		LEFT JOIN models m ON m.id = rl.model_id
		LEFT JOIN projects p ON p.id = rl.project_id
		WHERE rl.created_at > $1 AND rl.created_at <= $2
		  AND rl.cache_hit = TRUE
	`, last, now)
	if err != nil {
		return 0, fmt.Errorf("cache_hit query: %w", err)
	}
	cacheAgg := make(map[string]aggrow)
	for cacheRows.Next() {
		var tenantID, teamID, projectID, userID string
		var date time.Time
		var inputTokens, outputTokens int
		var pricingJSON []byte
		var savedCostMicros *int64
		var currency string
		if err := cacheRows.Scan(&tenantID, &teamID, &projectID, &userID, &date,
			&inputTokens, &outputTokens, &pricingJSON, &savedCostMicros, &currency); err != nil {
			continue
		}
		baseline, ok := billedCostUSD(savedCostMicros, currency, fxRate)
		if !ok {
			baseline = calcCost(pricingJSON, inputTokens, outputTokens)
		}
		if baseline <= 0 {
			continue
		}
		key := tenantID + "|" + teamID + "|" + projectID + "|" + userID + "|" + date.Format("2006-01-02") + "|cache_hit"
		a := cacheAgg[key]
		a.tenantID = tenantID
		a.teamID = teamID
		a.projectID = projectID
		a.userID = userID
		a.date = date
		a.source = "cache_hit"
		a.savingUSD += baseline
		a.requestCount++
		cacheAgg[key] = a
	}
	cacheRows.Close()

	// 2) Aggregate downgrade_model savings.
	downRows, err := c.db.Query(ctx, `
		SELECT rl.tenant_id, COALESCE(p.team_id, '') AS team_id,
		       rl.project_id, COALESCE(rl.user_id, '') AS user_id,
		       DATE(rl.created_at) AS date, COALESCE(rl.input_tokens, 0), COALESCE(rl.output_tokens, 0),
		       m_orig.pricing_json AS orig_pricing, m_used.pricing_json AS used_pricing
		FROM request_logs rl
		LEFT JOIN models m_orig ON m_orig.id = rl.original_model_id
		LEFT JOIN models m_used ON m_used.id = rl.model_id
		LEFT JOIN projects p ON p.id = rl.project_id
		WHERE rl.created_at > $1 AND rl.created_at <= $2
		  AND rl.governor_action = 'downgrade_model'
		  AND rl.original_model_id IS NOT NULL
	`, last, now)
	if err != nil {
		return 0, fmt.Errorf("downgrade_model query: %w", err)
	}
	downAgg := make(map[string]aggrow)
	for downRows.Next() {
		var tenantID, teamID, projectID, userID string
		var date time.Time
		var inputTokens, outputTokens int
		var origPricing, usedPricing []byte
		if err := downRows.Scan(&tenantID, &teamID, &projectID, &userID, &date,
			&inputTokens, &outputTokens, &origPricing, &usedPricing); err != nil {
			continue
		}
		origCost := calcCost(origPricing, inputTokens, outputTokens)
		usedCost := calcCost(usedPricing, inputTokens, outputTokens)
		saving := origCost - usedCost
		if saving <= 0 {
			continue
		}
		key := tenantID + "|" + teamID + "|" + projectID + "|" + userID + "|" + date.Format("2006-01-02") + "|model_downgraded"
		a := downAgg[key]
		a.tenantID = tenantID
		a.teamID = teamID
		a.projectID = projectID
		a.userID = userID
		a.date = date
		a.source = "model_downgraded"
		a.savingUSD += saving
		a.requestCount++
		downAgg[key] = a
	}
	downRows.Close()

	// 3) UPSERT all aggregated rows into saving_metrics.
	// team_id and user_id stored as  (not NULL) to ensure ON CONFLICT fires reliably
	// (PostgreSQL UNIQUE treats NULL != NULL, which would bypass conflict detection).
	for _, a := range cacheAgg {
		if err := c.upsert(ctx, a, fxRate); err != nil {
			log.Printf("[saving] upsert cache_hit failed: %v", err)
			continue
		}
		rowCount++
	}
	for _, a := range downAgg {
		if err := c.upsert(ctx, a, fxRate); err != nil {
			log.Printf("[saving] upsert model_downgraded failed: %v", err)
			continue
		}
		rowCount++
	}

	_ = c.wm.Set(ctx, workerName, now)
	return rowCount, nil
}

func (c *Calculator) upsert(ctx context.Context, a aggrow, fxRate float64) error {
	savingCNY := a.savingUSD * fxRate
	_, err := c.db.Exec(ctx, `
		INSERT INTO saving_metrics (tenant_id, team_id, project_id, user_id, date, source, saving_usd, saving_cny, request_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, team_id, project_id, user_id, date, source) DO UPDATE
		SET saving_usd    = saving_metrics.saving_usd    + EXCLUDED.saving_usd,
		    saving_cny    = saving_metrics.saving_cny    + EXCLUDED.saving_cny,
		    request_count = saving_metrics.request_count + EXCLUDED.request_count
	`, a.tenantID, a.teamID, a.projectID, a.userID, a.date, a.source, a.savingUSD, savingCNY, a.requestCount)
	return err
}

// billedCostUSD 把网关记录的实际计费成本（微单位）换算成美元；币种未知或成本缺失时返回 false。
func billedCostUSD(micros *int64, currency string, fxRate float64) (float64, bool) {
	if micros == nil || *micros <= 0 {
		return 0, false
	}
	amount := float64(*micros) / 1_000_000
	switch strings.ToUpper(strings.TrimSpace(currency)) {
	case "USD":
		return amount, true
	case "CNY":
		if fxRate <= 0 {
			return 0, false
		}
		return amount / fxRate, true
	}
	return 0, false
}

// calcCost computes the USD cost of a single request based on pricing_json.
// Expected pricing_json format:
//
//	{"input": 5.0, "output": 15.0, "currency": "USD", "pricing_unit": "per_million_tokens"}
func calcCost(pricingJSON []byte, inputTokens, outputTokens int) float64 {
	if len(pricingJSON) == 0 {
		return 0
	}
	var p map[string]any
	if err := json.Unmarshal(pricingJSON, &p); err != nil {
		return 0
	}
	in, _ := toFloat(p["input"])
	out, _ := toFloat(p["output"])
	return float64(inputTokens)/1_000_000*in + float64(outputTokens)/1_000_000*out
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case string:
		var f float64
		_, err := fmt.Sscanf(n, "%f", &f)
		return f, err == nil
	}
	return 0, false
}
