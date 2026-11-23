package modelops

import (
	"context"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// providerScopedCTE 把每次路由尝试展开成一行：有 attempts 的请求逐个展开，
// 没有 attempts 但确实到达上游的旧请求按最终渠道记 1 次（网关本地拒绝也会写 upstream_status_code，
// 所以按状态白名单判断是否到达过渠道）。attempt 只带渠道名，
// 按同租户 providers.name 关联回 id，关联不上时按名字单独成行。
// 参数：$1 租户、$2 窗口小时、$3 渠道 id、$4 模型 id。
const providerScopedCTE = `WITH base AS (
 SELECT r.id, r.model_id, r.provider_id, r.request_status, r.upstream_status_code, r.latency_ms, r.upstream_ttft_ms, r.created_at,
  CASE WHEN jsonb_typeof(r.routing_decision_json #> '{model_route_v2,attempts}')='array' THEN r.routing_decision_json #> '{model_route_v2,attempts}' END AS attempts
 FROM request_logs r
 WHERE r.tenant_id=$1 AND r.created_at>=now()-make_interval(hours=>$2) AND r.created_at<now()
  AND COALESCE(r.model_id,'')<>'' AND ($4='' OR r.model_id=$4)
), tries AS (
 SELECT b.id, b.model_id, b.created_at, a.ord::bigint AS ord, jsonb_array_length(b.attempts)::bigint AS n,
  NULL::text AS provider_id, a.v #>> '{route,provider_name}' AS provider_name,
  COALESCE(a.v->>'result','') AS result, COALESCE(a.v->>'failure_category','') AS failure_category,
  COALESCE(a.v->>'status_code_category','') AS status_category,
  CASE WHEN jsonb_typeof(a.v->'latency_ms')='number' THEN (a.v->>'latency_ms')::float8 END AS latency_ms,
  CASE WHEN a.ord=jsonb_array_length(b.attempts) THEN b.upstream_ttft_ms::float8 END AS ttft_ms,
  lag(a.v->>'result') OVER (PARTITION BY b.id ORDER BY a.ord) AS prev_result
 FROM base b CROSS JOIN LATERAL jsonb_array_elements(b.attempts) WITH ORDINALITY a(v,ord)
 WHERE b.attempts IS NOT NULL AND jsonb_array_length(b.attempts)>0
 UNION ALL
 SELECT b.id, b.model_id, b.created_at, 1, 1, b.provider_id, NULL,
  CASE WHEN b.request_status='success' AND b.upstream_status_code BETWEEN 200 AND 299 THEN 'success' ELSE 'failed' END,
  CASE WHEN b.upstream_status_code=429 THEN 'rate_limited' ELSE '' END,
  CASE WHEN b.upstream_status_code BETWEEN 500 AND 599 THEN '5xx' WHEN b.upstream_status_code BETWEEN 400 AND 499 THEN '4xx' ELSE '' END,
  b.latency_ms::float8, b.upstream_ttft_ms::float8, NULL
 FROM base b
 WHERE (b.attempts IS NULL OR jsonb_array_length(b.attempts)=0) AND COALESCE(b.provider_id,'')<>''
  AND b.upstream_status_code BETWEEN 100 AND 599 AND b.request_status IN ('success','failed','provider_error','provider_unavailable')
), resolved AS (
 SELECT t.*, COALESCE(t.provider_id, named.id, '') AS pid, COALESCE(p.name, t.provider_name, '') AS pname,
  CASE WHEN t.result='success' THEN ''
   WHEN t.failure_category='canceled' THEN 'canceled'
   WHEN t.failure_category='upstream_5xx' OR t.status_category='5xx' THEN 'http_5xx'
   WHEN t.failure_category='rate_limited' THEN 'rate_limited'
   WHEN t.failure_category='upstream_rejected' OR t.status_category='4xx' THEN 'rejected'
   WHEN t.failure_category IN ('network_error','timeout') THEN 'network'
   ELSE 'other' END AS err
 FROM tries t
 LEFT JOIN LATERAL (SELECT id FROM providers WHERE t.provider_id IS NULL AND tenant_id=$1 AND name=t.provider_name ORDER BY (status='active') DESC, id LIMIT 1) named ON true
 LEFT JOIN providers p ON p.tenant_id=$1 AND p.id=COALESCE(t.provider_id, named.id)
), scoped AS (
 SELECT *, CASE WHEN pid<>'' THEN pid ELSE 'name:'||pname END AS pkey FROM resolved WHERE ($3='' OR pid=$3)
)
`

const providerMonitorSQL = providerScopedCTE + `SELECT GROUPING(pkey)=0, COALESCE(pkey,''), COALESCE(max(pid),''), COALESCE(max(pname),''),
 count(*) FILTER (WHERE err<>'canceled'), count(*) FILTER (WHERE result='success'),
 percentile_cont(.5) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE result='success' AND latency_ms>=0),
 percentile_cont(.95) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE result='success' AND latency_ms>=0),
 count(*) FILTER (WHERE result='success' AND latency_ms>=0),
 percentile_cont(.5) WITHIN GROUP (ORDER BY ttft_ms) FILTER (WHERE result='success' AND ttft_ms>=0),
 count(*) FILTER (WHERE result='success' AND ttft_ms>=0),
 count(*) FILTER (WHERE err='http_5xx'), count(*) FILTER (WHERE err='rate_limited'), count(*) FILTER (WHERE err='rejected'),
 count(*) FILTER (WHERE err='network'), count(*) FILTER (WHERE err='other'),
 count(*) FILTER (WHERE result<>'success' AND err<>'canceled' AND ord<n),
 count(*) FILTER (WHERE prev_result='failed'),
 count(DISTINCT id) FILTER (WHERE n>1), count(DISTINCT model_id)
FROM scoped GROUP BY GROUPING SETS ((pkey),())`

const providerModelsSQL = providerScopedCTE + `SELECT s.pkey, s.model_id, COALESCE(m.model_name,''), count(*) FILTER (WHERE s.err<>'canceled'), count(*) FILTER (WHERE s.result='success')
FROM scoped s LEFT JOIN models m ON m.id=s.model_id GROUP BY 1,2,3 ORDER BY 1, 4 DESC, 3`

const providerHourlySQL = providerScopedCTE + `SELECT pkey, LEAST(floor(extract(epoch FROM created_at-(now()-make_interval(hours=>$2)))/($2*150))::int, 23),
 count(*) FILTER (WHERE err<>'canceled'), count(*) FILTER (WHERE result='success'),
 percentile_cont(.95) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE result='success' AND latency_ms>=0)
FROM scoped GROUP BY 1,2`

const providerBuckets = 24

func (s *PostgresStore) GetProviderMonitor(ctx context.Context, tenant string, f ReadFilter) (ProviderMonitor, error) {
	f, err := f.validated()
	if err != nil {
		return ProviderMonitor{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return ProviderMonitor{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout = '15s'`); err != nil {
		return ProviderMonitor{}, err
	}
	out := ProviderMonitor{Items: []ProviderStat{}, WindowHours: f.WindowHours}
	if err = tx.QueryRow(ctx, `SELECT now()`).Scan(&out.GeneratedAt); err != nil {
		return ProviderMonitor{}, err
	}
	args := []any{tenant, f.WindowHours, f.ProviderID, f.ModelID}
	index := map[string]int{}
	rows, err := tx.Query(ctx, providerMonitorSQL, args...)
	if err != nil {
		return ProviderMonitor{}, err
	}
	for rows.Next() {
		var item ProviderStat
		var isItem bool
		var key string
		var latencyN, ttftN, fallbacks int64
		if err = rows.Scan(&isItem, &key, &item.ProviderID, &item.ProviderName, &item.Attempts, &item.Successes, &item.LatencyP50MS, &item.LatencyP95MS, &latencyN, &item.TTFTP50MS, &ttftN,
			&item.Errors.HTTP5xx, &item.Errors.RateLimited, &item.Errors.Rejected, &item.Errors.Network, &item.Errors.Other, &item.FallbackOut, &item.FallbackIn, &fallbacks, &item.ModelCount); err != nil {
			rows.Close()
			return ProviderMonitor{}, err
		}
		item.SuccessRate = gated(ratio(item.Successes, item.Attempts), item.Attempts)
		item.LatencyP50MS, item.LatencyP95MS, item.TTFTP50MS = gated(item.LatencyP50MS, latencyN), gated(item.LatencyP95MS, latencyN), gated(item.TTFTP50MS, ttftN)
		if !isItem {
			out.Totals = ProviderTotals{Attempts: item.Attempts, SuccessRate: item.SuccessRate, Fallbacks: fallbacks, TTFTP50MS: item.TTFTP50MS}
			continue
		}
		item.Models, item.Hourly = []ProviderModelStat{}, providerTimeline(out.GeneratedAt, f.WindowHours)
		index[key] = len(out.Items)
		out.Items = append(out.Items, item)
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return ProviderMonitor{}, err
	}
	if rows, err = tx.Query(ctx, providerModelsSQL, args...); err != nil {
		return ProviderMonitor{}, err
	}
	for rows.Next() {
		var key string
		var m ProviderModelStat
		var successes int64
		if err = rows.Scan(&key, &m.ModelID, &m.ModelName, &m.Attempts, &successes); err != nil {
			rows.Close()
			return ProviderMonitor{}, err
		}
		m.SuccessRate = gated(ratio(successes, m.Attempts), m.Attempts)
		if i, ok := index[key]; ok {
			out.Items[i].Models = append(out.Items[i].Models, m)
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return ProviderMonitor{}, err
	}
	if rows, err = tx.Query(ctx, providerHourlySQL, args...); err != nil {
		return ProviderMonitor{}, err
	}
	for rows.Next() {
		var key string
		var bucket int
		var attempts, successes int64
		var p95 *float64
		if err = rows.Scan(&key, &bucket, &attempts, &successes, &p95); err != nil {
			rows.Close()
			return ProviderMonitor{}, err
		}
		if i, ok := index[key]; ok && bucket >= 0 && bucket < providerBuckets {
			p := &out.Items[i].Hourly[bucket]
			p.Attempts, p.SuccessRate, p.LatencyP95MS = attempts, ratio(successes, attempts), p95
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return ProviderMonitor{}, err
	}
	sort.SliceStable(out.Items, func(i, j int) bool {
		if out.Items[i].Attempts != out.Items[j].Attempts {
			return out.Items[i].Attempts > out.Items[j].Attempts
		}
		return out.Items[i].ProviderName < out.Items[j].ProviderName
	})
	return out, nil
}

func providerTimeline(now time.Time, hours int) []ProviderPoint {
	step := time.Duration(hours) * 150 * time.Second
	start := now.Add(-time.Duration(hours) * time.Hour)
	points := make([]ProviderPoint, providerBuckets)
	for i := range points {
		points[i].At = start.Add(time.Duration(i) * step)
	}
	return points
}
