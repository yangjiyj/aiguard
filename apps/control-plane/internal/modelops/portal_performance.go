package modelops

import (
	"context"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// 门户按模型名跨渠道聚合，口径与 modelOperationsQualitySQL 一致：拦截与取消不进成功率分母；
// 首字、TPS、总耗时只统计成功请求；TPS 要求生成窗口不少于 1 秒，安全缓冲后整段转发的短窗口会把速度算得离谱。参数：$1 租户、$2 窗口小时、$3 桶宽秒、$4 桶数。
const modelPerformanceSQL = `WITH base AS (
 SELECT m.model_name, r.request_status, r.upstream_status_code, r.latency_ms, r.upstream_ttft_ms, r.output_tokens, r.created_at,
  (r.output_audit_result #>> '{response_metadata,timing,generation_ms}')::int AS generation_ms
 FROM request_logs r JOIN models m ON m.id=r.model_id JOIN providers p ON p.id=m.provider_id AND p.tenant_id=$1
 WHERE r.tenant_id=$1 AND r.created_at>=now()-make_interval(hours=>$2) AND r.created_at<now()
), measured AS (
 SELECT model_name, latency_ms, upstream_ttft_ms,
  (request_status='success' AND upstream_status_code BETWEEN 200 AND 299) AS ok,
  (upstream_status_code BETWEEN 100 AND 599 AND request_status NOT IN ('blocked','cancelled','canceled')) AS upstream,
  CASE WHEN COALESCE(generation_ms,latency_ms-upstream_ttft_ms)>=1000 AND output_tokens>0
   THEN output_tokens::float8*1000/COALESCE(generation_ms,latency_ms-upstream_ttft_ms) END AS tps,
  LEAST(floor(extract(epoch FROM created_at-(now()-make_interval(hours=>$2)))/$3)::int, $4-1) AS bucket
 FROM base
)
SELECT model_name, GROUPING(bucket)=1, COALESCE(bucket,-1),
 count(*) FILTER (WHERE upstream), count(*) FILTER (WHERE upstream AND ok),
 percentile_cont(.5) WITHIN GROUP (ORDER BY upstream_ttft_ms) FILTER (WHERE ok AND upstream_ttft_ms>=0),
 percentile_cont(.95) WITHIN GROUP (ORDER BY upstream_ttft_ms) FILTER (WHERE ok AND upstream_ttft_ms>=0),
 count(*) FILTER (WHERE ok AND upstream_ttft_ms>=0),
 percentile_cont(.5) WITHIN GROUP (ORDER BY tps) FILTER (WHERE ok AND tps IS NOT NULL),
 count(*) FILTER (WHERE ok AND tps IS NOT NULL),
 percentile_cont(.5) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE ok AND latency_ms>=0),
 percentile_cont(.95) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE ok AND latency_ms>=0),
 count(*) FILTER (WHERE ok AND latency_ms>=0)
FROM measured GROUP BY GROUPING SETS ((model_name),(model_name,bucket))`

const modelProtocolsSQL = `SELECT m.model_name,
 COALESCE(bool_or(m.capabilities_json #>> '{protocols,chat_completions}'='true'),false),
 COALESCE(bool_or(m.capabilities_json #>> '{protocols,responses_native}'='true'),false),
 COALESCE(bool_or(m.capabilities_json #>> '{protocols,anthropic_messages}'='true'),false)
FROM models m JOIN providers p ON p.id=m.provider_id AND p.tenant_id=$1 WHERE m.status='active' GROUP BY 1`

func (s *PostgresStore) GetModelPerformance(ctx context.Context, tenant string, windowHours int) (ModelPerformanceReport, error) {
	hours, width, buckets, err := portalPerformanceWindow(windowHours)
	if err != nil {
		return ModelPerformanceReport{}, err
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return ModelPerformanceReport{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SET LOCAL statement_timeout = '5s'`); err != nil {
		return ModelPerformanceReport{}, err
	}
	out := ModelPerformanceReport{Data: []ModelPerformance{}, WindowHours: hours}
	if err = tx.QueryRow(ctx, `SELECT now()`).Scan(&out.GeneratedAt); err != nil {
		return ModelPerformanceReport{}, err
	}
	items := map[string]*ModelPerformance{}
	get := func(name string) *ModelPerformance {
		if item, ok := items[name]; ok {
			return item
		}
		start := out.GeneratedAt.Add(-time.Duration(hours) * time.Hour)
		item := &ModelPerformance{ModelName: name, Protocols: []string{}, Hourly: make([]PerformancePoint, buckets)}
		for i := range item.Hourly {
			item.Hourly[i].At = start.Add(time.Duration(i*width) * time.Second)
		}
		items[name] = item
		return item
	}
	rows, err := tx.Query(ctx, modelProtocolsSQL, tenant)
	if err != nil {
		return ModelPerformanceReport{}, err
	}
	for rows.Next() {
		var name string
		var chat, responses, messages bool
		if err = rows.Scan(&name, &chat, &responses, &messages); err != nil {
			rows.Close()
			return ModelPerformanceReport{}, err
		}
		item := get(name)
		for _, p := range []struct {
			on   bool
			name string
		}{{chat, "chat"}, {responses, "responses"}, {messages, "messages"}} {
			if p.on {
				item.Protocols = append(item.Protocols, p.name)
			}
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return ModelPerformanceReport{}, err
	}
	if rows, err = tx.Query(ctx, modelPerformanceSQL, tenant, hours, width, buckets); err != nil {
		return ModelPerformanceReport{}, err
	}
	for rows.Next() {
		var name string
		var whole bool
		var bucket int
		var samples, successes, ttftN, tpsN, latencyN int64
		var ttft50, ttft95, tps50, lat50, lat95 *float64
		if err = rows.Scan(&name, &whole, &bucket, &samples, &successes, &ttft50, &ttft95, &ttftN, &tps50, &tpsN, &lat50, &lat95, &latencyN); err != nil {
			rows.Close()
			return ModelPerformanceReport{}, err
		}
		item := get(name)
		if whole {
			item.Samples, item.SuccessRate = samples, gated(ratio(successes, samples), samples)
			item.TTFTP50MS, item.TTFTP95MS, item.TPSP50 = gated(ttft50, ttftN), gated(ttft95, ttftN), gated(tps50, tpsN)
			item.LatencyP50MS, item.LatencyP95MS = gated(lat50, latencyN), gated(lat95, latencyN)
			continue
		}
		if bucket >= 0 && bucket < buckets {
			item.Hourly[bucket] = PerformancePoint{At: item.Hourly[bucket].At, Samples: samples, SuccessRate: ratio(successes, samples), TTFTP50MS: ttft50, TPSP50: tps50}
		}
	}
	rows.Close()
	if err = rows.Err(); err != nil {
		return ModelPerformanceReport{}, err
	}
	for _, item := range items {
		out.Data = append(out.Data, *item)
	}
	sort.Slice(out.Data, func(i, j int) bool { return out.Data[i].ModelName < out.Data[j].ModelName })
	return out, nil
}
