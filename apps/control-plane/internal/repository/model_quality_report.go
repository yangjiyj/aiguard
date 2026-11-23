package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	_ "time/tzdata"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrModelQualityScopeNotFound = errors.New("model quality scope not found")

type ModelQualityWindow struct {
	Month    string    `json:"month"`
	Timezone string    `json:"timezone"`
	Start    time.Time `json:"start_at"`
	End      time.Time `json:"end_at"`
}

func ParseModelQualityWindow(month, timezone string, now time.Time) (ModelQualityWindow, error) {
	if timezone == "" {
		timezone = "Asia/Shanghai"
	}
	if len(timezone) > 64 || strings.ContainsAny(timezone, "\x00\r\n") {
		return ModelQualityWindow{}, errors.New("invalid timezone")
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return ModelQualityWindow{}, errors.New("invalid timezone")
	}
	if month == "" {
		month = now.In(location).Format("2006-01")
	}
	parsed, err := time.ParseInLocation("2006-01", month, location)
	if err != nil || len(month) != 7 || parsed.Year() < 2020 || parsed.Year() > now.Year()+1 {
		return ModelQualityWindow{}, errors.New("invalid month")
	}
	return ModelQualityWindow{Month: month, Timezone: timezone, Start: parsed.UTC(), End: parsed.AddDate(0, 1, 0).UTC()}, nil
}

type ModelObservationMetrics struct {
	OutputTokensPerSecP50 *float64 `json:"output_tokens_per_sec_p50"`
	SecurityP50MS         *float64 `json:"security_p50_ms"`
	SecurityP95MS         *float64 `json:"security_p95_ms"`
	PreUpstreamP50MS      *float64 `json:"pre_upstream_p50_ms"`
	PreUpstreamP95MS      *float64 `json:"pre_upstream_p95_ms"`
	RPM                   *float64 `json:"rpm"`
	TPM                   *float64 `json:"tpm"`
	Requests              int64    `json:"requests"`
	EligibleRequests      int64    `json:"eligible_requests"`
	HTTPSuccesses         int64    `json:"http_successes"`
	PlatformFailures      int64    `json:"platform_failures"`
	ClientErrors          int64    `json:"client_errors"`
	AuthFailures          int64    `json:"auth_failures"`
	Cancelled             int64    `json:"cancelled"`
	Blocked               int64    `json:"blocked"`
	Unknown               int64    `json:"unknown"`
	Availability          *float64 `json:"availability"`
	P50MS                 *float64 `json:"p50_ms"`
	P95MS                 *float64 `json:"p95_ms"`
	FirstEventP50MS       *float64 `json:"first_event_p50_ms"`
	FirstEventP95MS       *float64 `json:"first_event_p95_ms"`
	FirstEventSamples     int64    `json:"first_event_samples"`
	ActiveMinutes         int64    `json:"active_minutes"`
	DownMinutes           int64    `json:"down_minutes"`
	MinuteAvailability    *float64 `json:"minute_availability"`
}

type ModelQualityGroup struct {
	ModelID      string `json:"model_id"`
	ModelName    string `json:"model_name"`
	ProviderID   string `json:"provider_id"`
	ProviderName string `json:"provider_name"`
	ModelObservationMetrics
}

type ModelQualityDay struct {
	Day string `json:"day"`
	ModelObservationMetrics
}

type ModelQualityReport struct {
	ModelQualityWindow
	GeneratedAt   time.Time               `json:"generated_at"`
	ObservedUntil time.Time               `json:"observed_until"`
	InProgress    bool                    `json:"in_progress"`
	Available     bool                    `json:"available"`
	Totals        ModelObservationMetrics `json:"totals"`
	Models        []ModelQualityGroup     `json:"models"`
	Days          []ModelQualityDay       `json:"days"`
	Note          string                  `json:"note"`
}

type ModelQualityReportRepository struct{ db *pgxpool.Pool }

func NewModelQualityReportRepository(db *pgxpool.Pool) *ModelQualityReportRepository {
	return &ModelQualityReportRepository{db: db}
}

// Only terminal upstream observations enter availability. Policy blocks,
// cancellations and missing dispatch evidence remain distinct evidence.
const modelQualitySourceSQL = `WITH source AS (
 SELECT rl.created_at, rl.latency_ms, rl.upstream_ttft_ms, rl.input_tokens, rl.output_tokens,
 (rl.output_audit_result #>> '{response_metadata,timing,input_security_ms}')::int AS input_security_ms,
 (rl.output_audit_result #>> '{response_metadata,timing,output_security_ms}')::int AS output_security_ms,
 (rl.output_audit_result #>> '{response_metadata,timing,pre_upstream_ms}')::int AS pre_upstream_ms,
 (rl.output_audit_result #>> '{response_metadata,timing,generation_ms}')::int AS generation_ms,
 COALESCE(rl.model_id,'') AS model_id, COALESCE(rl.provider_id,'') AS provider_id,
 CASE WHEN mp.id IS NOT NULL THEN COALESCE(m.model_label,m.model_name,'') ELSE '' END AS model_name,
 COALESCE(p.name,'') AS provider_name,
 COALESCE(rl.request_status,'') IN ('cancelled','client_cancelled','canceled') OR rl.upstream_status_code=499 AS cancelled,
 COALESCE(rl.request_status,'') IN ('blocked','policy_blocked','denied','rejected') AS blocked,
 rl.upstream_status_code >= 200 AND rl.upstream_status_code < 400 AS http_success,
 rl.upstream_status_code BETWEEN 400 AND 498 AND rl.upstream_status_code NOT IN (401,403,429) AS client_error,
 rl.upstream_status_code IN (401,403) AS auth_failure,
 rl.upstream_status_code>=500 OR rl.upstream_status_code IN (401,403,429) OR
 (rl.upstream_status_code IS NULL AND COALESCE(rl.request_status,'') IN ('failed','timeout','upstream_error')) AS platform_failure,
 rl.upstream_status_code IS NOT NULL OR COALESCE(rl.request_status,'') IN ('failed','timeout','upstream_error') AS known
 FROM request_logs rl
 LEFT JOIN models m ON m.id=rl.model_id
 LEFT JOIN providers mp ON mp.id=m.provider_id AND mp.tenant_id=rl.tenant_id
 LEFT JOIN providers p ON p.id=rl.provider_id AND p.tenant_id=rl.tenant_id
 WHERE rl.tenant_id=$1 AND rl.created_at >= $2 AND rl.created_at < $3
 AND ($4='' OR rl.provider_id=$4) AND ($5='' OR rl.model_id=$5)
), observations AS (
 SELECT *, COALESCE(known,false) AND NOT COALESCE(cancelled,false) AND NOT COALESCE(blocked,false) AS eligible,
 CASE WHEN input_security_ms >= 0 OR output_security_ms >= 0 THEN COALESCE(input_security_ms,0)+COALESCE(output_security_ms,0) END AS security_ms,
 CASE WHEN COALESCE(generation_ms,latency_ms-upstream_ttft_ms)>=200 AND output_tokens>0
 THEN output_tokens::float8*1000/COALESCE(generation_ms,latency_ms-upstream_ttft_ms) END AS output_tokens_per_sec,
 to_char(timezone($6,created_at),'YYYY-MM-DD') AS day FROM source
)`

const modelQualityAggregateSQL = `COUNT(*) AS requests,
 COUNT(*) FILTER (WHERE eligible) AS eligible_requests,
 COUNT(*) FILTER (WHERE eligible AND http_success) AS http_successes,
 COUNT(*) FILTER (WHERE eligible AND platform_failure) AS platform_failures,
 COUNT(*) FILTER (WHERE eligible AND client_error) AS client_errors,
 COUNT(*) FILTER (WHERE eligible AND auth_failure) AS auth_failures,
 COUNT(*) FILTER (WHERE cancelled) AS cancelled,
 COUNT(*) FILTER (WHERE blocked AND NOT COALESCE(cancelled,false)) AS blocked,
 COUNT(*) FILTER (WHERE NOT eligible AND NOT COALESCE(cancelled,false) AND NOT COALESCE(blocked,false)) AS unknown,
 1.0-COUNT(*) FILTER (WHERE eligible AND platform_failure)::float8/NULLIF(COUNT(*) FILTER (WHERE eligible),0) AS availability,
 percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE eligible AND http_success AND latency_ms>=0) AS p50_ms,
 percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) FILTER (WHERE eligible AND http_success AND latency_ms>=0) AS p95_ms,
 percentile_cont(0.5) WITHIN GROUP (ORDER BY upstream_ttft_ms) FILTER (WHERE eligible AND http_success AND upstream_ttft_ms>=0) AS first_event_p50_ms,
 percentile_cont(0.95) WITHIN GROUP (ORDER BY upstream_ttft_ms) FILTER (WHERE eligible AND http_success AND upstream_ttft_ms>=0) AS first_event_p95_ms,
 COUNT(*) FILTER (WHERE eligible AND http_success AND upstream_ttft_ms>=0) AS first_event_samples,
 percentile_cont(0.5) WITHIN GROUP (ORDER BY output_tokens_per_sec) FILTER (WHERE eligible AND http_success) AS output_tokens_per_sec_p50,
 percentile_cont(0.5) WITHIN GROUP (ORDER BY security_ms) FILTER (WHERE eligible AND http_success) AS security_p50_ms,
 percentile_cont(0.95) WITHIN GROUP (ORDER BY security_ms) FILTER (WHERE eligible AND http_success) AS security_p95_ms,
 percentile_cont(0.5) WITHIN GROUP (ORDER BY pre_upstream_ms) FILTER (WHERE eligible AND http_success AND pre_upstream_ms>=0) AS pre_upstream_p50_ms,
 percentile_cont(0.95) WITHIN GROUP (ORDER BY pre_upstream_ms) FILTER (WHERE eligible AND http_success AND pre_upstream_ms>=0) AS pre_upstream_p95_ms,
 COUNT(*)::float8 / NULLIF(GREATEST(EXTRACT(EPOCH FROM ($3::timestamptz-$2::timestamptz))/60,0),0) AS rpm,
 COALESCE(SUM(GREATEST(COALESCE(input_tokens,0),0)+GREATEST(COALESCE(output_tokens,0),0)),0)::float8 / NULLIF(GREATEST(EXTRACT(EPOCH FROM ($3::timestamptz-$2::timestamptz))/60,0),0) AS tpm`

func (r *ModelQualityReportRepository) Report(ctx context.Context, tenantID, providerID, modelID string, window ModelQualityWindow, now time.Time) (ModelQualityReport, error) {
	if r == nil || r.db == nil || strings.TrimSpace(tenantID) == "" {
		return ModelQualityReport{}, errors.New("quality repository unavailable")
	}
	tx, err := r.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return ModelQualityReport{}, err
	}
	defer tx.Rollback(ctx)
	for _, scope := range []struct{ id, query string }{
		{providerID, `SELECT EXISTS(SELECT 1 FROM providers WHERE id=$1 AND tenant_id=$2) OR EXISTS(SELECT 1 FROM request_logs WHERE provider_id=$1 AND tenant_id=$2)`},
		{modelID, `SELECT EXISTS(SELECT 1 FROM models m JOIN providers p ON p.id=m.provider_id WHERE m.id=$1 AND p.tenant_id=$2) OR EXISTS(SELECT 1 FROM request_logs WHERE model_id=$1 AND tenant_id=$2)`},
	} {
		if scope.id == "" {
			continue
		}
		var owned bool
		if err = tx.QueryRow(ctx, scope.query, scope.id, tenantID).Scan(&owned); err != nil {
			return ModelQualityReport{}, err
		}
		if !owned {
			return ModelQualityReport{}, ErrModelQualityScopeNotFound
		}
	}
	until := window.End
	if now.Before(until) {
		until = now.UTC()
	}
	args := []any{tenantID, window.Start, until, providerID, modelID, window.Timezone}
	query := modelQualitySourceSQL + `, stats AS (SELECT ` + modelQualityAggregateSQL + ` FROM observations), minutes AS (
 SELECT date_trunc('minute',created_at) AS minute, bool_or(platform_failure) AS down FROM observations WHERE eligible GROUP BY 1
), minute_stats AS (
 SELECT COUNT(*) AS active_minutes,COUNT(*) FILTER(WHERE down) AS down_minutes,
 1.0-COUNT(*) FILTER(WHERE down)::float8/NULLIF(COUNT(*),0) AS minute_availability FROM minutes
), model_stats AS (
	 SELECT model_id,provider_id,model_name,provider_name,` + modelQualityAggregateSQL + ` FROM observations GROUP BY 1,2,3,4
), target_minutes AS (
 SELECT model_id,provider_id,date_trunc('minute',created_at) AS minute,bool_or(platform_failure) AS down FROM observations WHERE eligible GROUP BY 1,2,3
), target_minute_stats AS (
 SELECT model_id,provider_id,COUNT(*) AS active_minutes,COUNT(*) FILTER(WHERE down) AS down_minutes,
 1.0-COUNT(*) FILTER(WHERE down)::float8/NULLIF(COUNT(*),0) AS minute_availability FROM target_minutes GROUP BY 1,2
), day_stats AS (SELECT day,` + modelQualityAggregateSQL + ` FROM observations GROUP BY day), day_minutes AS (
 SELECT day,date_trunc('minute',created_at) AS minute,bool_or(platform_failure) AS down FROM observations WHERE eligible GROUP BY 1,2
), day_minute_stats AS (
 SELECT day,COUNT(*) AS active_minutes,COUNT(*) FILTER(WHERE down) AS down_minutes,
 1.0-COUNT(*) FILTER(WHERE down)::float8/NULLIF(COUNT(*),0) AS minute_availability FROM day_minutes GROUP BY 1
)
 SELECT jsonb_build_object('totals',to_jsonb(stats)||to_jsonb(minute_stats),
 'models',COALESCE((SELECT jsonb_agg(to_jsonb(ms)||jsonb_build_object('active_minutes',COALESCE(mm.active_minutes,0),'down_minutes',COALESCE(mm.down_minutes,0),'minute_availability',mm.minute_availability) ORDER BY ms.requests DESC,ms.provider_id,ms.model_id)
 FROM model_stats ms LEFT JOIN target_minute_stats mm USING(model_id,provider_id)),'[]'::jsonb),
 'days',COALESCE((SELECT jsonb_agg(to_jsonb(ds)||jsonb_build_object('active_minutes',COALESCE(dm.active_minutes,0),'down_minutes',COALESCE(dm.down_minutes,0),'minute_availability',dm.minute_availability) ORDER BY ds.day)
 FROM day_stats ds LEFT JOIN day_minute_stats dm USING(day)),'[]'::jsonb))
 FROM stats,minute_stats`
	var encoded []byte
	if err = tx.QueryRow(ctx, query, args...).Scan(&encoded); err != nil {
		return ModelQualityReport{}, fmt.Errorf("read monthly model quality: %w", err)
	}
	var report ModelQualityReport
	if err = json.Unmarshal(encoded, &report); err != nil {
		return ModelQualityReport{}, err
	}
	// 日维度分母裁剪到本地日与观察窗口的交集，含无流量分钟，避免把月均值误作日均值。
	location, _ := time.LoadLocation(window.Timezone)
	if location == nil {
		location = time.UTC
	}
	for i := range report.Days {
		day, parseErr := time.ParseInLocation("2006-01-02", report.Days[i].Day, location)
		if parseErr != nil {
			continue
		}
		start, end := day.UTC(), day.AddDate(0, 0, 1).UTC()
		if start.Before(window.Start) {
			start = window.Start
		}
		if end.After(until) {
			end = until
		}
		if end.After(start) {
			factor := until.Sub(window.Start).Minutes() / end.Sub(start).Minutes()
			if report.Days[i].RPM != nil {
				*report.Days[i].RPM *= factor
			}
			if report.Days[i].TPM != nil {
				*report.Days[i].TPM *= factor
			}
		}
	}
	report.ModelQualityWindow = window
	report.GeneratedAt = now.UTC()
	report.ObservedUntil = until
	report.InProgress = !now.Before(window.Start) && now.Before(window.End)
	report.Available = report.Totals.EligibleRequests > 0
	report.Note = "每分钟请求数/词元数按观察窗口全部分钟均摊（含无流量分钟）；当前月截止生成时刻，日维度按本地日裁剪。词元数为输入与输出之和，全部请求计入。输出速度与分段分位数仅统计成功调用；安全检测为已采集输入与输出之和；网关处理为发出请求前总耗时，包含输入检测。Observed business traffic only. Upstream authentication failures, 5xx, 429 and transport failures affect availability; other upstream 4xx are counted separately and do not prove caller fault. Policy blocks, cancellations and missing dispatch evidence are excluded. Silent minutes are unobserved. Latency is successful full request duration; first event includes text, reasoning or tool output, not TPOT."
	if err = tx.Commit(ctx); err != nil {
		return ModelQualityReport{}, err
	}
	return report, nil
}
