package modelops

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type pageCursor struct {
	At time.Time `json:"at"`
	ID string    `json:"id"`
}

func encodeCursor(at time.Time, id string) string {
	b, _ := json.Marshal(pageCursor{at, id})
	return base64.RawURLEncoding.EncodeToString(b)
}
func decodeCursor(raw string) (pageCursor, error) {
	if raw == "" {
		return pageCursor{At: time.Date(9999, 12, 31, 0, 0, 0, 0, time.UTC), ID: "~"}, nil
	}
	if len(raw) > 512 {
		return pageCursor{}, ErrInvalid
	}
	b, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return pageCursor{}, ErrInvalid
	}
	var c pageCursor
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if d.Decode(&c) != nil || c.At.IsZero() || c.ID == "" || len(c.ID) > 64 {
		return c, ErrInvalid
	}
	return c, nil
}
func pageLimit(n int) (int, error) {
	if n == 0 {
		return 50, nil
	}
	if n < 1 || n > 100 {
		return 0, ErrInvalid
	}
	return n, nil
}

const historyColumns = `id,model_id,model_name,provider_id,provider_name,upstream_model_id,protocol,config_digest,source,actor,created_at,config_version,epoch,success,http_status,body_validated,latency_ms,error_kind,invocation_id`

func scanHistory(row scanner) (ProbeRecord, error) {
	var r ProbeRecord
	err := row.Scan(&r.ID, &r.ModelID, &r.ModelName, &r.ProviderID, &r.ProviderName, &r.UpstreamModelID, &r.Protocol, &r.ConfigDigest, &r.Source, &r.Actor, &r.CreatedAt, &r.ConfigVersion, &r.Epoch, &r.Success, &r.HTTPStatus, &r.BodyValidated, &r.LatencyMS, &r.ErrorKind, &r.InvocationID)
	r.Supported = true
	return r, err
}
func (s *PostgresStore) ListHistory(ctx context.Context, tenant string, f HistoryFilter) (HistoryPage, error) {
	lim, err := pageLimit(f.Limit)
	if err != nil {
		return HistoryPage{}, err
	}
	c, err := decodeCursor(f.Cursor)
	if err != nil {
		return HistoryPage{}, err
	}
	rf, err := (ReadFilter{WindowHours: f.WindowHours}).validated()
	if err != nil {
		return HistoryPage{}, err
	}
	if f.Protocol != "" && f.Protocol != "chat" && f.Protocol != "responses" && f.Protocol != "messages" {
		return HistoryPage{}, ErrInvalid
	}
	if f.Source != "" && f.Source != "manual" && f.Source != "scheduled" {
		return HistoryPage{}, ErrInvalid
	}
	rows, err := s.pool.Query(ctx, `SELECT `+historyColumns+` FROM model_ops_probe_history WHERE tenant_id=$1 AND (created_at,id)<($2,$3) AND ($4='' OR model_id=$4) AND ($5='' OR provider_id=$5) AND ($6='' OR protocol=$6) AND ($7='' OR source=$7) AND ($9<>'' OR created_at>=clock_timestamp()-make_interval(hours=>$8)) AND ($9='' OR invocation_id=$9) ORDER BY created_at DESC,id DESC LIMIT $10`, tenant, c.At, c.ID, f.ModelID, f.ProviderID, f.Protocol, f.Source, rf.WindowHours, f.InvocationID, lim+1)
	if err != nil {
		return HistoryPage{}, err
	}
	defer rows.Close()
	page := HistoryPage{Items: []ProbeRecord{}}
	for rows.Next() {
		r, err := scanHistory(rows)
		if err != nil {
			return page, err
		}
		page.Items = append(page.Items, r)
	}
	if err := rows.Err(); err != nil {
		return page, err
	}
	if len(page.Items) > lim {
		page.Items = page.Items[:lim]
		last := page.Items[lim-1]
		page.NextCursor = encodeCursor(last.CreatedAt, last.ID)
	}
	return page, nil
}

func ratio(success, samples int64) *float64 {
	if samples == 0 {
		return nil
	}
	v := float64(success) / float64(samples)
	return &v
}
func (s *PostgresStore) GetOverview(ctx context.Context, tenant string, f ReadFilter) (Overview, error) {
	f, err := f.validated()
	if err != nil {
		return Overview{}, err
	}
	cfg, err := s.GetConfig(ctx, tenant)
	if err != nil {
		return Overview{}, err
	}
	// Include explicit manual observations for pending models without scheduling them.
	targets, err := s.ListManualTargets(ctx, tenant, nil)
	if err != nil {
		return Overview{}, err
	}
	out := Overview{Config: cfg, GeneratedAt: time.Now().UTC().Truncate(time.Microsecond), Targets: []TargetSummary{}}
	for _, t := range targets {
		if (f.ProviderID != "" && t.ProviderID != f.ProviderID) || (f.ModelID != "" && t.ModelID != f.ModelID) {
			continue
		}
		summary := TargetSummary{Target: t, State: "unknown", Hourly: []HourlyPoint{}}
		err = s.pool.QueryRow(ctx, `SELECT count(*),count(*) FILTER(WHERE success),percentile_cont(.5) WITHIN GROUP(ORDER BY latency_ms) FILTER(WHERE success),percentile_cont(.95) WITHIN GROUP(ORDER BY latency_ms) FILTER(WHERE success) FROM model_ops_probe_history WHERE tenant_id=$1 AND model_id=$2 AND provider_id=$3 AND protocol=$4 AND identity_digest=$5 AND created_at>=$7::timestamptz-make_interval(hours=>$6) AND created_at<$7`, tenant, t.ModelID, t.ProviderID, t.Protocol, t.IdentityDigest, f.WindowHours, out.GeneratedAt).Scan(&summary.Samples, &summary.Successes, &summary.P50MS, &summary.P95MS)
		if err != nil {
			return Overview{}, err
		}
		summary.Availability = ratio(summary.Successes, summary.Samples)
		var latest time.Time
		var success bool
		err = s.pool.QueryRow(ctx, `SELECT created_at,success,error_kind FROM model_ops_probe_history WHERE tenant_id=$1 AND model_id=$2 AND provider_id=$3 AND protocol=$4 AND identity_digest=$5 AND created_at<$6 ORDER BY created_at DESC,id DESC LIMIT 1`, tenant, t.ModelID, t.ProviderID, t.Protocol, t.IdentityDigest, out.GeneratedAt).Scan(&latest, &success, &summary.LastError)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return Overview{}, err
		}
		if err == nil {
			summary.LastProbeAt = &latest
			summary.State = "degraded"
			if success {
				summary.State = "healthy"
			}
			stale := time.Duration(cfg.IntervalSeconds*3) * time.Second
			if stale < 15*time.Minute {
				stale = 15 * time.Minute
			}
			if out.GeneratedAt.Sub(latest) > stale {
				summary.State = "stale"
			}
		}
		rows, err := s.pool.Query(ctx, `SELECT buckets.hour,count(h.id),count(h.id) FILTER(WHERE h.success),percentile_cont(.5) WITHIN GROUP(ORDER BY h.latency_ms) FILTER(WHERE h.success),percentile_cont(.95) WITHIN GROUP(ORDER BY h.latency_ms) FILTER(WHERE h.success) FROM generate_series($7::timestamptz-make_interval(hours=>$6),$7::timestamptz-make_interval(secs=>$6*150),make_interval(secs=>$6*150)) buckets(hour) LEFT JOIN model_ops_probe_history h ON h.tenant_id=$1 AND h.model_id=$2 AND h.provider_id=$3 AND h.protocol=$4 AND h.identity_digest=$5 AND h.created_at>=buckets.hour AND h.created_at<buckets.hour+make_interval(secs=>$6*150) GROUP BY buckets.hour ORDER BY buckets.hour`, tenant, t.ModelID, t.ProviderID, t.Protocol, t.IdentityDigest, f.WindowHours, out.GeneratedAt)
		if err != nil {
			return Overview{}, err
		}
		for rows.Next() {
			var p HourlyPoint
			if err = rows.Scan(&p.Hour, &p.Samples, &p.Successes, &p.P50MS, &p.P95MS); err != nil {
				rows.Close()
				return Overview{}, err
			}
			p.Availability = ratio(p.Successes, p.Samples)
			summary.Hourly = append(summary.Hourly, p)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return Overview{}, err
		}
		out.Targets = append(out.Targets, summary)
	}
	return out, nil
}

// nonBusinessRequestLogs 排除平台自建的请求日志（名单见 repository.NonBusinessEndpointTypes）。
var nonBusinessRequestLogs = repository.ExcludeNonBusinessEndpointsSQL("r")

// 性能分位数只统计成功请求；每分钟均值按完整窗口计算，包含无流量分钟。
var modelOperationsQualitySQL = `WITH timing_source AS (
 SELECT r.*,
 (r.output_audit_result #>> '{response_metadata,timing,input_security_ms}')::int AS input_security_ms,
 (r.output_audit_result #>> '{response_metadata,timing,output_security_ms}')::int AS output_security_ms,
 (r.output_audit_result #>> '{response_metadata,timing,pre_upstream_ms}')::int AS pre_upstream_ms,
 (r.output_audit_result #>> '{response_metadata,timing,generation_ms}')::int AS generation_ms
 FROM request_logs r
 WHERE r.tenant_id=$1 AND r.created_at>=statement_timestamp()-make_interval(hours=>$2) AND r.created_at<statement_timestamp()
 AND ($3='' OR r.provider_id=$3) AND ($4='' OR r.model_id=$4)
 AND ` + nonBusinessRequestLogs + `
), measured AS (
 SELECT *, CASE WHEN input_security_ms>=0 OR output_security_ms>=0
 THEN COALESCE(input_security_ms,0)+COALESCE(output_security_ms,0) END AS security_ms,
 CASE WHEN COALESCE(generation_ms,latency_ms-upstream_ttft_ms)>=200 AND output_tokens>0
 THEN output_tokens::float8*1000/COALESCE(generation_ms,latency_ms-upstream_ttft_ms) END AS output_tokens_per_sec
 FROM timing_source
)
SELECT COALESCE(r.model_id,''),COALESCE(m.model_name,''),COALESCE(r.provider_id,''),COALESCE(p.name,''),count(*),count(*) FILTER(WHERE r.request_status='success'),count(*) FILTER(WHERE r.request_status NOT IN ('blocked','cancelled','canceled') AND r.upstream_status_code BETWEEN 400 AND 599),count(*) FILTER(WHERE r.upstream_status_code IN (401,403) AND r.request_status NOT IN ('blocked','cancelled','canceled')),percentile_cont(.5) WITHIN GROUP(ORDER BY r.latency_ms) FILTER(WHERE r.request_status='success' AND r.latency_ms>=0),percentile_cont(.95) WITHIN GROUP(ORDER BY r.latency_ms) FILTER(WHERE r.request_status='success' AND r.latency_ms>=0),max(r.created_at),count(*) FILTER(WHERE r.upstream_status_code BETWEEN 500 AND 599 AND r.request_status NOT IN ('blocked','cancelled','canceled')),count(*) FILTER(WHERE r.upstream_status_code=429 AND r.request_status NOT IN ('blocked','cancelled','canceled')),count(*) FILTER(WHERE r.upstream_status_code BETWEEN 400 AND 499 AND r.upstream_status_code<>429 AND r.request_status NOT IN ('blocked','cancelled','canceled')),count(*) FILTER(WHERE r.request_status IN ('cancelled','canceled')),avg(r.upstream_ttft_ms) FILTER(WHERE r.upstream_ttft_ms>=0 AND r.request_status='success'),(array_agg(r.request_id ORDER BY r.created_at DESC,r.id DESC))[1],count(*) FILTER(WHERE r.upstream_status_code BETWEEN 100 AND 599 AND r.request_status NOT IN ('blocked','cancelled','canceled')),count(*) FILTER(WHERE r.request_status='success' AND r.upstream_status_code BETWEEN 200 AND 299),count(*) FILTER(WHERE r.request_status='blocked'),
 percentile_cont(.5) WITHIN GROUP(ORDER BY r.upstream_ttft_ms) FILTER(WHERE r.request_status='success' AND r.upstream_ttft_ms>=0),
 percentile_cont(.95) WITHIN GROUP(ORDER BY r.upstream_ttft_ms) FILTER(WHERE r.request_status='success' AND r.upstream_ttft_ms>=0),
 percentile_cont(.5) WITHIN GROUP(ORDER BY r.output_tokens_per_sec) FILTER(WHERE r.request_status='success'),
 percentile_cont(.5) WITHIN GROUP(ORDER BY r.security_ms) FILTER(WHERE r.request_status='success'),
 percentile_cont(.95) WITHIN GROUP(ORDER BY r.security_ms) FILTER(WHERE r.request_status='success'),
 percentile_cont(.5) WITHIN GROUP(ORDER BY r.pre_upstream_ms) FILTER(WHERE r.request_status='success' AND r.pre_upstream_ms>=0),
 percentile_cont(.95) WITHIN GROUP(ORDER BY r.pre_upstream_ms) FILTER(WHERE r.request_status='success' AND r.pre_upstream_ms>=0),
 count(*)::float8 / ($2::int * 60.0),
 COALESCE(sum(GREATEST(COALESCE(r.input_tokens,0),0)::bigint+GREATEST(COALESCE(r.output_tokens,0),0)::bigint),0)::float8 / ($2::int * 60.0)
 FROM measured r LEFT JOIN models m ON m.id=r.model_id AND EXISTS(SELECT 1 FROM providers mp WHERE mp.id=m.provider_id AND mp.tenant_id=r.tenant_id) LEFT JOIN providers p ON p.id=r.provider_id AND p.tenant_id=r.tenant_id GROUP BY r.model_id,m.model_name,r.provider_id,p.name ORDER BY m.model_name,r.provider_id,r.model_id`

func (s *PostgresStore) GetQuality(ctx context.Context, tenant string, f ReadFilter) (Quality, error) {
	f, err := f.validated()
	if err != nil {
		return Quality{}, err
	}
	rows, err := s.pool.Query(ctx, modelOperationsQualitySQL, tenant, f.WindowHours, f.ProviderID, f.ModelID)
	if err != nil {
		return Quality{}, err
	}
	defer rows.Close()
	out := Quality{Items: []QualityItem{}, GeneratedAt: time.Now().UTC(), Note: "每分钟请求数、词元数按所选完整窗口分钟数均摊，含无流量分钟；词元为输入与输出之和，计入全部请求。首字、输出速度和分段分位数仅统计成功请求；安全检测为已采集输入与输出之和，网关处理包含输入检测。"}
	for rows.Next() {
		var q QualityItem
		err = rows.Scan(&q.ModelID, &q.ModelName, &q.ProviderID, &q.ProviderName, &q.Samples, &q.Successes, &q.Failures, &q.AuthFailures, &q.P50MS, &q.P95MS, &q.LastRequestAt, &q.HTTP5xx, &q.HTTP429, &q.HTTP4xx, &q.Cancelled, &q.AvgFirstEventMS, &q.LastRequestID, &q.UpstreamSamples, &q.UpstreamSuccesses, &q.Blocked, &q.FirstEventP50MS, &q.FirstEventP95MS, &q.OutputTokensPerSecP50, &q.SecurityP50MS, &q.SecurityP95MS, &q.PreUpstreamP50MS, &q.PreUpstreamP95MS, &q.RPM, &q.TPM)
		if err != nil {
			return Quality{}, err
		}
		q.Availability = ratio(q.UpstreamSuccesses, q.UpstreamSamples)
		out.Items = append(out.Items, q)
	}
	return out, rows.Err()
}

const alertColumns = `id,model_id,model_name,provider_id,provider_name,upstream_model_id,protocol,config_digest,state,failure_count,last_error,opened_at,updated_at,resolved_at,acknowledged_at,acknowledged_by`

func scanAlert(row scanner) (Alert, error) {
	var a Alert
	err := row.Scan(&a.ID, &a.ModelID, &a.ModelName, &a.ProviderID, &a.ProviderName, &a.UpstreamModelID, &a.Protocol, &a.ConfigDigest, &a.State, &a.FailureCount, &a.LastError, &a.OpenedAt, &a.UpdatedAt, &a.ResolvedAt, &a.AcknowledgedAt, &a.AcknowledgedBy)
	a.Supported = true
	return a, err
}
func (s *PostgresStore) ListAlerts(ctx context.Context, tenant string, f AlertFilter) (AlertPage, error) {
	if f.State != "" && f.State != "open" && f.State != "resolved" {
		return AlertPage{}, ErrInvalid
	}
	lim, err := pageLimit(f.Limit)
	if err != nil {
		return AlertPage{}, err
	}
	c, err := decodeCursor(f.Cursor)
	if err != nil {
		return AlertPage{}, err
	}
	rows, err := s.pool.Query(ctx, `SELECT `+alertColumns+` FROM model_ops_alerts WHERE tenant_id=$1 AND ($2='' OR state=$2) AND (opened_at,id)<($3,$4) AND ($5='' OR provider_id=$5) AND ($6='' OR model_id=$6) ORDER BY opened_at DESC,id DESC LIMIT $7`, tenant, f.State, c.At, c.ID, f.ProviderID, f.ModelID, lim+1)
	if err != nil {
		return AlertPage{}, err
	}
	defer rows.Close()
	out := AlertPage{Items: []Alert{}}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return out, err
		}
		out.Items = append(out.Items, a)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Items) > lim {
		out.Items = out.Items[:lim]
		last := out.Items[lim-1]
		out.NextCursor = encodeCursor(last.OpenedAt, last.ID)
	}
	return out, nil
}
func (s *PostgresStore) AcknowledgeAlert(ctx context.Context, tenant, id, actor string) (Alert, error) {
	if tenant == "" || id == "" || actor == "" {
		return Alert{}, ErrInvalid
	}
	a, err := scanAlert(s.pool.QueryRow(ctx, `UPDATE model_ops_alerts SET acknowledged_at=COALESCE(acknowledged_at,clock_timestamp()),acknowledged_by=CASE WHEN acknowledged_at IS NULL THEN $3 ELSE acknowledged_by END WHERE tenant_id=$1 AND id=$2 RETURNING `+alertColumns, tenant, id, actor))
	if errors.Is(err, pgx.ErrNoRows) {
		return Alert{}, ErrUnavailable
	}
	return a, err
}
