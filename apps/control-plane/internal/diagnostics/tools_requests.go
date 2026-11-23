package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 请求类工具：get_request / search_requests / compare_windows。
// 失败分类 SQL 一律复用 repository.Usage*SQL，不另写分类逻辑；这些片段以表别名 rl 为前提。

const (
	t3DefaultWindowH   = 1
	t3MaxWindowH       = 24
	t3MaxHoursAgo      = 168
	t3DefaultBHoursAgo = 24
	t3MaxGroups        = 50
	t3MaxAttempts      = 10
	t3MaxErrText       = 1000
)

// RequestTools 返回请求类只读工具。
func RequestTools() []Tool {
	return []Tool{t3GetRequest{}, t3SearchRequests{}, t3CompareWindows{}}
}

// ---------- 公共辅助 ----------

type t3Args struct {
	sql  string
	args []any
}

func (a *t3Args) add(v any) string {
	a.args = append(a.args, v)
	return fmt.Sprintf("$%d", len(a.args))
}

func t3CheckScope(scope Scope) error {
	if scope.TenantID == "" {
		return errors.New("缺少租户信息")
	}
	if !scope.IsAdmin && scope.UserID == "" {
		return errors.New("员工身份缺少用户信息")
	}
	return nil
}

func t3Window(h int) int {
	if h <= 0 {
		return t3DefaultWindowH
	}
	if h > t3MaxWindowH {
		return t3MaxWindowH
	}
	return h
}

func t3Clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func t3Marshal(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	return json.RawMessage(b), err
}

func t3Trunc(v any, n int) any {
	s, ok := v.(string)
	if !ok || utf8.RuneCountInString(s) <= n {
		return v
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

func t3Int(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int32:
		return int64(t)
	case int:
		return int64(t)
	case float64:
		return int64(t)
	}
	return 0
}

// t3Filter 是 search_requests / compare_windows 共用的过滤参数。
type t3Filter struct {
	User            string `json:"user"`
	KeyPrefix       string `json:"key_prefix"`
	Model           string `json:"model"`
	Provider        string `json:"provider"`
	StatusCode      int    `json:"status_code"`
	FailureCategory string `json:"failure_category"`
}

const t3FilterProps = `
    "user": {"type": "string", "description": "用户 ID 或用户名（仅管理员有效，员工会被忽略）"},
    "key_prefix": {"type": "string", "description": "API Key 前缀"},
    "model": {"type": "string", "description": "模型 ID 或模型名"},
    "provider": {"type": "string", "description": "渠道 ID 或渠道名"},
    "status_code": {"type": "integer", "description": "上游 HTTP 状态码，只筛选失败分组"},
    "failure_category": {"type": "string", "description": "失败类别，如 rate_limited、quota_exceeded、timeout、upstream_5xx、auth_failed、model_not_found"}`

// t3Resolve 把模型/渠道的名字转成 id 列表；原值也保留，兼容直接传 id。
func t3Resolve(ctx context.Context, q Querier, tenantID, kind, val string) ([]string, error) {
	val = strings.TrimSpace(val)
	if val == "" {
		return nil, nil
	}
	ids := []string{val}
	var sql string
	switch kind {
	case "model":
		sql = `SELECT m.id AS id FROM models m JOIN providers p ON p.id = m.provider_id
		       WHERE p.tenant_id = $1 AND (m.id = $2 OR m.model_name = $2) LIMIT 50`
	default:
		sql = `SELECT p.id AS id FROM providers p WHERE p.tenant_id = $1 AND (p.id = $2 OR p.name = $2) LIMIT 50`
	}
	rows, err := q.Query(ctx, sql, tenantID, val)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		if id, ok := r["id"].(string); ok && id != val {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// t3Base 构造基础 WHERE（租户、窗口、与 usageRecordFilterWhere 一致的排除、scope 与可选筛选）。
// 不含 status_code / failure_category：它们只作用于失败分组。
// lo/hi 为窗口起止距现在的小时数表达式参数名（已加入 a）。
func t3Base(a *t3Args, scope Scope, f t3Filter, modelIDs, providerIDs []string, loHours, hiHours string) string {
	var w strings.Builder
	w.WriteString("rl.tenant_id = " + a.add(scope.TenantID))
	w.WriteString(" AND rl.created_at >= now() - make_interval(hours => " + loHours + ")")
	w.WriteString(" AND rl.created_at < now() - make_interval(hours => " + hiHours + ")")
	w.WriteString(" AND COALESCE(rl.endpoint_type, '') <> 'proxy'")
	// 平台自建的请求日志（运行故障告警等）不算业务请求（2.9.22）。
	w.WriteString(" AND " + repository.ExcludeNonBusinessEndpointsSQL("rl"))
	w.WriteString(" AND COALESCE(rl.request_status, '') NOT IN ('received', 'in_progress')")
	if !scope.IsAdmin {
		w.WriteString(" AND rl.user_id = " + a.add(scope.UserID))
	} else if u := strings.TrimSpace(f.User); u != "" {
		p := a.add(u)
		t := a.add(scope.TenantID)
		w.WriteString(" AND (rl.user_id = " + p + " OR rl.user_id IN (SELECT id FROM users WHERE tenant_id = " + t + " AND username = " + p + "))")
	}
	if kp := strings.TrimSpace(f.KeyPrefix); kp != "" {
		w.WriteString(" AND rl.client_id IN (SELECT id FROM internal_keys WHERE tenant_id = " + a.add(scope.TenantID) + " AND key_prefix = " + a.add(kp) + ")")
	}
	if len(modelIDs) > 0 {
		w.WriteString(" AND rl.model_id = ANY(" + a.add(modelIDs) + "::text[])")
	}
	if len(providerIDs) > 0 {
		w.WriteString(" AND rl.provider_id = ANY(" + a.add(providerIDs) + "::text[])")
	}
	return w.String()
}

func t3FailureExtra(a *t3Args, f t3Filter) string {
	var w strings.Builder
	if f.StatusCode > 0 {
		w.WriteString(" AND rl.upstream_status_code = " + a.add(f.StatusCode))
	}
	if c := strings.TrimSpace(f.FailureCategory); c != "" {
		w.WriteString(" AND (" + repository.UsageFailureCategorySQL + ") = " + a.add(c))
	}
	return w.String()
}

// t3SummarySQL：窗口内总数与成功数（失败/阻断由总数减成功数得出）。
func t3SummarySQL(scope Scope, f t3Filter, modelIDs, providerIDs []string, lo, hi int) (string, []any) {
	a := &t3Args{}
	loP, hiP := a.add(lo), a.add(hi)
	where := t3Base(a, scope, f, modelIDs, providerIDs, loP, hiP)
	sql := `SELECT count(*)::bigint AS total,
       (count(*) FILTER (WHERE (` + repository.UsageRequestStatusSQL + `) = 'success'))::bigint AS success
FROM request_logs rl WHERE ` + where
	return sql, a.args
}

// t3GroupsSQL：失败/阻断按 (failure_category, upstream_status_code, provider_id, model_id) 分组。
func t3GroupsSQL(scope Scope, f t3Filter, modelIDs, providerIDs []string, lo, hi, limit int) (string, []any) {
	a := &t3Args{}
	loP, hiP := a.add(lo), a.add(hi)
	where := t3Base(a, scope, f, modelIDs, providerIDs, loP, hiP)
	where += " AND (" + repository.UsageRequestStatusSQL + ") <> 'success'" + t3FailureExtra(a, f)
	sql := `SELECT g.failure_category, g.upstream_status_code, g.provider_id, p.name AS provider_name,
       g.model_id, m.model_name, g.count, g.model_denied, g.affected_users, g.first_at, g.last_at, g.sample_request_ids
FROM (
  SELECT (` + repository.UsageFailureCategorySQL + `) AS failure_category,
         rl.upstream_status_code AS upstream_status_code,
         rl.provider_id AS provider_id,
         rl.model_id AS model_id,
         count(*)::bigint AS count,
         (count(*) FILTER (WHERE rl.request_status IN ('key_model_not_allowed', 'forbidden_model')))::bigint AS model_denied,
         count(DISTINCT rl.user_id)::bigint AS affected_users,
         min(rl.created_at) AS first_at,
         max(rl.created_at) AS last_at,
         (array_agg(rl.request_id ORDER BY rl.created_at DESC))[1:3] AS sample_request_ids
  FROM request_logs rl
  WHERE ` + where + `
  GROUP BY 1, 2, 3, 4
) g
LEFT JOIN providers p ON p.id = g.provider_id
LEFT JOIN models m ON m.id = g.model_id
ORDER BY g.count DESC, g.last_at DESC
LIMIT ` + fmt.Sprint(limit)
	return sql, a.args
}

func t3Rate(success, total int64) any {
	if total <= 0 {
		return nil
	}
	return math.Round(float64(success)/float64(total)*1000) / 10
}

func t3ParseFilter(args json.RawMessage, dst any) error {
	if len(args) == 0 || string(args) == "null" {
		return nil
	}
	if err := json.Unmarshal(args, dst); err != nil {
		return fmt.Errorf("参数格式错误: %w", err)
	}
	return nil
}

func t3ResolveAll(ctx context.Context, q Querier, scope Scope, f t3Filter) (models, providers []string, err error) {
	if models, err = t3Resolve(ctx, q, scope.TenantID, "model", f.Model); err != nil {
		return
	}
	providers, err = t3Resolve(ctx, q, scope.TenantID, "provider", f.Provider)
	return
}

// ---------- get_request ----------

type t3GetRequest struct{}

func (t3GetRequest) Name() string    { return "get_request" }
func (t3GetRequest) AdminOnly() bool { return false }
func (t3GetRequest) Description() string {
	return "按请求编号（req_ 开头，或正向代理的裸 UUID）查询单条请求的完整信息：时间、用户名、Key 前缀、模型、渠道名、请求状态、失败类别、上游状态码、上游错误提示/错误码/错误原文、重试尝试列表、耗时、治理动作、计费结果；代理类请求（endpoint_type=proxy）另给上游/交付结局（upstream_outcome、delivery_outcome）、代理模式、目标域名与智能体类型；网关拒绝类请求（gateway_rejected=true，未转发上游，返回给客户端的状态码在 client_status_code，upstream_status_code 为空）另给拒绝原因（reject_reason：key_allowlist=密钥模型白名单，user_grant=账号模型授权）、客户端原始模型名，以及所用密钥的名称、状态、模型白名单、拦截方式和是否绑定智能体。只查最近 7 天。查不到时返回 found=false。参数：request_id（必填）。"
}
func (t3GetRequest) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"request_id":{"type":"string","description":"请求编号"}},"required":["request_id"]}`)
}

func (t3GetRequest) Run(ctx context.Context, q Querier, scope Scope, args json.RawMessage) (json.RawMessage, error) {
	if err := t3CheckScope(scope); err != nil {
		return nil, err
	}
	var in struct {
		RequestID string `json:"request_id"`
	}
	if err := t3ParseFilter(args, &in); err != nil {
		return nil, err
	}
	in.RequestID = strings.TrimSpace(in.RequestID)
	if in.RequestID == "" {
		return nil, errors.New("request_id 不能为空")
	}
	a := &t3Args{}
	where := "rl.tenant_id = " + a.add(scope.TenantID) + " AND rl.request_id = " + a.add(in.RequestID) +
		" AND rl.created_at >= now() - interval '7 days'"
	if !scope.IsAdmin {
		where += " AND rl.user_id = " + a.add(scope.UserID)
	}
	sql := `SELECT rl.request_id, rl.created_at, rl.user_id, u.username, rl.client_id, k.key_prefix,
       rl.model_id, m.model_name, rl.original_model_id, rl.provider_id, p.name AS provider_name,
       rl.endpoint_type, rl.request_status,
       (` + repository.UsageRequestStatusSQL + `) AS status_class,
       (` + repository.UsageFailureCategorySQL + `) AS failure_category,
       rl.upstream_status_code,
       (` + repository.UsageErrorHintSQL + `) AS upstream_error_hint,
       (` + repository.UsageUpstreamErrorCodeSQL + `) AS upstream_error_code,
       (` + repository.UsageErrorMessageSQL + `) AS error_message,
       rl.routing_decision_json #> '{model_route_v2,attempts}' AS attempts,
       rl.latency_ms, rl.upstream_ttft_ms, rl.governor_action, rl.billing_outcome, rl.upstream_outcome,
       rl.delivery_outcome, rl.proxy_mode, rl.proxy_target_host, rl.agent_type,
       rl.routing_decision_json ->> 'reject_reason' AS reject_reason,
       rl.routing_decision_json ->> 'client_model' AS client_model,
       k.name AS key_name, k.status AS key_status, k.model_allowlist AS key_model_allowlist,
       k.model_enforcement AS key_model_enforcement,
       (COALESCE(k.agent_instance_id, '') <> '') AS key_agent_bound
FROM request_logs rl
LEFT JOIN internal_keys k ON k.id = rl.client_id
LEFT JOIN users u ON u.id = rl.user_id
LEFT JOIN providers p ON p.id = rl.provider_id
LEFT JOIN models m ON m.id = rl.model_id
WHERE ` + where + ` ORDER BY rl.created_at DESC LIMIT 1`
	rows, err := q.Query(ctx, sql, a.args...)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return t3Marshal(map[string]any{"found": false})
	}
	r := rows[0]
	r["error_message"] = t3Trunc(r["error_message"], t3MaxErrText)
	t3MarkGatewayRejected(r)
	if at, ok := r["attempts"].([]any); ok && len(at) > t3MaxAttempts {
		r["attempts"] = at[:t3MaxAttempts]
		r["attempts_truncated"] = true
	}
	return t3Marshal(map[string]any{"found": true, "request": r})
}

// t3MarkGatewayRejected：网关拒绝类请求（模型授权 / 密钥白名单）没有转发到上游，
// 但网关把返回给客户端的 403 也写进了 upstream_status_code。原样交给模型会被读成“上游返回 403”，
// 所以改放到 client_status_code，并标明 forwarded_to_upstream=false。
func t3MarkGatewayRejected(r map[string]any) {
	st, _ := r["request_status"].(string)
	rr, _ := r["reject_reason"].(string)
	if st != "forbidden_model" && st != "key_model_not_allowed" && rr != "key_allowlist" && rr != "user_grant" {
		return
	}
	r["gateway_rejected"] = true
	r["forwarded_to_upstream"] = false
	r["client_status_code"] = r["upstream_status_code"]
	r["upstream_status_code"] = nil
}

// ---------- search_requests ----------

type t3SearchRequests struct{}

func (t3SearchRequests) Name() string    { return "search_requests" }
func (t3SearchRequests) AdminOnly() bool { return false }
func (t3SearchRequests) Description() string {
	return "在时间窗口内汇总失败和被阻断的请求：先给出总请求数、成功数、成功率，再按（失败类别、上游状态码、渠道、模型）分组，每组含数量、受影响用户数、最早/最晚时间和最多 3 个示例请求编号。可按用户、Key 前缀、模型（ID 或名字）、渠道（ID 或名字）、上游状态码、失败类别筛选；总数与成功率不受状态码和失败类别筛选影响。window_hours 默认 1，最大 24。员工身份只能看到自己的请求。"
}
func (t3SearchRequests) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{` + t3FilterProps + `,
    "window_hours": {"type": "integer", "minimum": 1, "maximum": 24, "description": "统计最近多少小时，默认 1，最大 24"}}}`)
}

func (t3SearchRequests) Run(ctx context.Context, q Querier, scope Scope, args json.RawMessage) (json.RawMessage, error) {
	if err := t3CheckScope(scope); err != nil {
		return nil, err
	}
	var in struct {
		t3Filter
		WindowHours int `json:"window_hours"`
	}
	if err := t3ParseFilter(args, &in); err != nil {
		return nil, err
	}
	wh := t3Window(in.WindowHours)
	mIDs, pIDs, err := t3ResolveAll(ctx, q, scope, in.t3Filter)
	if err != nil {
		return nil, err
	}
	sumSQL, sumArgs := t3SummarySQL(scope, in.t3Filter, mIDs, pIDs, wh, 0)
	sumRows, err := q.Query(ctx, sumSQL, sumArgs...)
	if err != nil {
		return nil, err
	}
	var total, success int64
	if len(sumRows) == 1 {
		total, success = t3Int(sumRows[0]["total"]), t3Int(sumRows[0]["success"])
	}
	grpSQL, grpArgs := t3GroupsSQL(scope, in.t3Filter, mIDs, pIDs, wh, 0, t3MaxGroups)
	groups, err := q.Query(ctx, grpSQL, grpArgs...)
	if err != nil {
		return nil, err
	}
	if groups == nil {
		groups = []map[string]any{}
	}
	return t3Marshal(map[string]any{
		"window_hours":     wh,
		"total":            total,
		"success":          success,
		"success_rate_pct": t3Rate(success, total),
		"groups":           groups,
	})
}

// ---------- compare_windows ----------

type t3CompareWindows struct{}

func (t3CompareWindows) Name() string    { return "compare_windows" }
func (t3CompareWindows) AdminOnly() bool { return false }
func (t3CompareWindows) Description() string {
	return "对比两个时间窗口的成功率和错误分布，用来判断问题是从什么时候开始的。窗口 A 为 [现在-a_hours_ago-window_hours, 现在-a_hours_ago]，窗口 B 同理使用 b_hours_ago。a_hours_ago 默认 0（最近一段），b_hours_ago 默认 24（昨天同一时段），最大 168。筛选参数同 search_requests。window_hours 默认 1，最大 24。"
}
func (t3CompareWindows) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{` + t3FilterProps + `,
    "a_hours_ago": {"type": "integer", "minimum": 0, "maximum": 168, "description": "窗口 A 结束时间距现在的小时数，默认 0"},
    "b_hours_ago": {"type": "integer", "minimum": 0, "maximum": 168, "description": "窗口 B 结束时间距现在的小时数，默认 24"},
    "window_hours": {"type": "integer", "minimum": 1, "maximum": 24, "description": "每个窗口的长度（小时），默认 1，最大 24"}}}`)
}

func (t3CompareWindows) Run(ctx context.Context, q Querier, scope Scope, args json.RawMessage) (json.RawMessage, error) {
	if err := t3CheckScope(scope); err != nil {
		return nil, err
	}
	var in struct {
		t3Filter
		AHoursAgo   *int `json:"a_hours_ago"`
		BHoursAgo   *int `json:"b_hours_ago"`
		WindowHours int  `json:"window_hours"`
	}
	if err := t3ParseFilter(args, &in); err != nil {
		return nil, err
	}
	wh := t3Window(in.WindowHours)
	aAgo, bAgo := 0, t3DefaultBHoursAgo
	if in.AHoursAgo != nil {
		aAgo = t3Clamp(*in.AHoursAgo, 0, t3MaxHoursAgo)
	}
	if in.BHoursAgo != nil {
		bAgo = t3Clamp(*in.BHoursAgo, 0, t3MaxHoursAgo)
	}
	mIDs, pIDs, err := t3ResolveAll(ctx, q, scope, in.t3Filter)
	if err != nil {
		return nil, err
	}
	window := func(ago int) (map[string]any, error) {
		lo, hi := ago+wh, ago
		sumSQL, sumArgs := t3SummarySQL(scope, in.t3Filter, mIDs, pIDs, lo, hi)
		sumRows, err := q.Query(ctx, sumSQL, sumArgs...)
		if err != nil {
			return nil, err
		}
		var total, success int64
		if len(sumRows) == 1 {
			total, success = t3Int(sumRows[0]["total"]), t3Int(sumRows[0]["success"])
		}
		grpSQL, grpArgs := t3GroupsSQL(scope, in.t3Filter, mIDs, pIDs, lo, hi, 10)
		groups, err := q.Query(ctx, grpSQL, grpArgs...)
		if err != nil {
			return nil, err
		}
		if groups == nil {
			groups = []map[string]any{}
		}
		return map[string]any{
			"hours_ago_start": lo, "hours_ago_end": hi,
			"total": total, "success": success, "failed_or_blocked": total - success,
			"success_rate_pct": t3Rate(success, total),
			"errors":           groups,
		}, nil
	}
	wa, err := window(aAgo)
	if err != nil {
		return nil, err
	}
	wb, err := window(bAgo)
	if err != nil {
		return nil, err
	}
	return t3Marshal(map[string]any{"window_hours": wh, "a": wa, "b": wb})
}
