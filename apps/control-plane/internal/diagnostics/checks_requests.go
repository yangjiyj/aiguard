package diagnostics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 请求类检查共用一条聚合查询（当前窗口 + 前一个同长窗口），结果在 RunChecks 内缓存。

type t6Row struct {
	Win        int      `json:"-"` // 0=当前窗口 1=前一窗口
	Category   string   `json:"failure_category"`
	Code       int      `json:"upstream_status_code"`
	ProviderID string   `json:"provider_id"`
	Provider   string   `json:"provider_name"`
	ModelID    string   `json:"model_id"`
	Model      string   `json:"model_name"`
	Status     string   `json:"request_status"`
	Billing    string   `json:"billing_outcome"`
	Count      int64    `json:"count"`
	Users      int64    `json:"users"`
	Samples    []string `json:"sample_request_ids"`
	Hint       string   `json:"upstream_error_hint,omitempty"`
	ErrCode    string   `json:"upstream_error_code,omitempty"`
}

type t6Agg struct {
	WindowH   int
	Cur, Prev []t6Row
	CurTotal  int64
	PrevTotal int64
}

func t6Window(h int) int {
	if h <= 0 {
		return 1
	}
	if h > 24 {
		return 24
	}
	return h
}

// t6AggSQL 一次扫描 2×窗口，按 (窗口, 失败类别, 上游状态码, 渠道, 模型, 请求状态, 计费结果) 聚合。
// 失败分类 SQL 复用 repository.Usage*SQL；排除条件与 request 工具一致（proxy、received、in_progress）。
func t6AggSQL(s Scope, hours int) (string, []any) {
	args := []any{s.TenantID, hours, hours * 2}
	where := `rl.tenant_id = $1
  AND rl.created_at >= now() - make_interval(hours => $3)
  AND COALESCE(rl.endpoint_type, '') <> 'proxy'
  AND ` + repository.ExcludeNonBusinessEndpointsSQL("rl") + `
  AND COALESCE(rl.request_status, '') NOT IN ('received', 'in_progress')`
	if !s.IsAdmin {
		args = append(args, s.UserID)
		where += " AND rl.user_id = $4"
	}
	hint := "(" + repository.UsageErrorHintSQL + ")"
	code := "(" + repository.UsageUpstreamErrorCodeSQL + ")"
	// 性能（客户A量级 200 万行、24 小时窗口扫 2 倍窗口约 58 万行，原写法实测 5–6 秒）：
	// 约 92% 的行是“成功、状态码 <400、非 budget 计费”的正常行，后续检查只用它们的行数
	// （CurTotal、渠道总量），不读样例、用户数和 hint。所以拆成两个分支，各自走租户+时间索引：
	//   normal：只按窄列计数，不算失败分类，不读 JSONB；
	//   heavy ：失败/可疑行（约 8%），保留完整分类、样例、用户数和 hint/err_code。
	// 两个分支的并集与原查询逐组等价（normal 行的 failure_category 恒为空串）；谓词里的列都包了 COALESCE，
	// 保证 NOT(normalPred) 不会因 NULL 变成 NULL，任何一行都恰好落进一个分支。
	normalPred := `COALESCE(rl.request_status, '') IN ('success', 'security_replied')
    AND COALESCE(rl.upstream_status_code, 0) < 400
    AND COALESCE(rl.billing_outcome, '') NOT LIKE 'budget\_%'`
	sql := `/* t6:agg */
SELECT g.w, g.failure_category, g.upstream_status_code, g.provider_id, p.name AS provider_name,
       g.model_id, COALESCE(NULLIF(m.model_label, ''), m.model_name) AS model_name,
       g.request_status, g.billing_outcome, g.count, g.users, g.samples, g.hint, g.err_code
FROM (
  SELECT (CASE WHEN rl.created_at >= now() - make_interval(hours => $2) THEN 0 ELSE 1 END)::int AS w,
         (` + repository.UsageFailureCategorySQL + `) AS failure_category,
         COALESCE(rl.upstream_status_code, 0)::int AS upstream_status_code,
         COALESCE(rl.provider_id, '') AS provider_id,
         COALESCE(rl.model_id, '') AS model_id,
         COALESCE(rl.request_status, '') AS request_status,
         COALESCE(rl.billing_outcome, '') AS billing_outcome,
         count(*)::bigint AS count,
         count(DISTINCT rl.user_id)::bigint AS users,
         (array_agg(rl.request_id ORDER BY rl.created_at DESC))[1:3] AS samples,
         COALESCE(mode() WITHIN GROUP (ORDER BY ` + hint + `) FILTER (WHERE ` + hint + ` <> ''), '') AS hint,
         COALESCE(mode() WITHIN GROUP (ORDER BY ` + code + `) FILTER (WHERE ` + code + ` <> ''), '') AS err_code
  FROM request_logs rl
  WHERE ` + where + `
    AND NOT (` + normalPred + `)
  GROUP BY 1, 2, 3, 4, 5, 6, 7
  UNION ALL
  SELECT (CASE WHEN rl.created_at >= now() - make_interval(hours => $2) THEN 0 ELSE 1 END)::int,
         ''::text,
         COALESCE(rl.upstream_status_code, 0)::int,
         COALESCE(rl.provider_id, ''),
         COALESCE(rl.model_id, ''),
         COALESCE(rl.request_status, ''),
         COALESCE(rl.billing_outcome, ''),
         count(*)::bigint, 0::bigint, ARRAY[]::text[], ''::text, ''::text
  FROM request_logs rl
  WHERE ` + where + `
    AND ` + normalPred + `
  GROUP BY 1, 2, 3, 4, 5, 6, 7
) g
LEFT JOIN providers p ON p.id = g.provider_id
LEFT JOIN models m ON m.id = g.model_id
ORDER BY g.w, g.count DESC`
	return sql, args
}

func t6Str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func t6Int(v any) int64 {
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

func t6Samples(v any) []string {
	var out []string
	switch t := v.(type) {
	case []any:
		for _, x := range t {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
	case []string:
		out = append(out, t...)
	}
	return out
}

func t6LoadRequestAgg(ctx context.Context, q Querier, s Scope, in Input) (*t6Agg, error) {
	if s.TenantID == "" {
		return nil, fmt.Errorf("缺少租户信息")
	}
	if !s.IsAdmin && s.UserID == "" {
		return nil, fmt.Errorf("员工身份缺少用户信息")
	}
	h := t6Window(in.WindowH)
	sql, args := t6AggSQL(s, h)
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	agg := &t6Agg{WindowH: h}
	for _, m := range rows {
		r := t6Row{
			Win: int(t6Int(m["w"])), Category: t6Str(m["failure_category"]), Code: int(t6Int(m["upstream_status_code"])),
			ProviderID: t6Str(m["provider_id"]), Provider: t6Str(m["provider_name"]),
			ModelID: t6Str(m["model_id"]), Model: t6Str(m["model_name"]),
			Status: t6Str(m["request_status"]), Billing: t6Str(m["billing_outcome"]),
			Count: t6Int(m["count"]), Users: t6Int(m["users"]), Samples: t6Samples(m["samples"]),
			Hint: t6Str(m["hint"]), ErrCode: t6Str(m["err_code"]),
		}
		if r.Win == 0 {
			agg.Cur = append(agg.Cur, r)
			agg.CurTotal += r.Count
		} else {
			agg.Prev = append(agg.Prev, r)
			agg.PrevTotal += r.Count
		}
	}
	return agg, nil
}

// t6AggOutput 是聚合步骤的 Step.Output：总数与失败分组（限量），完整样例见各检查自己的输出。
func t6AggOutput(a *t6Agg) json.RawMessage {
	var fails []t6Row
	prevBy := map[string]int64{}
	for _, r := range a.Cur {
		if r.Category != "" && len(fails) < 40 {
			fails = append(fails, r)
		}
	}
	for _, r := range a.Prev {
		if r.Category != "" {
			prevBy[r.Category] += r.Count
		}
	}
	return t6JSON(map[string]any{
		"window_hours": a.WindowH, "cur_total": a.CurTotal, "prev_total": a.PrevTotal,
		"cur_failed_groups": fails, "prev_failed_by_category": prevBy,
	})
}

// ---------- 辅助 ----------

func (a *t6Agg) cur(pred func(r t6Row) bool) []t6Row {
	var out []t6Row
	for _, r := range a.Cur {
		if pred(r) {
			out = append(out, r)
		}
	}
	return out
}

func (a *t6Agg) providerTotals() map[string]int64 {
	m := map[string]int64{}
	for _, r := range a.Cur {
		m[r.ProviderID] += r.Count
	}
	return m
}

func t6Sum(rows []t6Row) int64 {
	var n int64
	for _, r := range rows {
		n += r.Count
	}
	return n
}

// t6Ids 取示例请求编号（按分组数量从大到小），去重，最多 n 个。
func t6Ids(rows []t6Row, n int) []string {
	rs := append([]t6Row(nil), rows...)
	sort.SliceStable(rs, func(i, j int) bool { return rs[i].Count > rs[j].Count })
	seen := map[string]bool{}
	var out []string
	for _, r := range rs {
		for _, id := range r.Samples {
			if !seen[id] && len(out) < n {
				seen[id] = true
				out = append(out, id)
			}
		}
	}
	return out
}

func t6PName(r t6Row) string {
	if r.Provider != "" {
		return r.Provider
	}
	return "未识别渠道"
}

func t6MName(r t6Row) string {
	if r.Model != "" {
		return r.Model
	}
	return "未识别模型"
}

type t6PG struct {
	ID, Name string
	Rows     []t6Row
	Count    int64
}

func t6ByProvider(rows []t6Row) []t6PG {
	idx := map[string]int{}
	var out []t6PG
	for _, r := range rows {
		i, ok := idx[r.ProviderID]
		if !ok {
			i = len(out)
			idx[r.ProviderID] = i
			out = append(out, t6PG{ID: r.ProviderID, Name: t6PName(r)})
		}
		out[i].Rows = append(out[i].Rows, r)
		out[i].Count += r.Count
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func t6ModelNames(rows []t6Row) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range rows {
		n := t6MName(r)
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// t6Quote 把名字写成「a」「b」，最多 3 个。
func t6Quote(names []string) string {
	if len(names) > 3 {
		names = names[:3]
	}
	var sb strings.Builder
	for _, n := range names {
		sb.WriteString("「" + n + "」")
	}
	return sb.String()
}

func t6ModelLink(rows []t6Row) string {
	for _, r := range rows {
		if r.Model != "" {
			return "/model-operations?model=" + url.QueryEscape(r.Model)
		}
	}
	return "/model-operations"
}

func t6RawOf(r t6Row) string {
	switch {
	case r.Hint != "" && r.ErrCode != "":
		return r.Hint + " (code=" + r.ErrCode + ")"
	case r.Hint != "":
		return r.Hint
	}
	return r.ErrCode
}

// 网关自己拒绝的请求状态：不属于上游返回。
func t6IsGateway(r t6Row) bool {
	return r.Status == "rate_limited" || r.Status == "quota_exceeded" || strings.HasPrefix(r.Billing, "budget_") || t6IsModelDenied(r)
}

// 网关的模型授权拒绝（密钥白名单 key_model_not_allowed / 账号授权 forbidden_model）：HTTP 403 但没有转发到上游，
// 不能算成“上游鉴权失败”。
func t6IsModelDenied(r t6Row) bool {
	return r.Status == "key_model_not_allowed" || r.Status == "forbidden_model"
}

func t6Result1(fs []Finding, data any) (t6Result, error) {
	return t6Result{Findings: fs, Data: data}, nil
}

// ---------- 检查项 ----------

func t6CheckGwRateLimited(ctx context.Context, e *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	a, err := e.load(ctx, q, s, in)
	if err != nil {
		return t6Result{}, err
	}
	rows := a.cur(func(r t6Row) bool { return r.Status == "rate_limited" })
	n := t6Sum(rows)
	data := map[string]any{"window_hours": a.WindowH, "count": n, "rows": rows}
	if n == 0 {
		return t6Result1(nil, data)
	}
	ids := t6Ids(rows, 3)
	adv := []Advice{t6Adv(s, "在额度策略中调高每分钟请求上限，或请调用方降低并发", "/cost/budgets")}
	return t6Result1([]Finding{t6Find("gw_rate_limited", SevWarn, LevelConfirmed,
		"请求被网关限流拒绝（每分钟请求数限制或代理限流）",
		fmt.Sprintf("近 %d 小时有 %d 条请求被网关限流，这些请求没有到达上游", a.WindowH, n),
		adv, []string{"已排除上游问题：请求状态为网关限流，未转发到上游"},
		t6ReqEvidence(ids, "被网关限流拒绝", ""))}, data)
}

var t6BillingReason = map[string]string{
	"budget_exhausted":   "预算已用尽",
	"budget_unpriced":    "模型未定价",
	"budget_unavailable": "额度状态无法确认",
	"quota_exceeded":     "超出额度限制",
}

func t6CheckGwQuota(ctx context.Context, e *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	a, err := e.load(ctx, q, s, in)
	if err != nil {
		return t6Result{}, err
	}
	rows := a.cur(func(r t6Row) bool { return r.Status == "quota_exceeded" || strings.HasPrefix(r.Billing, "budget_") })
	n := t6Sum(rows)
	by := map[string]int64{}
	for _, r := range rows {
		k := r.Billing
		if !strings.HasPrefix(k, "budget_") {
			k = "quota_exceeded"
		}
		by[k] += r.Count
	}
	data := map[string]any{"window_hours": a.WindowH, "count": n, "by_reason": by, "rows": rows}
	if n == 0 {
		return t6Result1(nil, data)
	}
	var reasons []string
	keys := make([]string, 0, len(by))
	for k := range by {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		name := t6BillingReason[k]
		if name == "" {
			name = "预算限制"
		}
		reasons = append(reasons, fmt.Sprintf("%s %d 条", name, by[k]))
	}
	ev := t6ReqEvidence(t6Ids(rows, 3), "被额度或预算策略拦截", "")
	// 管理员补充命中的策略（尽力而为，失败不影响结论）。
	if s.IsAdmin {
		pol, perr := q.Query(ctx, `/* t6:quota_policies */
SELECT id, scope_type, scope_ref, user_id, key_prefix, daily_token_blocked, monthly_token_blocked, rpm_blocked,
       daily_budget_blocked, monthly_budget_blocked
FROM quota_policies
WHERE tenant_id = $1 AND status = 'active'
  AND (daily_token_blocked OR monthly_token_blocked OR rpm_blocked OR daily_budget_blocked OR monthly_budget_blocked)
LIMIT 10`, s.TenantID)
		if perr == nil {
			data["blocked_policies"] = pol
			for _, p := range pol {
				ev = append(ev, Evidence{Kind: "config", Ref: t6Str(p["id"]), Summary: "该额度策略已触发硬拦截"})
			}
		}
	}
	return t6Result1([]Finding{t6Find("gw_quota", SevError, LevelConfirmed,
		"请求被网关额度或预算策略拦截",
		fmt.Sprintf("近 %d 小时有 %d 条请求被拦截：%s", a.WindowH, n, strings.Join(reasons, "，")),
		[]Advice{t6Adv(s, "在预算与额度页核对命中的策略，必要时调整限额", "/cost/budgets"),
			t6Adv(s, "在调用明细中查看被拦截的请求", t6RecordsLink(firstOr(t6Ids(rows, 1), "")))},
		[]string{"已排除上游问题：请求在网关侧被拒绝，未转发到上游"}, ev)}, data)
}

func firstOr(xs []string, d string) string {
	if len(xs) > 0 {
		return xs[0]
	}
	return d
}

func t6HasQuotaText(r t6Row) bool {
	t := strings.ToLower(r.Hint + " " + r.ErrCode)
	return strings.Contains(t, "insufficient_quota")
}

// up_429 同时产出 up_billing（疑似欠费）。
func t6CheckUp429(ctx context.Context, e *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	a, err := e.load(ctx, q, s, in)
	if err != nil {
		return t6Result{}, err
	}
	pt := a.providerTotals()
	rows := a.cur(func(r t6Row) bool { return (r.Code == 429 || r.Code == 402) && !t6IsGateway(r) })
	var fs []Finding
	var items []map[string]any
	for _, g := range t6ByProvider(rows) {
		var n429, n402 int64
		quota := false
		for _, r := range g.Rows {
			if r.Code == 429 {
				n429 += r.Count
			} else {
				n402 += r.Count
			}
			if t6HasQuotaText(r) {
				quota = true
			}
		}
		total := pt[g.ID]
		pct := t6Pct(n429, total)
		items = append(items, map[string]any{"provider_name": g.Name, "count_429": n429, "count_402": n402, "total": total, "pct_429": pct,
			"count_bad": n429 + n402, "pct_bad": t6Pct(n429+n402, total), "rows": g.Rows})
		ids := t6Ids(g.Rows, 3)
		raw := ""
		for _, r := range g.Rows {
			if raw = t6RawOf(r); raw != "" {
				break
			}
		}
		if n429 > 0 {
			fs = append(fs, t6Find("up_429", SevWarn, LevelConfirmed,
				fmt.Sprintf("渠道「%s」被上游限流（429）", g.Name),
				fmt.Sprintf("近 %d 小时该渠道 %d 条请求中有 %d 条被上游限流，占 %d%%", a.WindowH, total, n429, pct),
				[]Advice{t6Adv(s, "降低该渠道的并发，或为相关模型配置备用渠道", t6ModelLink(g.Rows)),
					t6Adv(s, "在调用明细中查看示例请求", t6RecordsLink(firstOr(ids, "")))},
				[]string{"已排除网关限流：这些请求的限流来自上游返回的 429，不是网关拒绝"},
				t6ReqEvidence(ids, "上游返回 429", raw)))
		}
		if (n429 > 0 && n429*100 >= 80*total) || n402 > 0 || quota {
			fs = append(fs, t6Find("up_billing", SevError, LevelSuspected,
				fmt.Sprintf("渠道「%s」疑似欠费或额度耗尽", g.Name),
				fmt.Sprintf("近 %d 小时该渠道 %d 条请求中有 %d 条返回限流或欠费类错误，占 %d%%", a.WindowH, total, n429+n402, t6Pct(n429+n402, total)),
				[]Advice{t6Adv(s, "登录上游平台核对账户余额与额度，必要时充值", "/providers")},
				[]string{"未能从网关侧直接确认余额，需到上游平台核实"},
				t6ReqEvidence(ids, "上游返回限流或欠费类错误", raw)))
		}
	}
	return t6Result1(fs, map[string]any{"window_hours": a.WindowH, "items": items})
}

func t6CheckUp5xx(ctx context.Context, e *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	a, err := e.load(ctx, q, s, in)
	if err != nil {
		return t6Result{}, err
	}
	pt := a.providerTotals()
	rows := a.cur(func(r t6Row) bool { return r.Code >= 500 && r.Code < 600 && !t6IsGateway(r) })
	var fs []Finding
	var items []map[string]any
	for _, g := range t6ByProvider(rows) {
		total := pt[g.ID]
		pct := t6Pct(g.Count, total)
		items = append(items, map[string]any{"provider_name": g.Name, "count": g.Count, "total": total, "pct": pct, "rows": g.Rows})
		if g.Count < 5 || g.Count*100 <= 20*total {
			continue
		}
		ids := t6Ids(g.Rows, 3)
		raw := ""
		for _, r := range g.Rows {
			if raw = t6RawOf(r); raw != "" {
				break
			}
		}
		fs = append(fs, t6Find("up_5xx", SevError, LevelConfirmed,
			fmt.Sprintf("渠道「%s」的上游服务异常（5xx）", g.Name),
			fmt.Sprintf("近 %d 小时该渠道 %d 条请求中有 %d 条返回服务端错误，占 %d%%", a.WindowH, total, g.Count, pct),
			[]Advice{t6Adv(s, "联系上游服务商确认故障，并为相关模型配置备用渠道", t6ModelLink(g.Rows)),
				t6Adv(s, "在调用明细中查看示例请求", t6RecordsLink(firstOr(ids, "")))},
			[]string{"已排除网关限流与额度：这些请求的错误由上游返回"},
			t6ReqEvidence(ids, "上游返回服务端错误", raw)))
	}
	return t6Result1(fs, map[string]any{"window_hours": a.WindowH, "items": items})
}

var t6ParamRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(?:unsupported|unknown|unrecognized|invalid)\s+(?:request\s+)?param(?:eter)?s?:?\s*['"` + "`" + `]?([A-Za-z_][\w.\[\]]*)`),
	regexp.MustCompile(`(?i)param(?:eter)?\s*['"` + "`" + `]([A-Za-z_][\w.\[\]]*)['"` + "`" + `]`),
	regexp.MustCompile(`\b(max_completion_tokens|max_tokens|temperature|top_p|top_k|stream_options|response_format|tool_choice|tools|reasoning_effort)\b`),
}

// t6ParamName 从上游原文里提取被拒绝的参数名。
func t6ParamName(hint string) string {
	for _, re := range t6ParamRes {
		if m := re.FindStringSubmatch(hint); len(m) > 1 {
			return m[1]
		}
	}
	return ""
}

func t6CheckUpParam(ctx context.Context, e *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	a, err := e.load(ctx, q, s, in)
	if err != nil {
		return t6Result{}, err
	}
	rows := a.cur(func(r t6Row) bool { return (r.Code == 400 || r.Code == 422) && r.Hint != "" && !t6IsGateway(r) })
	type key struct{ p, h string }
	idx := map[key]int{}
	var groups []t6PG
	var hints []string
	for _, r := range rows {
		k := key{r.ProviderID, r.Hint}
		i, ok := idx[k]
		if !ok {
			i = len(groups)
			idx[k] = i
			groups = append(groups, t6PG{ID: r.ProviderID, Name: t6PName(r)})
			hints = append(hints, r.Hint)
		}
		groups[i].Rows = append(groups[i].Rows, r)
		groups[i].Count += r.Count
	}
	var fs []Finding
	var items []map[string]any
	for i, g := range groups {
		ids := t6Ids(g.Rows, 3)
		param := t6ParamName(hints[i])
		title := fmt.Sprintf("渠道「%s」的上游拒绝了请求参数", g.Name)
		if param != "" {
			title = fmt.Sprintf("渠道「%s」的上游拒绝了参数「%s」", g.Name, param)
		}
		adv := []Advice{t6Adv(s, "核对该模型在此渠道上的参数设置，或改用其他渠道", t6ModelLink(g.Rows)),
			t6Adv(s, "在调用明细中查看上游原文", t6RecordsLink(firstOr(ids, "")))}
		if g.Count >= 3 {
			adv = append(adv, Advice{Text: "可能是网关转发与该上游不兼容，请导出诊断包联系厂商"})
		}
		code := g.Rows[0].Code
		items = append(items, map[string]any{"provider_name": g.Name, "count": g.Count, "status_code": code, "param": param, "rows": g.Rows})
		fs = append(fs, t6Find("up_param", SevError, LevelConfirmed, title,
			fmt.Sprintf("近 %d 小时有 %d 条请求被上游以 %d 拒绝，涉及模型%s，请求参数与该上游不兼容", a.WindowH, g.Count, code, t6Quote(t6ModelNames(g.Rows))),
			adv, []string{"已排除网关限流与额度：这些请求由上游返回参数错误"},
			t6ReqEvidence(ids, "上游拒绝了请求参数", hints[i])))
	}
	return t6Result1(fs, map[string]any{"window_hours": a.WindowH, "items": items})
}

func t6CheckTimeout(ctx context.Context, e *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	a, err := e.load(ctx, q, s, in)
	if err != nil {
		return t6Result{}, err
	}
	pt := a.providerTotals()
	rows := a.cur(func(r t6Row) bool { return r.Category == "timeout" })
	var fs []Finding
	var items []map[string]any
	for _, g := range t6ByProvider(rows) {
		ids := t6Ids(g.Rows, 3)
		total := pt[g.ID]
		items = append(items, map[string]any{"provider_name": g.Name, "count": g.Count, "total": total, "rows": g.Rows})
		fs = append(fs, t6Find("timeout", SevWarn, LevelConfirmed,
			fmt.Sprintf("渠道「%s」的请求超时", g.Name),
			fmt.Sprintf("近 %d 小时该渠道 %d 条请求中有 %d 条超时", a.WindowH, total, g.Count),
			[]Advice{t6Adv(s, "检查上游响应速度与网络，必要时为相关模型配置备用渠道", t6ModelLink(g.Rows)),
				t6Adv(s, "在调用明细中查看示例请求", t6RecordsLink(firstOr(ids, "")))},
			nil, t6ReqEvidence(ids, "请求超时", "")))
	}
	return t6Result1(fs, map[string]any{"window_hours": a.WindowH, "items": items})
}

func t6CheckAuthFailed(ctx context.Context, e *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	a, err := e.load(ctx, q, s, in)
	if err != nil {
		return t6Result{}, err
	}
	rows := a.cur(func(r t6Row) bool {
		return (r.Code == 401 || r.Code == 403) && !t6IsGateway(r) && r.Category != "security_rejected"
	})
	var fs []Finding
	var items []map[string]any
	for _, g := range t6ByProvider(rows) {
		ids := t6Ids(g.Rows, 3)
		raw := ""
		for _, r := range g.Rows {
			if raw = t6RawOf(r); raw != "" {
				break
			}
		}
		items = append(items, map[string]any{"provider_name": g.Name, "count": g.Count, "status_code": g.Rows[0].Code, "rows": g.Rows})
		fs = append(fs, t6Find("auth_failed", SevError, LevelConfirmed,
			fmt.Sprintf("渠道「%s」的上游鉴权失败，凭据可能已失效", g.Name),
			fmt.Sprintf("近 %d 小时有 %d 条请求被上游以 %d 拒绝，涉及模型%s", a.WindowH, g.Count, g.Rows[0].Code, t6Quote(t6ModelNames(g.Rows))),
			[]Advice{t6Adv(s, "在渠道管理中更新该渠道的凭据并测试连通", "/providers")},
			[]string{"已排除网关限流与额度：鉴权错误由上游返回"},
			t6ReqEvidence(ids, "上游鉴权失败", raw)))
	}
	return t6Result1(fs, map[string]any{"window_hours": a.WindowH, "items": items})
}

func t6CheckModelMissing(ctx context.Context, e *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	a, err := e.load(ctx, q, s, in)
	if err != nil {
		return t6Result{}, err
	}
	rows := a.cur(func(r t6Row) bool { return r.Status == "model_not_configured" || r.Status == "model_not_found" })
	n := t6Sum(rows)
	data := map[string]any{"window_hours": a.WindowH, "count": n, "rows": rows}
	if n == 0 {
		return t6Result1(nil, data)
	}
	ids := t6Ids(rows, 3)
	var known []string
	for _, nm := range t6ModelNames(rows) {
		if nm != "未识别模型" {
			known = append(known, nm)
		}
	}
	title := "有请求使用了未配置或不存在的模型"
	if len(known) > 0 {
		title = "模型" + t6Quote(known) + "未配置或不存在"
	}
	return t6Result1([]Finding{t6Find("model_missing", SevError, LevelConfirmed, title,
		fmt.Sprintf("近 %d 小时有 %d 条请求因模型未配置或不存在被拒绝", a.WindowH, n),
		[]Advice{t6Adv(s, "在模型管理中确认该模型已配置并启用，或让调用方改用已有模型", "/models"),
			t6Adv(s, "在调用明细中查看示例请求", t6RecordsLink(firstOr(ids, "")))},
		[]string{"已排除上游问题：请求在网关侧找不到可用模型，未转发到上游"},
		t6ReqEvidence(ids, "模型未配置或不存在", ""))}, data)
}

func t6CheckSecurityBlock(ctx context.Context, e *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	a, err := e.load(ctx, q, s, in)
	if err != nil {
		return t6Result{}, err
	}
	rows := a.cur(func(r t6Row) bool { return r.Category == "security_rejected" })
	cur := t6Sum(rows)
	var prev int64
	for _, r := range a.Prev {
		if r.Category == "security_rejected" {
			prev += r.Count
		}
	}
	data := map[string]any{"window_hours": a.WindowH, "count": cur, "prev_count": prev, "rows": rows}
	// 突增：较前一窗口 ×3；至少 3 条才报，避免个别拦截造成噪声。
	if cur < 3 || cur < 3*prev {
		return t6Result1(nil, data)
	}
	ids := t6Ids(rows, 3)
	return t6Result1([]Finding{t6Find("security_block", SevWarn, LevelSuspected,
		"安全拦截数量突增，可能存在误拦",
		fmt.Sprintf("近 %d 小时被安全策略拦截 %d 条，前一时段为 %d 条", a.WindowH, cur, prev),
		[]Advice{t6Adv(s, "到告警页核对被拦截的内容，确认是否为误拦，必要时调整策略", "/security/alerts"),
			t6Adv(s, "在调用明细中查看示例请求", t6RecordsLink(firstOr(ids, "")))},
		[]string{"已排除上游问题：这些请求由安全策略在网关侧拦截"},
		t6ReqEvidence(ids, "被安全策略拦截", ""))}, data)
}

func t6CheckStreamAbort(ctx context.Context, e *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	a, err := e.load(ctx, q, s, in)
	if err != nil {
		return t6Result{}, err
	}
	rows := a.cur(func(r t6Row) bool { return r.Category == "stream_aborted" })
	n := t6Sum(rows)
	pct := t6Pct(n, a.CurTotal)
	data := map[string]any{"window_hours": a.WindowH, "count": n, "total": a.CurTotal, "pct": pct, "rows": rows}
	if n < 3 || n*100 <= 10*a.CurTotal {
		return t6Result1(nil, data)
	}
	ids := t6Ids(rows, 3)
	return t6Result1([]Finding{t6Find("stream_abort", SevWarn, LevelSuspected,
		"流式响应中断比例偏高",
		fmt.Sprintf("近 %d 小时 %d 条请求中有 %d 条流式响应中途中断，占 %d%%", a.WindowH, a.CurTotal, n, pct),
		[]Advice{t6Adv(s, "检查客户端与网关之间的代理超时设置，以及上游的稳定性", "/system/service-health"),
			t6Adv(s, "在调用明细中查看示例请求", t6RecordsLink(firstOr(ids, "")))},
		nil, t6ReqEvidence(ids, "流式响应中断", ""))}, data)
}

// t6CheckKeyModelDenied 汇总窗口内被密钥模型白名单拒绝的请求（按密钥、模型分组）。
// 网关在 rejectModelDenied 等处会先写 request_logs（状态 key_model_not_allowed，
// routing_decision_json.reject_reason=key_allowlist），所以这是确定的结论，不是推测。
func t6CheckKeyModelDenied(ctx context.Context, _ *t6Env, q Querier, s Scope, in Input, _ *HostView) (t6Result, error) {
	h := t6Window(in.WindowH)
	args := []any{s.TenantID, h}
	where := `rl.tenant_id = $1 AND rl.created_at >= now() - make_interval(hours => $2)
  AND (rl.routing_decision_json ->> 'reject_reason' = 'key_allowlist' OR rl.request_status = 'key_model_not_allowed')`
	if !s.IsAdmin {
		args = append(args, s.UserID)
		where += " AND rl.user_id = $3"
	}
	rows, err := q.Query(ctx, `/* t6:key_model_denied */
SELECT COALESCE(rl.client_id, '') AS key_id, COALESCE(k.key_prefix, '') AS key_prefix, COALESCE(k.name, '') AS key_name,
       COALESCE(rl.routing_decision_json ->> 'client_model', '') AS model_name,
       count(*)::bigint AS count, (array_agg(rl.request_id ORDER BY rl.created_at DESC))[1:3] AS samples
FROM request_logs rl LEFT JOIN internal_keys k ON k.id = rl.client_id
WHERE `+where+`
GROUP BY 1, 2, 3, 4 ORDER BY count DESC LIMIT 20`, args...)
	if err != nil {
		return t6Result{}, err
	}
	var fs []Finding
	for _, r := range rows {
		ids := t6Samples(r["samples"])
		who := "这把密钥"
		if p, n := t6Str(r["key_prefix"]), t6Str(r["key_name"]); p != "" && n != "" {
			who = fmt.Sprintf("这把密钥（前缀 %s、名称 %s）", p, n)
		} else if p != "" {
			who = fmt.Sprintf("这把密钥（前缀 %s）", p)
		}
		model := "该模型"
		if m := t6Str(r["model_name"]); m != "" {
			model = "模型 " + m
		}
		link := "/keys"
		if id := t6Str(r["key_id"]); id != "" {
			link = "/keys?key_id=" + url.QueryEscape(id)
		}
		fs = append(fs, t6Find("key_model_allowlist", SevError, LevelConfirmed,
			fmt.Sprintf("%s的模型白名单不含%s，网关拒绝了对它的请求", who, model),
			fmt.Sprintf("近 %d 小时有 %d 条请求因此被拒绝，没有转发到上游", h, t6Int(r["count"])),
			append([]Advice{t6Adv(s, "在密钥管理中把该模型加入这把密钥的白名单，或改用其他密钥", link)}, t6RecordsAdvice(ids)...),
			[]string{"已排除上游问题：这些请求在网关侧被拒绝，没有转发到上游"},
			t6ReqEvidence(ids, "被密钥模型白名单拒绝", "")))
	}
	return t6Result{Findings: fs, Data: map[string]any{"window_hours": h, "items": rows}}, nil
}
