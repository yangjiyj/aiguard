package diagnostics

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// L2 固定排查树：按输入类型（请求 / 用户 / 模型 / 渠道 / 体检）执行预设的工具调用顺序，
// 结论全部用中文模板生成，数字与编号只取自工具输出，最后经 FactCheck 校验。
// 所有工具都经 Registry.Call 调用，权限、脱敏、截断统一生效。

const (
	t7NotFoundTitle   = "未找到该请求（可能不属于你，或超过 7 天）"
	t7CorrelationMin  = 3
	t7CorrelationSpan = 30 * time.Minute
	t7MaxGroupFinding = 5
)

// ---------- 小工具 ----------

func t7Str(v any) string { s, _ := v.(string); return s }

func t7Num(v any) int64 {
	if f, ok := v.(float64); ok {
		return int64(f)
	}
	return 0
}

func t7Map(v any) map[string]any { m, _ := v.(map[string]any); return m }
func t7List(v any) []any         { l, _ := v.([]any); return l }
func t7Bool(v any) bool          { b, _ := v.(bool); return b }

func t7HasCJK(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

func t7Cut(s string, n int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func t7NewID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "diag_" + hex.EncodeToString(b)
}

// t7When 把工具输出里的 RFC3339 时间格式化成“月-日 时:分”，保持原时区，数字与原文一致。
func t7When(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.Format("01-02 15:04")
}

func t7Adv(s Scope, text, link string) Advice {
	if !s.IsAdmin {
		return Advice{Text: "请联系管理员处理：" + text}
	}
	return Advice{Text: text, Link: link}
}

func t7RecordsLink(id string) string {
	if id == "" {
		return "/cost/records"
	}
	return "/cost/records?request_id=" + id
}

func t7ModelLink(model string) string {
	if model == "" {
		return "/model-operations"
	}
	return "/model-operations?model=" + strings.ReplaceAll(model, " ", "%20")
}

func t7Find(id string, sev Severity, lv Level, title, impact string, adv []Advice, excl []string, ev []Evidence) Finding {
	if adv == nil {
		adv = []Advice{}
	}
	if excl == nil {
		excl = []string{}
	}
	if ev == nil {
		ev = []Evidence{}
	}
	return Finding{CheckID: id, Severity: sev, Level: lv, Title: title, Impact: impact, Advice: adv, Excluded: excl, Evidence: ev}
}

// t7StepSummary 给每次工具调用生成面向客户的中文进度文案。
func t7StepSummary(tool string, _ json.RawMessage) string {
	switch tool {
	case "get_request":
		return "正在查这条请求的完整链路"
	case "search_requests":
		return "正在统计同类请求的分布"
	case "compare_windows":
		return "正在对比近期与 24 小时前的错误情况"
	case "change_timeline":
		return "正在查看故障出现前后的升级与配置变更"
	case "get_provider":
		return "正在检查渠道状态与凭据"
	case "get_model_routes":
		return "正在检查模型路由与可用渠道"
	case "get_user_access":
		return "正在核对账号的模型授权"
	case "get_quota_policies":
		return "正在检查限流与额度策略"
	case "get_license":
		return "正在检查授权状态"
	case "host_container_logs":
		return "正在查看网关容器日志"
	case "host_snapshot":
		return "正在读取宿主机快照"
	case "host_drift":
		return "正在比对配置漂移"
	}
	return "正在调用工具 " + tool
}

// ---------- 执行上下文 ----------

type t7Run struct {
	ctx   context.Context
	q     Querier
	reg   *Registry
	s     Scope
	steps []Step
}

type t7Res struct {
	m   map[string]any
	err string
}

func (x t7Res) ok() bool { return x.err == "" && x.m != nil }

func (r *t7Run) call(name string, args map[string]any) t7Res {
	raw, _ := json.Marshal(args)
	st := r.reg.Call(r.ctx, r.q, r.s, name, raw)
	st.Summary = t7StepSummary(name, raw)
	r.steps = append(r.steps, st)
	if st.Err != "" {
		return t7Res{err: st.Err}
	}
	var m map[string]any
	if err := json.Unmarshal(st.Output, &m); err != nil {
		return t7Res{err: "工具输出不是 JSON 对象"}
	}
	return t7Res{m: m}
}

// t7Args 构造工具参数，跳过空串与零值。
func t7Args(kv ...any) map[string]any {
	m := map[string]any{}
	for i := 0; i+1 < len(kv); i += 2 {
		k := kv[i].(string)
		switch v := kv[i+1].(type) {
		case string:
			if v != "" {
				m[k] = v
			}
		case int64:
			if v != 0 {
				m[k] = v
			}
		case int:
			m[k] = v
		default:
			m[k] = v
		}
	}
	return m
}

// ---------- 入口 ----------

// RunTree 执行 L2 固定排查树。FactCheck 失败时同时返回报告与错误（说明排查树本身有 bug）。
func RunTree(ctx context.Context, q Querier, reg *Registry, s Scope, in Input, host *HostView) (*Report, error) {
	rep := &Report{ID: t7NewID(), Tier: TierL2, StartedAt: time.Now()}
	r := &t7Run{ctx: ctx, q: q, reg: reg, s: s}
	kind := in.Kind
	if kind == "" {
		if reqIDRe.MatchString(in.Text) || reqIDRe.MatchString(in.Ref) {
			kind = "request"
		} else {
			kind = "question"
		}
	}
	switch kind {
	case "request":
		rep.Findings = r.requestTree(in)
	case "user":
		rep.Findings = r.userTree(in)
	case "model", "provider":
		rep.Findings = r.modelTree(in, kind)
	default: // health / question
		if kind == "question" {
			rep.Degraded = "当前未启用智能排查，已改为全局体检"
		}
		findings, ok, steps := RunChecks(ctx, q, s, in, host)
		rep.Findings, rep.OKCount = findings, ok
		r.steps = append(r.steps, steps...)
	}
	if rep.Findings == nil {
		rep.Findings = []Finding{}
	}
	rep.Steps = r.steps
	rep.FinishedAt = time.Now()
	if err := FactCheck(rep); err != nil {
		return rep, err
	}
	return rep, nil
}

// ---------- 请求树 ----------

type t7Req struct {
	ID, Status, Class, Cat, Hint, UpCodeStr, ErrMsg string
	ProviderID, ProviderName, ModelID, ModelName    string
	OrigModel, Billing, UserID, CreatedAt           string
	UpCode                                          int64
	// 网关模型拒绝（forbidden_model / key_model_not_allowed）相关：拒绝原因、客户端原始模型名、所用密钥。
	RejectReason, ClientModel            string
	KeyID, KeyPrefix, KeyName, KeyStatus string
	KeyAllowlist                         []string
	// 代理类请求（endpoint_type=proxy）：上游/交付结局、目标域名、耗时。
	Endpoint, UpOutcome, DelOutcome, ProxyMode, TargetHost, AgentType string
	LatencyMS                                                         int64
}

func t7ParseReq(m map[string]any) t7Req {
	return t7Req{
		ID: t7Str(m["request_id"]), Status: t7Str(m["request_status"]), Class: t7Str(m["status_class"]),
		Cat: t7Str(m["failure_category"]), Hint: t7Str(m["upstream_error_hint"]),
		UpCodeStr: t7Str(m["upstream_error_code"]), ErrMsg: t7Str(m["error_message"]),
		ProviderID: t7Str(m["provider_id"]), ProviderName: t7Str(m["provider_name"]),
		ModelID: t7Str(m["model_id"]), ModelName: t7Str(m["model_name"]), OrigModel: t7Str(m["original_model_id"]),
		Billing: t7Str(m["billing_outcome"]), UserID: t7Str(m["user_id"]), CreatedAt: t7Str(m["created_at"]),
		UpCode:       t7Num(m["upstream_status_code"]),
		RejectReason: t7Str(m["reject_reason"]), ClientModel: t7Str(m["client_model"]),
		KeyID: t7Str(m["client_id"]), KeyPrefix: t7Str(m["key_prefix"]), KeyName: t7Str(m["key_name"]),
		KeyStatus: t7Str(m["key_status"]), KeyAllowlist: t7StrItems(m["key_model_allowlist"]),
		Endpoint: t7Str(m["endpoint_type"]), UpOutcome: t7Str(m["upstream_outcome"]), DelOutcome: t7Str(m["delivery_outcome"]),
		ProxyMode: t7Str(m["proxy_mode"]), TargetHost: t7Str(m["proxy_target_host"]), AgentType: t7Str(m["agent_type"]),
		LatencyMS: t7Num(m["latency_ms"]),
	}
}

func t7StrItems(v any) []string {
	var out []string
	for _, x := range t7List(v) {
		if s := t7Str(x); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (q t7Req) modelRef() string {
	for _, s := range []string{q.ModelName, q.OrigModel, q.ModelID} {
		if s != "" {
			return s
		}
	}
	return ""
}

func (q t7Req) provLabel() string {
	if q.ProviderName != "" {
		return q.ProviderName
	}
	return q.ProviderID
}

func (q t7Req) gatewayBlocked() bool {
	return q.Status == "rate_limited" || q.Status == "quota_exceeded" || strings.HasPrefix(q.Billing, "budget_")
}

func (q t7Req) rawText() string {
	var parts []string
	for _, p := range []string{q.Hint, q.UpCodeStr, q.ErrMsg} {
		if strings.TrimSpace(p) != "" {
			parts = append(parts, p)
		}
	}
	return t7Cut(Redact(strings.Join(parts, "\n")), 500)
}

func (q t7Req) evidence(summary string) Evidence {
	return Evidence{Kind: "request", Ref: q.ID, Summary: summary, Raw: q.rawText()}
}

func (q t7Req) insufficientQuota() bool {
	low := strings.ToLower(q.Hint + " " + q.UpCodeStr + " " + q.ErrMsg)
	return q.UpCode == 402 || strings.Contains(low, "insufficient_quota")
}

func (r *t7Run) requestTree(in Input) []Finding {
	id := strings.TrimSpace(in.Ref)
	if id == "" {
		id = reqIDRe.FindString(in.Text)
	}
	if id == "" {
		return []Finding{t7Find("request_not_found", SevWarn, LevelUnknown, "没有找到可查询的请求编号", "",
			[]Advice{{Text: "请提供完整的请求编号（调用明细里的请求编号），或粘贴完整报错"}}, nil, nil)}
	}
	res := r.call("get_request", map[string]any{"request_id": id})
	if !res.ok() {
		return []Finding{t7Find("request_not_found", SevWarn, LevelUnknown, "查询该请求时出错，暂时无法判断", res.err, nil, nil, nil)}
	}
	if !t7Bool(res.m["found"]) {
		return []Finding{t7Find("request_not_found", SevWarn, LevelUnknown, t7NotFoundTitle, "",
			[]Advice{{Text: "请核对请求编号是否完整、是否复制了其他字段"}}, nil, nil)}
	}
	q := t7ParseReq(t7Map(res.m["request"]))
	if q.ID == "" {
		q.ID = id
	}
	isGateway := q.gatewayBlocked()
	switch {
	case q.Class == "success":
		return []Finding{t7Find("request_ok", SevOK, LevelConfirmed, "该请求处理成功，没有失败记录", "",
			[]Advice{{Text: "如果仍觉得结果不对，请描述具体现象，或提供其他请求编号"}}, nil,
			[]Evidence{q.evidence("该请求的状态为成功")})}
	case q.Cat == "security_rejected" || q.Class == "blocked":
		return r.securityRejected(q)
	case isGateway:
		return r.gatewayBlock(q)
	case q.modelDenied():
		// 必须排在 auth_failed 之前：网关拒绝时 upstream_status_code 记的是 403，但请求并没有转发到上游。
		return r.modelDenied(q)
	case q.Status == "model_not_configured" || q.Status == "model_not_found" || q.Cat == "model_not_found":
		return r.modelMissing(q)
	case q.Endpoint == "proxy" && q.UpCode == 0:
		// 代理请求没有上游 HTTP 状态码：靠上游/交付结局、耗时和宿主机重启证据区分原因。
		return r.proxyFailure(q)
	case q.Cat == "auth_failed" || q.UpCode == 401 || q.UpCode == 403:
		return r.authFailed(q)
	case q.UpCode == 429:
		return r.upstream429(q)
	case q.UpCode >= 400 && q.UpCode < 500:
		return r.upstream4xx(q)
	case q.Cat == "timeout" || q.Cat == "upstream_5xx" || q.UpCode >= 500 || q.Status == "timeout" || q.Status == "provider_timeout":
		return r.upstream5xx(q)
	}
	return []Finding{t7Find("request_unknown", SevWarn, LevelUnknown, "暂时无法判断这条请求失败的原因", "已有信息不足以归入已知的失败类型",
		[]Advice{{Text: "建议导出诊断包，联系厂商进一步分析"}}, []string{"已排除网关限流与额度拦截：该请求没有对应的拦截记录"},
		[]Evidence{q.evidence("失败请求，原因未能归类")})}
}

// modelDenied 判断该请求是否被网关的模型授权拒绝。网关在 rejectModelDenied 等处会先写 request_logs，
// 状态为 key_model_not_allowed（密钥白名单）或 forbidden_model，HTTP 403，
// routing_decision_json.reject_reason 为 key_allowlist（密钥白名单）或 user_grant（账号授权）。
func (q t7Req) modelDenied() bool {
	return q.RejectReason == "key_allowlist" || q.RejectReason == "user_grant" ||
		q.Status == "key_model_not_allowed" || q.Status == "forbidden_model"
}

func (q t7Req) deniedModel() string {
	for _, s := range []string{q.ClientModel, q.ModelName, q.OrigModel} {
		if s != "" {
			return s
		}
	}
	return ""
}

func t7Has(list []string, s string) bool {
	for _, e := range list {
		if e == s {
			return true
		}
	}
	return false
}

func (r *t7Run) modelDenied(q t7Req) []Finding {
	model := q.deniedModel()
	// 密钥白名单：拒绝原因有明确记录（或状态就是 key_model_not_allowed）→ 确定；
	// 旧版本没有拒绝原因、状态为 forbidden_model，但这把密钥现在的白名单确实不含该模型 → 只能判疑似（白名单可能被改过）。
	switch {
	case q.RejectReason == "key_allowlist" || q.Status == "key_model_not_allowed":
		return []Finding{r.keyAllowlistFinding(q, model, LevelConfirmed)}
	case q.RejectReason == "" && model != "" && len(q.KeyAllowlist) > 0 && !t7Has(q.KeyAllowlist, model):
		return []Finding{r.keyAllowlistFinding(q, model, LevelSuspected)}
	}
	// 账号授权（部门 / 个人名单）
	ev := []Evidence{q.evidence("网关以模型授权拒绝了该请求（forbidden_model）")}
	excl := []string{"已排除上游问题：该请求在网关侧被拒绝，没有转发到上游"}
	if q.RejectReason == "user_grant" {
		excl = append(excl, "已排除密钥白名单：拒绝原因记录为账号授权，而不是密钥白名单")
	}
	title := "该请求被网关的账号模型授权拒绝（forbidden_model）"
	impact := ""
	// 只有网关明确记录了 user_grant 才能判确定；旧版本没有记录拒绝原因，只能判疑似。
	level := LevelSuspected
	if q.RejectReason == "user_grant" {
		level = LevelConfirmed
	}
	if model != "" && q.UserID != "" {
		if acc := r.call("get_user_access", t7Args("user", q.UserID, "model", model)); acc.ok() && t7Bool(acc.m["found"]) {
			if chk := t7Map(acc.m["model_check"]); chk != nil {
				if t7Bool(chk["allowed"]) {
					title = fmt.Sprintf("该请求因账号没有模型 %s 的使用权限被网关拒绝，但该账号目前已有此模型的权限", model)
					impact = "授权可能在请求之后被调整过，重新发起请求即可确认"
				} else {
					title = fmt.Sprintf("该账号没有模型 %s 的使用权限，网关已拒绝该请求（forbidden_model）", model)
					impact = t7Str(chk["reason"])
				}
			}
		}
	}
	return []Finding{t7Find("user_access", SevError, level, title, impact,
		[]Advice{t7Adv(r.s, "在员工 AI 权限或部门模型授权中给该账号开通此模型", "/organizations")}, excl, ev)}
}

func (r *t7Run) keyAllowlistFinding(q t7Req, model string, level Level) Finding {
	who := "这把密钥"
	switch {
	case q.KeyPrefix != "" && q.KeyName != "":
		who = fmt.Sprintf("这把密钥（前缀 %s、名称 %s）", q.KeyPrefix, q.KeyName)
	case q.KeyPrefix != "":
		who = fmt.Sprintf("这把密钥（前缀 %s）", q.KeyPrefix)
	}
	modelPart := "该模型"
	if model != "" {
		modelPart = "模型 " + model
	}
	title := fmt.Sprintf("%s的模型白名单不含%s，网关已拒绝该请求", who, modelPart)
	if level != LevelConfirmed {
		title = fmt.Sprintf("%s的模型白名单不含%s，很可能因此被网关拒绝", who, modelPart)
	}
	impact := "同一账号使用其他密钥、或该密钥调用白名单内的模型，不受影响"
	if model != "" {
		switch {
		case len(q.KeyAllowlist) == 0:
			impact = "这把密钥现在的白名单已清空（不再限制模型），可能在请求之后被修改过，重新发起请求即可确认"
		case t7Has(q.KeyAllowlist, model):
			impact = "这把密钥现在的白名单已包含该模型，可能在请求之后被修改过，重新发起请求即可确认"
		default:
			impact = "这把密钥当前白名单内的模型：" + strings.Join(q.KeyAllowlist, "、")
		}
	}
	excl := []string{"已排除上游问题：该请求在网关侧被拒绝，没有转发到上游"}
	if level == LevelConfirmed {
		excl = append(excl, "已排除账号授权：网关记录的拒绝原因是密钥白名单，而不是部门或个人授权")
	}
	keyRef := q.KeyID
	ev := []Evidence{q.evidence("网关以密钥模型白名单拒绝了该请求")}
	if keyRef != "" {
		ev = append(ev, Evidence{Kind: "config", Ref: keyRef, Summary: "密钥 " + q.KeyPrefix + " 的模型白名单"})
	}
	link := "/keys"
	if keyRef != "" {
		link = "/keys?key_id=" + url.QueryEscape(keyRef)
	}
	return t7Find("key_model_allowlist", SevError, level, title, impact,
		[]Advice{t7Adv(r.s, "在密钥管理中把该模型加入这把密钥的白名单，或改用其他密钥", link)}, excl, ev)
}

func (r *t7Run) securityRejected(q t7Req) []Finding {
	return []Finding{t7Find("security_block", SevWarn, LevelConfirmed, "该请求被内容安全策略拦截", "请求没有转发到上游",
		[]Advice{t7Adv(r.s, "到告警页核对被拦截的内容，确认是否为误拦，必要时调整策略", "/security/alerts")},
		[]string{"已排除上游故障：该请求在网关就被拦截，没有转发到上游"},
		[]Evidence{q.evidence("被内容安全策略拦截")})}
}

// ---- 网关自身拦截 ----

type t7Hit struct {
	kind    string // blocked | rpm | tpm | conc | day_tokens | month_tokens | day_budget | month_budget
	scope   string
	limit   int64
	used    int64
	policy  string
	hasUsed bool
}

var t7ScopeLabel = map[string]string{"user": "用户级", "key": "密钥级", "team": "部门级", "project": "项目级", "tenant": "租户级"}

func t7Scope(s string) string {
	if l, ok := t7ScopeLabel[s]; ok {
		return l
	}
	return "当前生效的"
}

func t7PickPolicy(q t7Req, policies []any, usage map[string]any) *t7Hit {
	dayTok, monthTok := t7Num(usage["day_tokens"]), t7Num(usage["month_tokens"])
	var blocked, exceeded, configured *t7Hit
	consider := func(slot **t7Hit, h t7Hit) {
		if *slot == nil || (h.limit > 0 && (h.limit < (*slot).limit || (*slot).limit == 0)) {
			c := h
			*slot = &c
		}
	}
	for _, p := range policies {
		pm := t7Map(p)
		if pm == nil {
			continue
		}
		sc, pid := t7Str(pm["scope_type"]), t7Str(pm["id"])
		type dim struct {
			kind, limitKey, blockKey string
			used                     int64
			hasUsed                  bool
		}
		var dims []dim
		if q.Status == "rate_limited" {
			dims = []dim{{"rpm", "rpm_limit", "rpm_blocked", 0, false}, {"tpm", "tpm_limit", "tpm_blocked", 0, false}, {"conc", "concurrency_limit", "concurrency_blocked", 0, false}}
		} else {
			dims = []dim{{"day_tokens", "daily_token_limit", "daily_token_blocked", dayTok, true}, {"month_tokens", "monthly_token_limit", "monthly_token_blocked", monthTok, true},
				{"day_budget", "daily_budget_micros", "daily_budget_blocked", 0, false}, {"month_budget", "monthly_budget_micros", "monthly_budget_blocked", 0, false}}
		}
		for _, d := range dims {
			lim := t7Num(pm[d.limitKey])
			h := t7Hit{kind: d.kind, scope: sc, limit: lim, used: d.used, policy: pid, hasUsed: d.hasUsed}
			if t7Bool(pm[d.blockKey]) {
				h.kind, h.limit = "blocked:"+d.kind, 0
				if blocked == nil {
					c := h
					blocked = &c
				}
				continue
			}
			if lim <= 0 {
				continue
			}
			if d.hasUsed && d.used >= lim {
				consider(&exceeded, h)
			} else if q.Status != "rate_limited" && !d.hasUsed && strings.HasPrefix(q.Billing, "budget_") &&
				((strings.Contains(q.Billing, "month") == strings.HasPrefix(d.kind, "month")) || !strings.Contains(q.Billing, "day") && !strings.Contains(q.Billing, "month")) {
				consider(&exceeded, h)
			} else {
				consider(&configured, h)
			}
		}
	}
	for _, h := range []*t7Hit{blocked, exceeded, configured} {
		if h != nil {
			return h
		}
	}
	return nil
}

func t7DimName(kind string) string {
	switch strings.TrimPrefix(kind, "blocked:") {
	case "rpm":
		return "每分钟请求数"
	case "tpm":
		return "每分钟 token"
	case "conc":
		return "并发数"
	case "day_tokens":
		return "日 token 配额"
	case "month_tokens":
		return "月 token 配额"
	case "day_budget":
		return "日预算"
	case "month_budget":
		return "月预算"
	}
	return "额度"
}

func (r *t7Run) gatewayBlock(q t7Req) []Finding {
	res := r.call("get_quota_policies", t7Args("user", q.UserID))
	var hit *t7Hit
	var usage map[string]any
	if res.ok() {
		usage = t7Map(res.m["usage"])
		hit = t7PickPolicy(q, t7List(res.m["policies"]), usage)
	}
	checkID, what := "gw_quota", "额度"
	if q.Status == "rate_limited" {
		checkID, what = "gw_rate_limited", "限流"
	}
	title := fmt.Sprintf("该请求被网关%s拦截，没有转发到上游", what)
	var ev []Evidence
	ev = append(ev, q.evidence("被网关"+what+"拦截"))
	var excl []string
	if q.UpCode == 0 {
		excl = append(excl, "已排除上游问题：这是网关自身的拦截，该请求没有上游状态码")
	}
	switch {
	case hit == nil:
		excl = append(excl, "未能匹配到当前生效的对应策略（策略可能已被调整）")
	case strings.HasPrefix(hit.kind, "blocked:"):
		title = fmt.Sprintf("该请求被网关策略直接封禁（%s策略把%s设为禁止使用）", t7Scope(hit.scope), t7DimName(hit.kind))
		ev = append(ev, Evidence{Kind: "config", Ref: hit.policy, Summary: t7Scope(hit.scope) + "策略封禁了" + t7DimName(hit.kind)})
	case hit.kind == "rpm":
		title = fmt.Sprintf("该请求被网关限流拦截：%s策略限制每分钟 %d 次请求", t7Scope(hit.scope), hit.limit)
		ev = append(ev, Evidence{Kind: "config", Ref: hit.policy, Summary: fmt.Sprintf("%s策略的每分钟请求数上限为 %d", t7Scope(hit.scope), hit.limit)})
	case hit.kind == "tpm" || hit.kind == "conc":
		title = fmt.Sprintf("该请求被网关限流拦截：%s策略限制%s为 %d", t7Scope(hit.scope), t7DimName(hit.kind), hit.limit)
		ev = append(ev, Evidence{Kind: "config", Ref: hit.policy, Summary: fmt.Sprintf("%s策略的%s上限为 %d", t7Scope(hit.scope), t7DimName(hit.kind), hit.limit)})
	case hit.hasUsed:
		title = fmt.Sprintf("该请求被网关%s拦截：%s策略限额 %d，已用 %d", t7DimName(hit.kind), t7Scope(hit.scope), hit.limit, hit.used)
		ev = append(ev, Evidence{Kind: "config", Ref: hit.policy, Summary: fmt.Sprintf("%s策略的%s限额为 %d，已用 %d", t7Scope(hit.scope), t7DimName(hit.kind), hit.limit, hit.used)})
		if hit.used < hit.limit {
			excl = append(excl, "当前用量已低于限额（额度可能已重置或策略已调整）")
		}
	default:
		title = fmt.Sprintf("该请求被网关%s拦截（%s策略）", t7DimName(hit.kind), t7Scope(hit.scope))
		ev = append(ev, Evidence{Kind: "config", Ref: hit.policy, Summary: t7Scope(hit.scope) + "策略设有" + t7DimName(hit.kind) + "上限"})
	}
	impact := ""
	if usage != nil {
		impact = fmt.Sprintf("该账号今日已发起 %d 次请求，累计 %d token", t7Num(usage["day_requests"]), t7Num(usage["day_tokens"]))
	}
	return []Finding{t7Find(checkID, SevError, LevelConfirmed, title, impact,
		[]Advice{t7Adv(r.s, "在配额策略中调整对应限额，或等待额度重置", "/cost/quota-policies")}, excl, ev)}
}

// ---- 模型缺失 ----

func (r *t7Run) modelMissing(q t7Req) []Finding {
	name := q.modelRef()
	title := "该请求使用的模型没有配置或已被移除"
	if name != "" {
		title = fmt.Sprintf("模型 %s 没有配置或已被移除", name)
	}
	var excl []string
	impact := ""
	level := LevelConfirmed
	if r.s.IsAdmin && name != "" {
		res := r.call("get_model_routes", map[string]any{"model": name})
		if res.ok() {
			if t7Bool(res.m["found"]) {
				n := t7Num(res.m["usable_routes"])
				if n == 0 {
					title = fmt.Sprintf("模型 %s 已配置，但当前没有任何可用渠道", name)
					impact = t7RouteProblems(res.m)
				} else {
					title = fmt.Sprintf("模型 %s 现在有 %d 条可用路由，但这次请求未能命中", name, n)
					impact = "该请求发生时路由配置可能不同，或请求中的模型名与现有配置不一致"
					level = LevelSuspected
					excl = append(excl, "已排除模型被删除：该模型当前仍有配置")
				}
			} else {
				excl = append(excl, "已核对模型配置：租户内不存在该模型名")
			}
		}
	}
	return []Finding{t7Find("model_missing", SevError, level, title, impact,
		[]Advice{t7Adv(r.s, "在模型管理中确认该模型已配置并启用，或让调用方改用已有模型", "/models")}, excl,
		[]Evidence{q.evidence("请求状态为模型未配置")})}
}

func t7RouteProblems(m map[string]any) string {
	var parts []string
	for _, x := range t7List(m["routes"]) {
		rt := t7Map(x)
		if rt == nil || t7Bool(rt["usable"]) {
			continue
		}
		why := "不可用"
		switch {
		case t7Str(rt["provider_status"]) != "active":
			why = "渠道已停用"
		case t7Str(rt["model_status"]) != "active":
			why = "模型已停用"
		case t7Str(rt["health_state"]) == "unhealthy":
			why = "渠道健康检查失败"
		}
		parts = append(parts, fmt.Sprintf("渠道 %s（%s）", t7Str(rt["provider_name"]), why))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "；")
}

// ---- 鉴权失败 ----

func (r *t7Run) authFailed(q t7Req) []Finding {
	title := "渠道凭据被上游拒绝（失效或无权限）"
	if q.provLabel() != "" {
		title = fmt.Sprintf("渠道 %s 的凭据被上游拒绝（失效或无权限）", q.provLabel())
	}
	var excl []string
	impact := ""
	if r.s.IsAdmin && q.ProviderID != "" {
		res := r.call("get_provider", map[string]any{"provider": q.ProviderID})
		if res.ok() && t7Bool(res.m["found"]) {
			lh := t7Map(res.m["last_hour"])
			if lh != nil {
				impact = fmt.Sprintf("该渠道近 1 小时共 %d 条请求，成功 %d 条", t7Num(lh["total"]), t7Num(lh["success"]))
			}
			if t7Bool(res.m["has_active_credential"]) {
				excl = append(excl, "已排除凭据缺失：渠道存在可用凭据，但上游仍然拒绝（可能已过期或被撤销）")
			} else {
				title = fmt.Sprintf("渠道 %s 当前没有可用凭据，上游鉴权被拒", q.provLabel())
			}
			if t7Str(res.m["status"]) == "active" {
				excl = append(excl, "已排除渠道被停用：渠道当前为启用状态")
			}
		}
	}
	return []Finding{t7Find("auth_failed", SevError, LevelConfirmed, title, impact,
		[]Advice{t7Adv(r.s, "在渠道管理中更新该渠道的凭据并测试连通", "/providers")}, excl,
		[]Evidence{q.evidence("上游返回鉴权失败")})}
}

// ---- 上游 429 ----

func (r *t7Run) upstream429(q t7Req) []Finding {
	title := "上游限流：上游返回 HTTP 429（请求频率过高）"
	if q.provLabel() != "" {
		title = fmt.Sprintf("上游限流：渠道 %s 返回 HTTP 429（请求频率过高）", q.provLabel())
	}
	excl := []string{"已排除网关限流与额度拦截：该请求已转发到上游，由上游返回 HTTP 429"}
	impact := ""
	res := r.call("search_requests", t7Args("provider", q.ProviderID, "window_hours", 1))
	if res.ok() {
		total, success := t7Num(res.m["total"]), t7Num(res.m["success"])
		var best *t7Group
		var sum429 int64
		for _, g := range t7Groups(res.m) {
			if g.Code == 429 && (g.ProviderID == q.ProviderID || q.ProviderID == "") {
				sum429 += g.Count
				gg := g
				if best == nil || g.Count > best.Count || (g.ModelID == q.ModelID && best.ModelID != q.ModelID) {
					best = &gg
				}
			}
		}
		switch {
		case total > 0 && sum429*100 >= 80*total:
			impact = fmt.Sprintf("整个渠道近 1 小时几乎都在被上游限流：共 %d 条请求，成功 %d 条", total, success)
			excl = append(excl, "已排除单个请求偶发：渠道内绝大多数请求都被限流")
		case total > 0 && best != nil:
			impact = fmt.Sprintf("该渠道近 1 小时共 %d 条请求，其中 %d 条被上游限流", total, best.Count)
			if success > 0 {
				excl = append(excl, fmt.Sprintf("已排除整条渠道故障：近 1 小时该渠道仍有 %d 条请求成功", success))
			}
		}
	}
	out := []Finding{t7Find("up_429", SevError, LevelConfirmed, title, impact,
		[]Advice{t7Adv(r.s, "降低该渠道的并发，或为相关模型配置备用渠道", t7ModelLink(q.modelRef()))}, excl,
		[]Evidence{q.evidence("上游返回 HTTP 429")})}
	if q.insufficientQuota() {
		out = append(out, r.billingSuspect(q))
	}
	return out
}

func (r *t7Run) billingSuspect(q t7Req) Finding {
	title := "疑似上游额度不足（欠费）"
	if q.provLabel() != "" {
		title = fmt.Sprintf("疑似上游额度不足（欠费）：渠道 %s", q.provLabel())
	}
	return t7Find("up_billing", SevError, LevelSuspected, title, "该渠道的请求可能持续失败，直到上游账户充值",
		[]Advice{t7Adv(r.s, "登录上游平台核对账户余额与额度，必要时充值", "/providers")},
		[]string{"多数上游没有余额接口，无法直接查询余额，仅凭错误特征（额度不足提示或 HTTP 402）推断"},
		[]Evidence{q.evidence("上游错误特征指向额度不足")})
}

// ---- 上游 4xx（含参数不兼容） ----

type t7Group struct {
	Cat, ProviderID, ProviderName, ModelID, ModelName, FirstAt, LastAt string
	Code, Count, Users, Denied                                         int64
	Samples                                                            []string
}

func t7Groups(m map[string]any) []t7Group {
	var out []t7Group
	key := "groups"
	if m["groups"] == nil {
		key = "errors"
	}
	for _, x := range t7List(m[key]) {
		g := t7Map(x)
		if g == nil {
			continue
		}
		tg := t7Group{Cat: t7Str(g["failure_category"]), ProviderID: t7Str(g["provider_id"]), ProviderName: t7Str(g["provider_name"]),
			ModelID: t7Str(g["model_id"]), ModelName: t7Str(g["model_name"]), FirstAt: t7Str(g["first_at"]), LastAt: t7Str(g["last_at"]),
			Code: t7Num(g["upstream_status_code"]), Count: t7Num(g["count"]), Users: t7Num(g["affected_users"]), Denied: t7Num(g["model_denied"])}
		for _, sid := range t7List(g["sample_request_ids"]) {
			if s := t7Str(sid); s != "" {
				tg.Samples = append(tg.Samples, s)
			}
		}
		out = append(out, tg)
	}
	return out
}

func t7MatchGroup(groups []t7Group, q t7Req) *t7Group {
	for i, g := range groups {
		if g.Code == q.UpCode && g.ProviderID == q.ProviderID && (q.ModelID == "" || g.ModelID == q.ModelID) {
			return &groups[i]
		}
	}
	return nil
}

var t7ParamRe = regexp.MustCompile("['\"`]([A-Za-z_][A-Za-z0-9_.\\[\\]-]*)['\"`]")

// t7ExplainHint 把上游英文报错概括成一句中文；已经是中文的提示原样使用。
func t7ExplainHint(hint, upCode, msg string) string {
	if t7HasCJK(hint) {
		return t7Cut(hint, 60)
	}
	all := hint + " " + msg
	low := strings.ToLower(all + " " + upCode)
	has := func(ss ...string) bool {
		for _, s := range ss {
			if strings.Contains(low, s) {
				return true
			}
		}
		return false
	}
	switch {
	case has("insufficient_quota", "exceeded your current quota", "billing"):
		return "上游账户额度不足或已欠费"
	case has("context length", "context_length", "maximum context", "too many tokens"):
		return "请求内容超出上游模型的上下文长度限制"
	case has("max_tokens", "max_completion_tokens") && has("maximum allowed", "maximum value", "greater than", "exceeds", "too large", " > "):
		return "输出长度参数 max_tokens 超过该模型允许的上限"
	case has("unsupported parameter", "unknown parameter", "invalid parameter", "unrecognized request argument", "max_tokens", "max_completion_tokens", "extra inputs", "not permitted"):
		if m := t7ParamRe.FindStringSubmatch(all); m != nil {
			return "参数 " + m[1] + " 被该上游拒绝"
		}
		return "请求参数被该上游拒绝"
	case has("model") && has("not found", "does not exist", "not exist", "deployment"):
		return "上游不存在该模型或部署"
	case has("content_filter", "content management policy", "content policy"):
		return "上游的内容审核拒绝了该请求"
	}
	return "上游返回了拒绝错误"
}

func (r *t7Run) upstream4xx(q t7Req) []Finding {
	expl := "请求被拒绝"
	if q.Hint != "" || q.ErrMsg != "" {
		expl = t7ExplainHint(q.Hint, q.UpCodeStr, q.ErrMsg)
	}
	title := fmt.Sprintf("上游拒绝：%s（HTTP %d）", expl, q.UpCode)

	filter := func(extra ...any) map[string]any {
		kv := append([]any{"provider", q.ProviderID, "model", q.ModelID, "status_code", q.UpCode}, extra...)
		return t7Args(kv...)
	}
	srch := r.call("search_requests", filter("window_hours", 24))
	cmp := r.call("compare_windows", filter("a_hours_ago", 0, "b_hours_ago", 24, "window_hours", 24))

	var grp *t7Group
	if srch.ok() {
		grp = t7MatchGroup(t7Groups(srch.m), q)
	}
	var bCount int64 = -1
	if cmp.ok() {
		bCount = 0
		for _, g := range t7Groups(t7Map(cmp.m["b"])) {
			if g.Code == q.UpCode && g.ProviderID == q.ProviderID && (q.ModelID == "" || g.ModelID == q.ModelID) {
				bCount += g.Count
			}
		}
	}

	var tlEvents []map[string]any
	tlOK := false
	if r.s.IsAdmin && grp != nil && grp.FirstAt != "" {
		tl := r.call("change_timeline", map[string]any{"around": grp.FirstAt, "window_hours": 1})
		if tl.ok() {
			tlOK = true
			for _, e := range t7List(tl.m["events"]) {
				if em := t7Map(e); em != nil {
					tlEvents = append(tlEvents, em)
				}
			}
		}
	}

	impact := "仅查到这一条请求，无法判断是否批量发生"
	var excl []string
	excl = append(excl, "已排除网关限流与额度拦截：该请求已转发到上游，由上游返回错误")
	if grp != nil {
		impact = fmt.Sprintf("同渠道同模型近 24 小时共 %d 条相同错误，涉及 %d 个用户", grp.Count, grp.Users)
		if grp.Count >= t7CorrelationMin {
			excl = append(excl, fmt.Sprintf("已排除客户端偶发：同渠道同模型近 24 小时有 %d 条相同错误", grp.Count))
		}
	}
	if bCount > 0 {
		excl = append(excl, "已排除新近引入：24 小时前同渠道同模型就已出现相同错误")
	}

	ev := []Evidence{q.evidence(fmt.Sprintf("上游返回 HTTP %d", q.UpCode))}
	if grp != nil {
		n := 0
		for _, sid := range grp.Samples {
			if sid != q.ID && n < 2 {
				ev = append(ev, Evidence{Kind: "request", Ref: sid, Summary: "同类错误示例"})
				n++
			}
		}
	}
	adv := []Advice{t7Adv(r.s, "核对该模型在此渠道上的参数设置，或改用其他渠道", t7ModelLink(q.modelRef())),
		t7Adv(r.s, "在调用明细中查看上游原文", t7RecordsLink(q.ID))}
	if grp != nil && grp.Count >= t7CorrelationMin {
		adv = append(adv, Advice{Text: "多个请求同时被拒，可能是网关转发与该上游不兼容，建议导出诊断包并联系厂商"})
	}
	main := t7Find("up_param", SevError, LevelConfirmed, title, impact, adv, excl, ev)
	out := []Finding{main}

	// 首次出现时间与变更吻合
	if grp != nil && grp.Count >= t7CorrelationMin && bCount == 0 && tlOK {
		if f := t7Correlate(grp, tlEvents); f != nil {
			out = append(out, *f)
		} else {
			out[0].Excluded = append(out[0].Excluded, "已排除版本升级与配置变更：错误首次出现前后 30 分钟内没有升级或配置变更记录")
		}
	}
	if q.insufficientQuota() {
		out = append(out, r.billingSuspect(q))
	}
	return out
}

// t7TrimEvent 去掉事件摘要里的英文状态和操作人等细节，只保留客户能读懂的部分。
func t7TrimEvent(kind, s string) string {
	for _, cut := range []string{"（状态", "，完成于", "，操作人", "，详情", "，当前状态", "，对象"} {
		if i := strings.Index(s, cut); i > 0 {
			s = s[:i]
		}
	}
	return strings.TrimSpace(s)
}

func t7Correlate(grp *t7Group, events []map[string]any) *Finding {
	first, err := time.Parse(time.RFC3339, grp.FirstAt)
	if err != nil {
		return nil
	}
	type cand struct {
		at   time.Time
		raw  string
		kind string
		sum  string
		d    time.Duration
	}
	var cs []cand
	for _, e := range events {
		at, err := time.Parse(time.RFC3339, t7Str(e["at"]))
		if err != nil {
			continue
		}
		d := at.Sub(first)
		if d < 0 {
			d = -d
		}
		if d <= t7CorrelationSpan {
			cs = append(cs, cand{at, t7Str(e["at"]), t7Str(e["kind"]), t7Str(e["summary"]), d})
		}
	}
	if len(cs) == 0 {
		return nil
	}
	sort.SliceStable(cs, func(i, j int) bool { return cs[i].d < cs[j].d })
	c := cs[0]
	label := "配置变更"
	if c.kind == "upgrade" {
		label = "升级"
	}
	desc := t7TrimEvent(c.kind, c.sum)
	title := fmt.Sprintf("该问题始于 %s，与%s（%s于 %s）时间吻合，疑似网关新版本或配置变更引入",
		t7When(grp.FirstAt), desc, label, t7When(c.raw))
	ev := []Evidence{{Kind: "change", Ref: c.kind, Summary: desc + "，时间 " + t7When(c.raw)}}
	for _, sid := range grp.Samples {
		ev = append(ev, Evidence{Kind: "request", Ref: sid, Summary: "该类错误的示例请求"})
		break
	}
	f := t7Find("tree_change_correlation", SevWarn, LevelSuspected, title,
		fmt.Sprintf("此后同类错误共 %d 条", grp.Count),
		[]Advice{{Text: "导出诊断包并联系厂商，核实是否由该次升级或配置变更引入；如是配置变更，可先核对并回退"}},
		[]string{"这只是时间上的吻合，不能证明因果；尚未找到直接证据"}, ev)
	return &f
}

// ---- 上游 5xx / 超时 ----

func (r *t7Run) upstream5xx(q t7Req) []Finding {
	isTimeout := q.Cat == "timeout" || q.Status == "timeout" || q.Status == "provider_timeout" || q.UpCode == 408 || q.UpCode == 504
	var title string
	switch {
	case isTimeout:
		title = "请求超时：上游在限定时间内没有返回"
	case q.UpCode > 0:
		title = fmt.Sprintf("上游服务错误：上游返回 HTTP %d", q.UpCode)
	default:
		title = "上游服务错误：上游返回了服务端异常"
	}
	if q.provLabel() != "" {
		title += "（渠道 " + q.provLabel() + "）"
	}
	var excl []string
	excl = append(excl, "已排除网关限流与额度拦截：该请求已转发到上游")
	impact := ""
	var ev []Evidence
	ev = append(ev, q.evidence("上游异常或超时"))
	var extra []Finding

	srch := r.call("search_requests", t7Args("provider", q.ProviderID, "window_hours", 1))
	if srch.ok() {
		total, success := t7Num(srch.m["total"]), t7Num(srch.m["success"])
		if total > 0 {
			if success == 0 {
				impact = fmt.Sprintf("该渠道近 1 小时共 %d 条请求，没有一条成功，整个渠道都在异常", total)
			} else {
				impact = fmt.Sprintf("该渠道近 1 小时共 %d 条请求，成功 %d 条", total, success)
				excl = append(excl, "已排除整条渠道故障：渠道其余请求仍有成功")
			}
		}
	}
	if r.s.IsAdmin {
		if q.ProviderID != "" {
			pv := r.call("get_provider", map[string]any{"provider": q.ProviderID})
			if pv.ok() && t7Bool(pv.m["found"]) {
				if t7Str(pv.m["status"]) == "active" {
					excl = append(excl, "已排除渠道被停用：渠道当前为启用状态")
				} else {
					excl = append(excl, "注意：该渠道当前不是启用状态")
				}
				if t7Bool(pv.m["has_active_credential"]) {
					excl = append(excl, "已排除凭据缺失：渠道存在可用凭据")
				}
			}
		}
		lg := r.call("host_container_logs", map[string]any{"service": "gateway-core", "grep": q.ID, "since_minutes": 10})
		switch {
		case lg.err != "":
			if strings.Contains(lg.err, "未安装") {
				excl = append(excl, "未能查看宿主机日志：未安装采集器")
			} else {
				excl = append(excl, "未能查看宿主机日志：采集器暂不可用")
			}
		default:
			out := strings.TrimSpace(t7Str(lg.m["output"]))
			if out == "" {
				excl = append(excl, "宿主机网关日志（近 10 分钟）中没有该请求编号的记录")
			} else {
				ev = append(ev, Evidence{Kind: "log", Ref: "gateway-core", Summary: "网关容器日志中有该请求的记录", Raw: t7Cut(out, 800)})
				low := strings.ToLower(out)
				if strings.Contains(low, "panic") || strings.Contains(low, "nil pointer") || strings.Contains(low, "goroutine ") {
					extra = append(extra, t7Find("gw_defect", SevError, LevelSuspected,
						"网关日志中该请求附近出现异常堆栈，疑似网关缺陷，请导出诊断包联系厂商", "",
						[]Advice{{Text: "导出诊断包并联系厂商"}},
						[]string{"这是根据日志关键字做的判断，尚未确认根因"},
						[]Evidence{{Kind: "log", Ref: "gateway-core", Summary: "日志含异常堆栈", Raw: t7Cut(out, 800)}}))
				}
			}
		}
	}
	adv := []Advice{t7Adv(r.s, "检查上游服务状态与网络，必要时为相关模型配置备用渠道", t7ModelLink(q.modelRef())),
		t7Adv(r.s, "在调用明细中查看示例请求", t7RecordsLink(q.ID))}
	id := "up_5xx"
	if isTimeout {
		id = "timeout"
	}
	return append([]Finding{t7Find(id, SevError, LevelConfirmed, title, impact, adv, excl, ev)}, extra...)
}

// ---------- 用户树 ----------

var t7CodeWords = map[string]bool{"forbidden_model": true, "rate_limited": true, "quota_exceeded": true, "insufficient_quota": true,
	"model_not_found": true, "model_not_configured": true, "provider_error": true, "unauthorized": true}

var t7TokenRe = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._:/\-]{2,}`)

// t7ModelCandidates 从原文里挑出可能是模型名的词（含连字符、点、冒号或数字），最多 3 个。
func t7ModelCandidates(text, ref string) []string {
	var out []string
	seen := map[string]bool{ref: true}
	text = reqIDRe.ReplaceAllString(text, " ")
	for _, tok := range t7TokenRe.FindAllString(text, -1) {
		tok = strings.TrimRight(tok, ".:/-")
		low := strings.ToLower(tok)
		if seen[tok] || t7CodeWords[low] || strings.HasPrefix(low, "http") || strings.HasPrefix(low, "req_") {
			continue
		}
		if !strings.ContainsAny(tok, "-._:/0123456789") {
			continue
		}
		if _, err := fmt.Sscanf(tok, "%d", new(int)); err == nil && strings.Trim(tok, "0123456789") == "" {
			continue
		}
		seen[tok] = true
		out = append(out, tok)
		if len(out) == 3 {
			break
		}
	}
	return out
}

func (r *t7Run) userTree(in Input) []Finding {
	ref := strings.TrimSpace(in.Ref)
	if r.s.IsAdmin && ref == "" {
		return []Finding{t7Find("user_access", SevWarn, LevelUnknown, "没有指定要排查的用户", "",
			[]Advice{{Text: "请提供用户名、用户 ID 或 API Key 前缀"}}, nil, nil)}
	}
	acc := r.call("get_user_access", t7Args("user", ref))
	if !acc.ok() {
		return []Finding{t7Find("user_access", SevWarn, LevelUnknown, "查询该用户的授权信息时出错，暂时无法判断", acc.err, nil, nil, nil)}
	}
	if !t7Bool(acc.m["found"]) {
		return []Finding{t7Find("user_access", SevWarn, LevelUnknown, "未找到该用户（请核对用户名或 ID）", "", nil, nil, nil)}
	}
	var out []Finding
	username := t7Str(acc.m["username"])
	if username == "" {
		username = ref
	}
	ev := Evidence{Kind: "config", Ref: t7Str(acc.m["user_id"]), Summary: "账号 " + username + " 的授权配置"}
	chat := t7Bool(acc.m["chat_allowed"])
	reasons := ""
	for _, x := range t7List(acc.m["chat_denied_reasons"]) {
		if s := t7Str(x); s != "" {
			reasons += s + "；"
		}
	}
	reasons = strings.TrimRight(reasons, "；")

	// 点名的模型逐个核对（账号整体没有聊天资格时网关在中间件直接拒绝、不写请求记录，这是它唯一的诊断路径）
	var modelProblems []Finding
	asked := false
	for _, cand := range t7ModelCandidates(in.Text, ref) {
		mr := r.call("get_user_access", t7Args("user", ref, "model", cand))
		if !mr.ok() {
			continue
		}
		chk := t7Map(mr.m["model_check"])
		if chk == nil {
			continue
		}
		code := t7Str(chk["reason_code"])
		if code == "model_unknown" {
			continue // 不是租户内的模型名，忽略
		}
		asked = true
		reason := t7Str(chk["reason"])
		if t7Bool(chk["allowed"]) {
			if ex := t7List(chk["key_allowlist_excludes"]); len(ex) > 0 {
				var ps []string
				for _, p := range ex {
					ps = append(ps, t7Str(p))
				}
				modelProblems = append(modelProblems, t7Find("user_key", SevWarn, LevelConfirmed,
					fmt.Sprintf("账号有模型 %s 的使用权限，但密钥 %s 的模型白名单没有包含它（用这些密钥调用会被拒绝）", cand, strings.Join(ps, "、")), "",
					[]Advice{t7Adv(r.s, "在密钥管理中把该模型加入密钥白名单，或改用其他密钥", "/keys")}, nil,
					[]Evidence{ev}))
			}
			continue
		}
		switch code {
		case "model_inactive":
			modelProblems = append(modelProblems, t7Find("user_access", SevError, LevelConfirmed,
				fmt.Sprintf("模型 %s 当前不可用（%s）", cand, reason), "",
				[]Advice{t7Adv(r.s, "在模型管理中启用该模型或其所在渠道", "/models")}, nil, []Evidence{ev}))
		default:
			excl := []string{"这类拒绝会写入调用明细（状态为 forbidden_model），也可到调用明细按用户筛选来核对"}
			if code == "chat_not_allowed" {
				excl = []string{"这类拒绝发生在网关授权环节，不会写入调用明细，因此查不到请求记录"}
			}
			modelProblems = append(modelProblems, t7Find("user_access", SevError, LevelConfirmed,
				fmt.Sprintf("该账号没有模型 %s 的使用权限（网关会直接拒绝，返回 forbidden_model）", cand), reason,
				[]Advice{t7Adv(r.s, "在员工 AI 权限或部门模型授权中给该账号开通此模型", "/organizations")},
				excl, []Evidence{ev}))
		}
	}
	out = append(out, modelProblems...)
	if !chat && !asked {
		out = append(out, t7Find("user_access", SevError, LevelConfirmed,
			"该账号没有聊天资格，网关会拒绝它的所有模型请求（返回 forbidden_model）", reasons,
			[]Advice{t7Adv(r.s, "为该账号分配部门并确认账号状态正常", "/users")},
			[]string{"这类拒绝发生在网关授权环节，不会写入调用明细，因此查不到请求记录"}, []Evidence{ev}))
	}
	if st := t7Str(acc.m["status"]); st != "" && st != "active" && chat {
		out = append(out, t7Find("user_access", SevError, LevelConfirmed, "该账号已被停用", "",
			[]Advice{t7Adv(r.s, "在用户管理中确认账号状态", "/users")}, nil, []Evidence{ev}))
	}
	// 密钥可用性
	keys := t7List(acc.m["keys"])
	usable := 0
	for _, k := range keys {
		km := t7Map(k)
		if km != nil && t7Str(km["status"]) == "active" && !t7Bool(km["expired"]) {
			usable++
		}
	}
	if usable == 0 {
		title := "该账号没有任何 API Key"
		if len(keys) > 0 {
			title = "该账号的 API Key 全部已停用或过期"
		}
		out = append(out, t7Find("user_key", SevError, LevelConfirmed, title, "",
			[]Advice{t7Adv(r.s, "为该账号创建新的 API Key", "/keys")}, nil, []Evidence{ev}))
	}

	// 额度
	qp := r.call("get_quota_policies", t7Args("user", ref))
	if qp.ok() && t7Bool(qp.m["found"]) {
		out = append(out, t7QuotaFindings(r.s, qp.m)...)
	}

	// 请求
	wh := in.WindowH
	if wh <= 0 || wh > 24 {
		wh = 24
	}
	sr := r.call("search_requests", t7Args("user", ref, "window_hours", wh))
	if sr.ok() {
		out = append(out, r.groupFindings(sr.m)...)
	}
	if len(out) == 0 {
		total := int64(0)
		if sr.ok() {
			total = t7Num(sr.m["total"])
		}
		impact := ""
		if sr.ok() {
			impact = fmt.Sprintf("近 %d 小时共 %d 条请求，没有失败", wh, total)
		}
		out = append(out, t7Find("user_access", SevOK, LevelUnknown,
			"该账号的授权、密钥和额度都正常，近期也没有失败请求，暂时无法解释所反映的问题", impact,
			[]Advice{{Text: "请提供具体的请求编号、报错原文或使用的模型名，便于进一步定位"}},
			[]string{"已核对：账号状态与聊天资格正常", "已核对：存在可用的 API Key", "已核对：没有额度被打满或被封禁"},
			[]Evidence{ev}))
	}
	return out
}

func t7QuotaFindings(s Scope, m map[string]any) []Finding {
	var out []Finding
	usage := t7Map(m["usage"])
	for _, p := range t7List(m["policies"]) {
		pm := t7Map(p)
		if pm == nil {
			continue
		}
		sc, pid := t7Scope(t7Str(pm["scope_type"])), t7Str(pm["id"])
		hard := t7Str(pm["overage_action"]) == "block"
		type dim struct {
			name, limitKey, blockKey string
			used                     int64
			hasUsed                  bool
		}
		dims := []dim{{"日 token 配额", "daily_token_limit", "daily_token_blocked", t7Num(usage["day_tokens"]), usage != nil},
			{"月 token 配额", "monthly_token_limit", "monthly_token_blocked", t7Num(usage["month_tokens"]), usage != nil},
			{"每分钟请求数", "rpm_limit", "rpm_blocked", 0, false}, {"并发数", "concurrency_limit", "concurrency_blocked", 0, false},
			{"日预算", "daily_budget_micros", "daily_budget_blocked", 0, false}, {"月预算", "monthly_budget_micros", "monthly_budget_blocked", 0, false}}
		for _, d := range dims {
			adv := []Advice{t7Adv(s, "在配额策略中调整对应限额", "/cost/quota-policies")}
			ev := []Evidence{{Kind: "config", Ref: pid, Summary: sc + "策略：" + d.name}}
			if t7Bool(pm[d.blockKey]) {
				out = append(out, t7Find("user_quota", SevError, LevelConfirmed,
					fmt.Sprintf("%s策略把%s设为禁止使用，该账号的相关请求会被网关直接拦截", sc, d.name), "", adv, nil, ev))
				continue
			}
			lim := t7Num(pm[d.limitKey])
			if d.hasUsed && lim > 0 && d.used >= lim && hard {
				out = append(out, t7Find("user_quota", SevError, LevelConfirmed,
					fmt.Sprintf("%s策略的%s已用尽：限额 %d，已用 %d，超限动作为拦截", sc, d.name, lim, d.used), "", adv, nil, ev))
			}
		}
	}
	return out
}

// ---------- 模型 / 渠道树 ----------

func (r *t7Run) modelTree(in Input, kind string) []Finding {
	ref := strings.TrimSpace(in.Ref)
	if ref == "" {
		return []Finding{t7Find("model_missing", SevWarn, LevelUnknown, "没有指定要排查的模型或渠道", "",
			[]Advice{{Text: "请提供模型名或渠道名"}}, nil, nil)}
	}
	wh := in.WindowH
	if wh <= 0 || wh > 24 {
		wh = 1
	}
	var out []Finding
	var routes t7Res
	providerIDs := []string{}
	if kind == "model" {
		if r.s.IsAdmin {
			routes = r.call("get_model_routes", map[string]any{"model": ref})
			if routes.ok() {
				if !t7Bool(routes.m["found"]) {
					out = append(out, t7Find("model_missing", SevError, LevelConfirmed, "租户内没有配置你输入的这个模型", "",
						[]Advice{t7Adv(r.s, "在模型管理中添加该模型，或核对模型名是否写错", "/models")}, nil,
						[]Evidence{{Kind: "config", Ref: ref, Summary: "模型 " + ref + " 的路由查询结果为空"}}))
				} else {
					out = append(out, t7RouteFindings(r.s, ref, routes.m)...)
					for _, x := range t7List(routes.m["routes"]) {
						if rt := t7Map(x); rt != nil {
							providerIDs = append(providerIDs, t7Str(rt["provider_id"]))
						}
					}
				}
			}
		}
		sr := r.call("search_requests", t7Args("model", ref, "window_hours", wh))
		if sr.ok() {
			out = append(out, r.groupFindings(sr.m)...)
			if len(providerIDs) == 0 {
				for _, g := range t7Groups(sr.m) {
					providerIDs = append(providerIDs, g.ProviderID)
				}
			}
		}
	} else {
		sr := r.call("search_requests", t7Args("provider", ref, "window_hours", wh))
		providerIDs = append(providerIDs, ref)
		if sr.ok() {
			out = append(out, r.groupFindings(sr.m)...)
		}
	}
	if r.s.IsAdmin {
		seen := map[string]bool{}
		n := 0
		for _, pid := range providerIDs {
			if pid == "" || seen[pid] || n >= 3 {
				continue
			}
			seen[pid] = true
			n++
			pv := r.call("get_provider", map[string]any{"provider": pid})
			if pv.ok() {
				out = append(out, t7ProviderFindings(r.s, pv.m)...)
			}
		}
	}
	if len(out) == 0 {
		out = append(out, t7Find("model_missing", SevOK, LevelUnknown, "该对象的路由与渠道状态正常，近期没有发现失败请求", "",
			[]Advice{{Text: "请提供具体的请求编号或报错原文，便于进一步定位"}},
			[]string{"已核对：渠道均为启用状态且有可用凭据", "已核对：窗口内没有失败或被拦截的请求"}, []Evidence{{Kind: "config", Ref: ref, Summary: "模型与渠道配置检查结果"}}))
	}
	return out
}

func t7RouteFindings(s Scope, ref string, m map[string]any) []Finding {
	// 标题里的模型名取自工具输出，保证与事实校验一致。
	if rs := t7List(m["routes"]); len(rs) > 0 {
		if n := t7Str(t7Map(rs[0])["model_name"]); n != "" {
			ref = n
		}
	}
	ev := []Evidence{{Kind: "config", Ref: ref, Summary: "模型 " + ref + " 的路由配置"}}
	var out []Finding
	n := t7Num(m["usable_routes"])
	if n == 0 {
		out = append(out, t7Find("no_route", SevError, LevelConfirmed, fmt.Sprintf("模型 %s 没有任何可用渠道", ref), t7RouteProblems(m),
			[]Advice{t7Adv(s, "启用该模型所在渠道，或为它添加可用渠道", t7ModelLink(ref))}, nil, ev))
		return out
	}
	if p := t7RouteProblems(m); p != "" {
		out = append(out, t7Find("provider_down", SevWarn, LevelConfirmed, fmt.Sprintf("模型 %s 有部分路由不可用", ref), p,
			[]Advice{t7Adv(s, "启用或修复这些渠道", t7ModelLink(ref))}, nil, ev))
	}
	if !t7Bool(m["has_standby"]) {
		out = append(out, t7Find("no_standby", SevWarn, LevelConfirmed, fmt.Sprintf("模型 %s 只有 %d 条可用路由，没有备用渠道", ref, n),
			"主渠道一旦故障，该模型会整体不可用",
			[]Advice{t7Adv(s, "为该模型再配置一个备用渠道", t7ModelLink(ref))}, nil, ev))
	}
	return out
}

func t7ProviderFindings(s Scope, m map[string]any) []Finding {
	if !t7Bool(m["found"]) {
		return nil
	}
	name := t7Str(m["name"])
	ev := []Evidence{{Kind: "config", Ref: t7Str(m["id"]), Summary: "渠道 " + name + " 的状态"}}
	var out []Finding
	if st := t7Str(m["status"]); st != "active" {
		out = append(out, t7Find("provider_down", SevError, LevelConfirmed, fmt.Sprintf("渠道 %s 已停用", name), "指向该渠道的路由不会生效",
			[]Advice{t7Adv(s, "启用该渠道，或把路由改到其他渠道", "/providers")}, nil, ev))
	}
	if !t7Bool(m["has_active_credential"]) {
		out = append(out, t7Find("auth_failed", SevError, LevelConfirmed, fmt.Sprintf("渠道 %s 没有可用凭据", name), "调用该渠道会被上游拒绝",
			[]Advice{t7Adv(s, "在渠道管理中配置有效凭据", "/providers")}, nil, ev))
	}
	return out
}

// ---------- 聚合分组 → 结论 ----------

func (r *t7Run) groupFindings(search map[string]any) []Finding {
	groups := t7Groups(search)
	var out []Finding
	for i, g := range groups {
		if i >= t7MaxGroupFinding {
			break
		}
		if g.Cat == "client_canceled" {
			continue
		}
		if f := r.groupFinding(g); f != nil {
			out = append(out, *f)
		}
	}
	return out
}

func t7GroupEvidence(g t7Group) []Evidence {
	var ev []Evidence
	for _, sid := range g.Samples {
		ev = append(ev, Evidence{Kind: "request", Ref: sid, Summary: "该类问题的示例请求"})
	}
	return ev
}

func t7Names(g t7Group) (prov, model string) {
	prov, model = g.ProviderName, g.ModelName
	if prov == "" {
		prov = g.ProviderID
	}
	if model == "" {
		model = g.ModelID
	}
	return
}

func (r *t7Run) groupFinding(g t7Group) *Finding {
	prov, model := t7Names(g)
	where := ""
	switch {
	case prov != "" && model != "":
		where = fmt.Sprintf("（渠道 %s，模型 %s）", prov, model)
	case prov != "":
		where = fmt.Sprintf("（渠道 %s）", prov)
	}
	impact := fmt.Sprintf("涉及 %d 个用户，最早 %s，最近 %s", g.Users, t7When(g.FirstAt), t7When(g.LastAt))
	ev := t7GroupEvidence(g)
	recAdv := func() Advice {
		if len(g.Samples) > 0 {
			return t7Adv(r.s, "在调用明细中查看示例请求", t7RecordsLink(g.Samples[0]))
		}
		return t7Adv(r.s, "在调用明细中查看失败请求", t7RecordsLink(""))
	}
	mk := func(id string, sev Severity, lv Level, title string, excl []string, adv ...Advice) *Finding {
		f := t7Find(id, sev, lv, title, impact, append(adv, recAdv()), excl, ev)
		return &f
	}
	switch {
	case g.Cat == "quota_exceeded":
		return mk("gw_quota", SevError, LevelConfirmed, fmt.Sprintf("网关额度拦截了 %d 条请求%s", g.Count, where),
			[]string{"已排除上游问题：这是网关自身的拦截，没有转发到上游"},
			t7Adv(r.s, "在配额策略中调整对应限额，或等待额度重置", "/cost/quota-policies"))
	case g.Cat == "rate_limited" && g.Code == 0:
		return mk("gw_rate_limited", SevError, LevelConfirmed, fmt.Sprintf("网关限流拦截了 %d 条请求%s", g.Count, where),
			[]string{"已排除上游问题：这是网关自身的拦截，没有转发到上游"},
			t7Adv(r.s, "在配额策略中调高 RPM 限制", "/cost/quota-policies"))
	case g.Code == 429 || g.Cat == "rate_limited":
		return mk("up_429", SevError, LevelConfirmed, fmt.Sprintf("上游限流：返回 HTTP 429 共 %d 条%s", g.Count, where),
			[]string{"已排除网关限流与额度拦截：这些请求已转发到上游，由上游返回 429"},
			t7Adv(r.s, "降低并发或为相关模型配置备用渠道", t7ModelLink(model)))
	case g.Cat == "security_rejected":
		return mk("security_block", SevWarn, LevelConfirmed, fmt.Sprintf("%d 条请求被内容安全策略拦截%s", g.Count, where), nil,
			t7Adv(r.s, "到告警页核对被拦截的内容，确认是否为误拦", "/security/alerts"))
	case g.Cat == "model_not_found":
		return mk("model_missing", SevError, LevelConfirmed, fmt.Sprintf("%d 条请求使用了未配置的模型%s", g.Count, where), nil,
			t7Adv(r.s, "在模型管理中确认该模型已配置并启用", "/models"))
	case g.Denied > 0 && g.Denied == g.Count:
		// 网关模型授权拒绝（密钥白名单或账号授权）记的是 HTTP 403，但没有转发到上游，不能算渠道凭据问题。
		return mk("model_denied", SevError, LevelConfirmed, fmt.Sprintf("%d 条请求被网关的模型授权拒绝（密钥白名单或账号授权）%s", g.Count, where),
			[]string{"已排除上游问题：这些请求在网关侧被拒绝，没有转发到上游"},
			t7Adv(r.s, "在密钥管理中核对这些请求所用密钥的模型白名单", "/keys"))
	case g.Cat == "auth_failed" || g.Code == 401 || g.Code == 403:
		return mk("auth_failed", SevError, LevelConfirmed, fmt.Sprintf("渠道凭据被上游拒绝 %d 次%s", g.Count, where), nil,
			t7Adv(r.s, "在渠道管理中更新该渠道的凭据并测试连通", "/providers"))
	case g.Cat == "timeout":
		return mk("timeout", SevError, LevelConfirmed, fmt.Sprintf("%d 条请求超时%s", g.Count, where), nil,
			t7Adv(r.s, "检查上游响应速度与网络，必要时配置备用渠道", t7ModelLink(model)))
	case g.Cat == "upstream_5xx" || g.Code >= 500:
		t := fmt.Sprintf("上游服务错误：%d 条请求返回 5xx 错误%s", g.Count, where)
		if g.Code > 0 {
			t = fmt.Sprintf("上游服务错误：%d 条请求返回 HTTP %d%s", g.Count, g.Code, where)
		}
		return mk("up_5xx", SevError, LevelConfirmed, t, nil,
			t7Adv(r.s, "检查上游服务状态，必要时配置备用渠道", t7ModelLink(model)))
	case g.Cat == "stream_aborted":
		return mk("stream_abort", SevWarn, LevelSuspected, fmt.Sprintf("%d 条流式响应中途中断%s", g.Count, where), []string{"尚未确认是客户端断开还是上游中断"},
			t7Adv(r.s, "检查客户端与网关之间的网络和超时设置", "/system/service-health"))
	case g.Code >= 400 && g.Code < 500:
		expl := "请求被拒绝"
		if len(g.Samples) > 0 {
			if sr := r.call("get_request", map[string]any{"request_id": g.Samples[0]}); sr.ok() && t7Bool(sr.m["found"]) {
				q := t7ParseReq(t7Map(sr.m["request"]))
				if q.Hint != "" || q.ErrMsg != "" {
					expl = t7ExplainHint(q.Hint, q.UpCodeStr, q.ErrMsg)
				}
			}
		}
		return mk("up_param", SevError, LevelConfirmed, fmt.Sprintf("上游拒绝：%s（HTTP %d，共 %d 条）%s", expl, g.Code, g.Count, where),
			[]string{"已排除网关限流与额度拦截：这些请求已转发到上游，由上游返回错误"},
			t7Adv(r.s, "核对该模型在此渠道上的参数设置，或改用其他渠道", t7ModelLink(model)))
	}
	return mk("request_unknown", SevWarn, LevelUnknown, fmt.Sprintf("%d 条请求失败，原因未能归类%s", g.Count, where), nil,
		Advice{Text: "建议导出诊断包，联系厂商进一步分析"})
}

// ---------- 代理类请求失败 ----------

const (
	t7RestartSlack = 5 * time.Second // 请求结束后仍视为“处理期间”的宽限
	t7UpgradeLead  = 2 * time.Minute // 升级记录先于请求开始这么久内仍算同一次发布
)

// t7RestartServices 是处理代理流量的容器；它们重启会切断进行中的请求。
var t7RestartServices = []string{"proxy-server", "gateway-core"}

func t7ParseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// proxyFailure 处理没有上游 HTTP 状态码的失败代理请求：
// 客户端中断 / 目标站点超时 / 连不上目标站点 / 网关服务重启时被中断 / 响应传输中断 / 原因不明的中途中断。
func (r *t7Run) proxyFailure(q t7Req) []Finding {
	target := ""
	if q.TargetHost != "" {
		target = "（目标 " + q.TargetHost + "）"
	}
	retry := Advice{Text: "重新发起请求"}
	excl := []string{"已排除网关限流与额度拦截：该请求已进入代理转发", "已排除上游返回错误：该请求没有上游状态码"}
	ev := []Evidence{q.evidence(fmt.Sprintf("代理请求失败，上游结局 %s，交付结局 %s，耗时 %d 毫秒", q.UpOutcome, q.DelOutcome, q.LatencyMS))}
	mk := func(id string, sev Severity, lv Level, title, impact string, adv []Advice, ex []string, e []Evidence) []Finding {
		return []Finding{t7Find(id, sev, lv, title, impact, adv, append(append([]string{}, excl...), ex...), e)}
	}
	switch {
	case q.Cat == "client_canceled" || q.Status == "client_canceled" || q.DelOutcome == "client_canceled":
		return mk("proxy_client_canceled", SevWarn, LevelConfirmed, "客户端中断了请求"+target, "调用方在拿到结果前主动断开了连接，不是网关或上游故障",
			[]Advice{retry, {Text: "如果经常发生，检查调用方的超时设置是否过短"}}, nil, ev)
	case q.UpOutcome == "timeout" || q.Cat == "timeout" || q.Status == "timeout" || q.Status == "provider_timeout":
		return mk("proxy_timeout", SevError, LevelConfirmed, "代理请求超时：目标站点在限定时间内没有响应"+target, "",
			[]Advice{retry, t7Adv(r.s, "检查目标站点是否可达、网络出口是否拥塞", "")}, nil, ev)
	case q.UpOutcome == "network_error":
		return mk("proxy_upstream_unreachable", SevError, LevelConfirmed, "无法连接目标站点"+target+"：上游连接失败", "",
			[]Advice{retry, t7Adv(r.s, "检查目标站点域名解析、网络出口与防火墙", "")}, nil, ev)
	}

	// 结局不明确或传输中断：先看请求处理期间网关服务是否重启过（仅管理员可核对宿主机）。
	start, okT := t7ParseTime(q.CreatedAt)
	end := start.Add(time.Duration(q.LatencyMS) * time.Millisecond)
	if r.s.IsAdmin && okT {
		rev, confirmed, notes := r.restartEvidence(start, end)
		excl = append(excl, notes...)
		if len(rev) > 0 {
			ev = append(ev, rev...)
			lv, title := LevelSuspected, "疑似该请求在网关升级期间被中断"
			impact := "请求处理期间有升级记录，进行中的请求可能被切断，因此没有拿到上游结果"
			if confirmed {
				lv, title = LevelConfirmed, "该请求在网关服务重启时被中断"
				impact = "请求处理期间（" + t7When(q.CreatedAt) + " 起）代理服务发生重启，进行中的请求被切断，因此没有拿到上游结果"
			}
			return mk("gw_restart_interrupt", SevWarn, lv, title+target, impact,
				[]Advice{{Text: "重新发起请求；如频繁发生，避开业务高峰做升级"}}, nil, ev)
		}
	}
	if q.Cat == "stream_aborted" || q.Status == "stream_aborted" || q.DelOutcome == "aborted" {
		return mk("proxy_stream_aborted", SevWarn, LevelConfirmed, "响应传输中途中断"+target, "上游已开始返回，但传输没有完成",
			[]Advice{retry, t7Adv(r.s, "检查客户端到网关、网关到目标站点之间的网络稳定性", "")}, nil, ev)
	}
	title := "代理请求在处理中途被中断，具体原因暂时无法确认" + target
	impact := "上游结局与交付结局均未记录，可能是网关服务升级或重启、网络中断所致"
	adv := []Advice{retry}
	if r.s.IsAdmin {
		adv = append(adv, Advice{Text: "对照该时间点的服务重启与升级记录，确认是否发布期间被切断"})
	} else {
		adv = append(adv, Advice{Text: "如频繁发生，请联系管理员处理"})
	}
	return mk("proxy_interrupted", SevWarn, LevelSuspected, title, impact, adv,
		[]string{"未发现可直接确认的原因，结论仅为推测"}, ev)
}

// restartEvidence 在请求处理区间 [start, end+宽限] 内找重启证据：
// 容器 started_at 落在区间内为确定（confirmed）；只有 change_timeline 的升级记录为疑似。
func (r *t7Run) restartEvidence(start, end time.Time) (ev []Evidence, confirmed bool, notes []string) {
	hi := end.Add(t7RestartSlack)
	snap := r.call("host_snapshot", map[string]any{})
	if snap.ok() {
		for _, c := range t7List(snap.m["containers"]) {
			cm := t7Map(c)
			svc, name := t7Str(cm["service"]), t7Str(cm["name"])
			match := false
			for _, w := range t7RestartServices {
				if svc == w || strings.Contains(name, w) {
					match = true
				}
			}
			at, ok := t7ParseTime(t7Str(cm["started_at"]))
			if !match || !ok || at.Before(start) || at.After(hi) {
				continue
			}
			ref := svc
			if ref == "" {
				ref = name
			}
			ev = append(ev, Evidence{Kind: "host", Ref: ref, Summary: "容器 " + ref + " 于 " + t7When(t7Str(cm["started_at"])) + " 重新启动，落在该请求处理期间"})
			confirmed = true
		}
		if !confirmed {
			notes = append(notes, "已核对代理服务容器：请求处理期间没有重启")
		}
	} else if strings.Contains(snap.err, "未安装") {
		notes = append(notes, "未能核对容器重启：未安装采集器")
	} else {
		notes = append(notes, "未能核对容器重启：采集器暂不可用")
	}
	if confirmed {
		return ev, true, notes
	}
	tl := r.call("change_timeline", map[string]any{"around": start.UTC().Format(time.RFC3339), "window_hours": 1})
	if !tl.ok() {
		return ev, false, notes
	}
	for _, e := range t7List(tl.m["events"]) {
		em := t7Map(e)
		at, ok := t7ParseTime(t7Str(em["at"]))
		if t7Str(em["kind"]) != "upgrade" || !ok || at.Before(start.Add(-t7UpgradeLead)) || at.After(hi) {
			continue
		}
		ev = append(ev, Evidence{Kind: "change", Ref: "upgrade", Summary: t7Cut(t7Str(em["summary"]), 120) + "，时间 " + t7When(t7Str(em["at"]))})
	}
	return ev, false, notes
}
