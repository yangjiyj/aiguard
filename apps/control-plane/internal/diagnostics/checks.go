package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"unicode/utf8"
)

// L1 检查项：每项只读、互相独立；请求类检查共享一次聚合查询（见 checks_requests.go）。

type Check struct {
	ID        string
	Category  string // request | config | host
	AdminOnly bool
	Run       func(ctx context.Context, q Querier, s Scope, in Input, host *HostView) ([]Finding, error)

	summary string
	run     t6RunFn
}

type t6Result struct {
	Findings []Finding
	Data     any // 该检查用到的原始聚合数据，写入 Step.Output 供 FactCheck 使用
}

type t6RunFn func(ctx context.Context, e *t6Env, q Querier, s Scope, in Input, host *HostView) (t6Result, error)

// t6ErrSkip 表示该检查因前置条件不满足而跳过（不计入正常项）。
var t6ErrSkip = errors.New("检查已跳过")

func t6Def(id, category string, adminOnly bool, summary string, fn t6RunFn) Check {
	return Check{
		ID: id, Category: category, AdminOnly: adminOnly, summary: summary, run: fn,
		Run: func(ctx context.Context, q Querier, s Scope, in Input, host *HostView) ([]Finding, error) {
			res, err := fn(ctx, &t6Env{}, q, s, in, host)
			if errors.Is(err, t6ErrSkip) {
				return nil, nil
			}
			return res.Findings, err
		},
	}
}

// t6Env 在一次 RunChecks 内缓存请求聚合。
type t6Env struct {
	agg     *t6Agg
	err     error
	loaded  bool
	fresh   bool // 本次检查刚加载了聚合，需要补一条 Step
	aggStep Step
}

func (e *t6Env) load(ctx context.Context, q Querier, s Scope, in Input) (*t6Agg, error) {
	if e.loaded {
		return e.agg, e.err
	}
	e.loaded, e.fresh = true, true
	e.agg, e.err = t6LoadRequestAgg(ctx, q, s, in)
	e.aggStep = Step{Tool: "check:request_agg", Args: json.RawMessage(`{}`), Summary: "汇总窗口内的请求数据"}
	if e.err != nil {
		e.aggStep.Err = e.err.Error()
	} else {
		e.aggStep.Output = t6AggOutput(e.agg)
	}
	return e.agg, e.err
}

// AllChecks 返回全部 L1 检查项（顺序固定）。
func AllChecks() []Check {
	return []Check{
		t6Def("gw_rate_limited", "request", false, "检查网关限流", t6CheckGwRateLimited),
		t6Def("gw_quota", "request", false, "检查额度与预算", t6CheckGwQuota),
		t6Def("up_429", "request", false, "检查上游限流与欠费", t6CheckUp429),
		t6Def("up_5xx", "request", false, "检查上游服务异常", t6CheckUp5xx),
		t6Def("up_param", "request", false, "检查上游参数拒绝", t6CheckUpParam),
		t6Def("timeout", "request", false, "检查请求超时", t6CheckTimeout),
		t6Def("auth_failed", "request", false, "检查上游鉴权", t6CheckAuthFailed),
		t6Def("model_missing", "request", false, "检查模型配置", t6CheckModelMissing),
		t6Def("key_model_allowlist", "request", false, "检查密钥模型白名单", t6CheckKeyModelDenied),
		t6Def("security_block", "request", false, "检查安全拦截", t6CheckSecurityBlock),
		t6Def("stream_abort", "request", false, "检查流式中断", t6CheckStreamAbort),
		t6Def("license", "config", true, "检查授权状态", t6CheckLicense),
		t6Def("provider_down", "config", true, "检查渠道状态与路由", t6CheckProviderDown),
		t6Def("no_route", "config", true, "检查模型可用渠道", t6CheckNoRoute),
		t6Def("host_container", "host", true, "检查容器运行状态", t6CheckHostContainer),
		t6Def("host_drift", "host", true, "检查配置漂移", t6CheckHostDrift),
		t6Def("host_disk", "host", true, "检查磁盘使用率", t6CheckHostDisk),
		t6Def("host_cert", "host", true, "检查证书有效期", t6CheckHostCert),
		t6Def("agent_missing", "host", true, "检查宿主机采集器", t6CheckAgentMissing),
	}
}

// RunChecks 执行全部适用的检查项。员工跳过 AdminOnly 检查；单项报错只记入该 Step。
func RunChecks(ctx context.Context, q Querier, s Scope, in Input, host *HostView) (findings []Finding, okCount int, steps []Step) {
	env := &t6Env{}
	for _, c := range AllChecks() {
		if c.AdminOnly && !s.IsAdmin {
			continue
		}
		if ctx.Err() != nil {
			break
		}
		env.fresh = false
		res, err := t6SafeRun(ctx, c, env, q, s, in, host)
		if env.fresh {
			steps = append(steps, env.aggStep)
			env.fresh = false
		}
		step := Step{Tool: "check:" + c.ID, Args: json.RawMessage(`{}`), Summary: c.summary}
		switch {
		case errors.Is(err, t6ErrSkip):
			step.Summary += "（已跳过）"
			step.Output = t6JSON(map[string]any{"skipped": true})
		case err != nil:
			step.Err = err.Error()
		default:
			step.Output = t6JSON(res.Data)
			if len(res.Findings) == 0 {
				okCount++
			} else {
				findings = append(findings, res.Findings...)
			}
		}
		steps = append(steps, step)
	}
	sort.SliceStable(findings, func(i, j int) bool { return t6SevRank(findings[i].Severity) > t6SevRank(findings[j].Severity) })
	return findings, okCount, steps
}

func t6SafeRun(ctx context.Context, c Check, e *t6Env, q Querier, s Scope, in Input, host *HostView) (res t6Result, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("检查 %s 异常: %v", c.ID, r)
		}
	}()
	return c.run(ctx, e, q, s, in, host)
}

func t6SevRank(s Severity) int {
	switch s {
	case SevError:
		return 2
	case SevWarn:
		return 1
	}
	return 0
}

// t6JSON 序列化并脱敏；超过工具输出上限时返回截断标记。
func t6JSON(v any) json.RawMessage {
	if v == nil {
		return json.RawMessage(`{}`)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{"error":"序列化失败"}`)
	}
	red := Redact(string(b))
	if !json.Valid([]byte(red)) {
		return json.RawMessage(`{"redacted":true}`)
	}
	if len(red) > MaxToolOutput {
		part := []rune(red)
		trunc, _ := json.Marshal(map[string]any{"truncated": true, "partial": string(part[:MaxToolOutput/4])})
		return trunc
	}
	return json.RawMessage(red)
}

// ---------- 公共构造辅助 ----------

func t6Find(id string, sev Severity, lv Level, title, impact string, adv []Advice, excl []string, ev []Evidence) Finding {
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

// t6Adv 构造建议：管理员带控制台链接；员工转为"请联系管理员"且不带后台链接。
func t6Adv(s Scope, text, link string) Advice {
	if !s.IsAdmin {
		return Advice{Text: "请联系管理员处理：" + text}
	}
	return Advice{Text: text, Link: link}
}

func t6RecordsLink(id string) string {
	if id == "" {
		return "/cost/records"
	}
	return "/cost/records?request_id=" + url.QueryEscape(id)
}

func t6RecordsAdvice(ids []string) []Advice {
	if len(ids) == 0 {
		return nil
	}
	return []Advice{{Text: "在调用明细中查看示例请求", Link: t6RecordsLink(ids[0])}}
}

func t6Raw(s string) string {
	if utf8.RuneCountInString(s) > 500 {
		s = string([]rune(s)[:500]) + "…"
	}
	return Redact(s)
}

func t6ReqEvidence(ids []string, summary, raw string) []Evidence {
	var out []Evidence
	for i, id := range ids {
		e := Evidence{Kind: "request", Ref: id, Summary: summary}
		if i == 0 && raw != "" {
			e.Raw = t6Raw(raw)
		}
		out = append(out, e)
	}
	return out
}

func t6Pct(n, total int64) int64 {
	if total <= 0 {
		return 0
	}
	return (n*100 + total/2) / total
}
