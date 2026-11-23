package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// L3 自由排查：模型自主选择只读工具、多步取证，最后输出带证据和已排除项的结论 JSON。
// 任何异常（格式连错、超时、超步数、超 token、结论不合法、编造数字、模型报错）都降档为 L2 排查树。

const (
	t7MaxRounds       = 10 // 预取证据后一般 2~4 轮就能收；第 10 轮后强制收尾
	t7AgentTimeout    = 180 * time.Second
	t7TokenBudget     = 100000           // 累计口径（每轮都重算上下文）；预取证据会抬高每轮的 prompt
	t7WrapUpRemain    = 45 * time.Second // 剩余时间不足时不再放行新的工具轮，强制模型收尾
	t7RetryMinRemain  = 25 * time.Second // 剩余时间少于此值不再重试模型调用
	t7ParallelTools   = 2                // 与只读执行器 MaxConns=2 对齐
	t7PrefetchViewLen = 5000             // 预取结果喂给模型时的字数上限（Steps 里保留完整输出供事实校验）
	t7MaxBadCalls     = 2
	t7FallbackTimeout = 90 * time.Second
	t7MaxRawBytes     = 2048
)

// t7RetryBackoff 是模型调用失败后重试前的等待；测试里会调小。
var t7RetryBackoff = 800 * time.Millisecond

const t7SystemPrompt = `你是 JJDGuard 网关的值班排障工程师，正在帮客户排查网关使用中的故障。

工作方法：
0. 系统已经按输入类型预先调用了几个常用工具，结果就在对话里（对象详情、同类请求统计、前后对比、近期变更等）。先读完这些结果再决定下一步：证据已经够下结论就直接输出，不要重复调用已经查过的工具；还缺证据时，把需要的工具放在同一轮里一起调用，不要一个一个地调。
1. 先看现场：弄清楚输入里是请求编号、用户、模型、渠道，还是一段报错或一个问题；有请求编号就先查这条请求。
2. 提出 2 到 3 个怀疑方向（例如网关限流或额度、上游限流或欠费、上游参数不兼容、渠道凭据、模型未配置或无权限、网关自身缺陷）。
3. 调用工具逐个找证据，并逐个排除不成立的方向，每排除一个都要有依据。
4. 重点追问两件事：问题从什么时候开始，那时候变了什么。用 change_timeline 和 compare_windows 回答，不要只看单条请求。
5. 区分网关自身拦截（rate_limited、quota_exceeded）和上游返回的错误（带上游状态码），不要混为一谈。凡是提到额度、配额、限流的结论，title 里必须写明是“网关”侧还是“上游”侧。

硬性规则：
- 只能使用工具返回的事实。结论里出现的数字、请求编号必须原样来自工具输出，不得编造、推算或四舍五入。
- 工具返回“未找到”或报错时，如实说明，不要猜测。
- 如果证据表明是网关自身缺陷或与上游不兼容，直接写“网关缺陷，请导出诊断包联系厂商”，不要把责任推给客户或上游。
- 欠费、额度耗尽、余额不足只能写 suspected：网关没有上游余额接口，只能凭错误特征（insufficient_quota、HTTP 402、整个渠道持续 429）推断，不得写成 confirmed，并在 excluded 里说明“无法直接查询上游余额”。
- 已被工具直接证实的事实（例如上游返回了哪个状态码、拒绝了哪个参数）单独写成一条 confirmed 结论；基于时间吻合等推断出来的原因另写一条 suspected 结论，不要把事实和推断合并成一条，也不要因为根因没查清就把已证实的事实降级。
- 代理类请求（endpoint_type=proxy）失败且没有上游状态码、上游/交付结局为 unknown 时：用 host_snapshot 核对 proxy-server、gateway-core 的 started_at；若 started_at 落在 [请求 created_at, created_at+latency_ms 毫秒（再加 5 秒）] 内，说明请求在网关服务重启（升级/发布）时被中断，这是直接证据，写 confirmed，title 写“该请求在网关服务重启时被中断”，建议“重新发起请求；如频繁发生，避开业务高峰做升级”；只有升级记录（change_timeline）而没有容器重启证据时才写 suspected。员工身份看不到宿主机，只能写 suspected，且不要提宿主机或容器细节。
- 证据不足时，level 必须是 unknown，并说明还缺什么证据；只有直接证据才能写 confirmed，靠推断的写 suspected。
- 全程用中文。上游英文报错原文只放进 evidence 的 raw 字段，title、impact、advice 里不要出现英文原文。
- 你只能读取数据，不能修改任何配置；建议只能写成让管理员去做的动作。

- 结论要精炼，输出越短越好：title 一句话；impact 一句话；advice 最多 3 条；excluded 每条一句、最多 4 条；evidence 最多 4 条，raw 只摘关键一行（不超过 200 字）；findings 只写与问题直接相关的结论，不要为凑数单列“缺少证据”的结论，证据缺口写进相关结论的 excluded 或 title。

最终回答只输出一个 JSON 对象，不要任何多余文字：
{"findings":[{"check_id":"简短英文标识","severity":"ok|warn|error","level":"confirmed|suspected|unknown","title":"一句话结论","impact":"影响面（条数、渠道、模型、用户数，必须来自工具输出）","advice":[{"text":"可执行的建议","link":"可选，控制台路由"}],"excluded":["已排除的可能及依据"],"evidence":[{"kind":"request|log|config|change|host","ref":"请求编号或对象 ID","summary":"证据一句话","raw":"可选，上游原文"}]}]}
每条 finding 必须有 evidence 和 excluded（level 为 unknown 时可以为空，但要在 title 里说明缺什么）。`

// ---------- 降档 ----------

type t7Degrade struct{ reason string }

func (e *t7Degrade) Error() string { return e.reason }

func t7Deg(format string, a ...any) error { return &t7Degrade{fmt.Sprintf(format, a...)} }

// RunAgent 执行 L3。成功返回 Tier=L3 的报告；降档时返回 Tier=L2 的报告，Degraded 写明原因，
// 且保留 L3 已经查过的 steps。只有上层 ctx 被取消时才返回 error。
func RunAgent(ctx context.Context, m LLM, q Querier, reg *Registry, s Scope, in Input, history []Msg, progress func(Step)) (*Report, error) {
	started := time.Now()
	if m == nil {
		return t7Fallback(ctx, q, reg, s, in, nil, "没有可用的模型，已改用固定排查"), nil
	}
	lctx, cancel := context.WithTimeout(ctx, t7AgentTimeout)
	defer cancel()

	steps, findings, err := t7Loop(lctx, m, q, reg, s, in, history, progress)
	if err == nil {
		rep := &Report{ID: t7NewID(), Tier: TierL3, Findings: findings, Steps: steps, StartedAt: started, FinishedAt: time.Now()}
		if ferr := FactCheck(t7WithInputFacts(rep, in)); ferr != nil {
			err = t7Deg("智能排查结论包含未经查证的数字，已改用固定排查")
		} else {
			return rep, nil
		}
	}
	if ctx.Err() != nil { // 调用方主动取消
		return nil, ctx.Err()
	}
	var d *t7Degrade
	reason := "智能排查未能完成，已改用固定排查"
	if errors.As(err, &d) {
		reason = d.reason
	}
	return t7Fallback(ctx, q, reg, s, in, steps, reason), nil
}

func t7Fallback(ctx context.Context, q Querier, reg *Registry, s Scope, in Input, l3Steps []Step, reason string) *Report {
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), t7FallbackTimeout)
	defer cancel()
	rep, _ := RunTree(fctx, q, reg, s, in, nil)
	if rep == nil {
		rep = &Report{ID: t7NewID(), Tier: TierL2, Findings: []Finding{}, StartedAt: time.Now(), FinishedAt: time.Now()}
	}
	rep.Tier = TierL2
	if rep.Degraded != "" && rep.Degraded != reason {
		reason += "；" + rep.Degraded
	}
	rep.Degraded = reason
	rep.Steps = append(append([]Step{}, l3Steps...), rep.Steps...)
	return rep
}

// t7WithInputFacts 返回仅供事实校验使用的报告副本：用户原话里出现的数字、请求编号
// （例如“一直 403”）也是有据可查的事实，结论复述它们不算编造。不改动原报告的 Steps。
func t7WithInputFacts(rep *Report, in Input) *Report {
	b, _ := json.Marshal(map[string]string{"text": in.Text, "ref": in.Ref})
	cp := *rep
	cp.Steps = append(append([]Step{}, rep.Steps...), Step{Tool: "user_input", Output: b})
	return &cp
}

// ---------- 主循环 ----------

func t7Describe(s Scope, in Input, prefetched bool) string {
	var b strings.Builder
	role := "员工（只能查自己的请求）"
	if s.IsAdmin {
		role = "管理员"
	}
	fmt.Fprintf(&b, "当前时间：%s\n提问者身份：%s\n", time.Now().Format(time.RFC3339), role)
	fmt.Fprintf(&b, "输入类型：%s\n", t7KindLabel(in.Kind))
	if in.Ref != "" {
		fmt.Fprintf(&b, "已解析出的对象：%s\n", in.Ref)
	}
	wh := in.WindowH
	if wh <= 0 {
		wh = 1
	}
	fmt.Fprintf(&b, "默认统计窗口：%d 小时\n", wh)
	if strings.TrimSpace(in.Text) != "" {
		b.WriteString("用户原文：\n" + in.Text + "\n")
	}
	if prefetched {
		b.WriteString("\n系统已先调用了几个常用只读工具，结果见下面的工具消息。请基于这些证据排查：够了就直接输出 JSON 结论；还缺证据就在同一轮里并行调用需要的工具，最后按要求输出 JSON 结论。")
	} else {
		b.WriteString("\n请开始排查，需要数据时调用工具（需要多个时放在同一轮并行调用），最后按要求输出 JSON 结论。")
	}
	return b.String()
}

func t7KindLabel(k string) string {
	switch k {
	case "request":
		return "请求编号（request）"
	case "user":
		return "用户（user）"
	case "model":
		return "模型（model）"
	case "provider":
		return "渠道（provider）"
	case "health":
		return "一键体检（health）"
	}
	return "自然语言问题（question）"
}

func t7ToolSpecs(tools []Tool) []ToolSpec {
	out := make([]ToolSpec, 0, len(tools))
	for _, t := range tools {
		out = append(out, ToolSpec{Name: t.Name(), Description: t.Description(), Schema: t.Schema()})
	}
	return out
}

func t7SystemWithTools(tools []Tool) string {
	var b strings.Builder
	b.WriteString(t7SystemPrompt)
	b.WriteString("\n\n可用工具及用途：\n")
	for _, t := range tools {
		fmt.Fprintf(&b, "- %s：%s\n", t.Name(), t.Description())
	}
	return b.String()
}

func t7IsObject(raw json.RawMessage) bool {
	t := strings.TrimSpace(string(raw))
	return t != "" && t[0] == '{' && json.Valid([]byte(t))
}

const t7ErrBadArgs = "参数必须是 JSON 对象"

const t7WrapUpMsg = "证据已经足够，或排查时间/步数即将用完。请不要再调用任何工具，现在就基于已有证据输出最终 JSON 结论；证据不足的地方把 level 写成 unknown 并说明还缺什么。"

// t7ExecCalls 执行一批工具调用：最多 t7ParallelTools 个并发（与只读执行器 MaxConns=2 对齐），
// 返回结果与 calls 一一对应、顺序一致；每个调用完成时立刻回调 live（进度实时输出）。
func t7ExecCalls(ctx context.Context, q Querier, reg *Registry, s Scope, calls []ToolCall, live func(Step)) []Step {
	out := make([]Step, len(calls))
	sem := make(chan struct{}, t7ParallelTools)
	var wg sync.WaitGroup
	for i := range calls {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			c := calls[i]
			args := c.Args
			if strings.TrimSpace(string(args)) == "" {
				args = json.RawMessage(`{}`)
			}
			var st Step
			if !t7IsObject(args) {
				st = Step{Tool: c.Name, Args: json.RawMessage(`{}`), Summary: "工具调用格式有误", Err: t7ErrBadArgs}
			} else {
				st = reg.Call(ctx, q, s, c.Name, args)
				st.Summary = t7StepSummary(c.Name, args)
				if st.Err == ErrUnknownTool.Error() {
					st.Summary = "工具调用格式有误"
				}
			}
			out[i] = st
			if live != nil {
				live(st)
			}
		}(i)
	}
	wg.Wait()
	return out
}

func t7ToolContent(st Step) string {
	if st.Err != "" {
		return "工具调用失败：" + st.Err
	}
	return string(st.Output)
}

func t7ViewCut(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…（以上为节选，完整数据已留存）"
}

func t7ToolsHave(tools []Tool, name string) bool {
	for _, t := range tools {
		if t.Name() == name {
			return true
		}
	}
	return false
}

func t7JSONArgs(m map[string]any) json.RawMessage {
	b, _ := json.Marshal(m)
	return b
}

func t7Clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// t7Prefetch 在模型开口之前并行跑几个廉价的确定性取证，结果作为第一轮上下文，
// 省掉模型逐个点工具的若干轮。有请求编号时先查这条请求，再用它的渠道/模型做同类统计、
// 前后对比和变更时间线；没有编号时按输入类型取统计、对比与变更。预取失败不影响后续（模型自己再查）。
// 返回的 calls 与 steps 一一对应；steps 会进入 Report.Steps，FactCheck 能核对到其中的数字。
func t7Prefetch(ctx context.Context, q Querier, reg *Registry, s Scope, in Input, tools []Tool, live func(Step)) (calls []ToolCall, steps []Step, extra string) {
	n := 0
	run := func(batch []ToolCall) []Step {
		for i := range batch {
			n++
			batch[i].ID = fmt.Sprintf("pre_%d", n)
		}
		res := t7ExecCalls(ctx, q, reg, s, batch, live)
		calls = append(calls, batch...)
		steps = append(steps, res...)
		return res
	}
	call := func(name string, args map[string]any) ToolCall {
		return ToolCall{Name: name, Args: t7JSONArgs(args)}
	}

	wh := t7Clamp(in.WindowH, 1, 24)
	filter := map[string]any{}
	var tlArgs map[string]any
	var follow []ToolCall // 依据请求详情追加的取证（用户授权、渠道、路由、配额）

	reqID := reqIDRe.FindString(in.Ref)
	if reqID == "" {
		reqID = reqIDRe.FindString(in.Text)
	}
	// 体检 / 无对象的自然语言问题：直接跑确定性体检项（与 L2 同一批检查），
	// 省掉模型逐项点配置工具的几十秒；未发现问题的方向模型仍可自己继续查。
	if reqID == "" && (in.Kind == "health" || in.Kind == "question" || in.Kind == "") {
		fs, okCount, hs := RunChecks(ctx, q, s, in, nil)
		for _, st := range hs {
			steps = append(steps, st)
			if live != nil {
				live(st)
			}
		}
		return nil, steps, t7HealthContext(fs, okCount)
	}
	switch {
	case reqID != "" && t7ToolsHave(tools, "get_request"):
		res := run([]ToolCall{call("get_request", map[string]any{"request_id": reqID})})[0]
		if res.Err == "" {
			var o struct {
				Found   bool           `json:"found"`
				Request map[string]any `json:"request"`
			}
			if json.Unmarshal(res.Output, &o) == nil && o.Found {
				if p := t7Str(o.Request["provider_id"]); p != "" {
					filter["provider"] = p
				}
				if m := t7Str(o.Request["model_id"]); m != "" {
					filter["model"] = m
				}
				if s.IsAdmin {
					uid, mname := t7Str(o.Request["user_id"]), t7Str(o.Request["model_name"])
					cat := t7Str(o.Request["failure_category"])
					up := t7Num(o.Request["upstream_status_code"])
					if uid != "" {
						ua := map[string]any{"user": uid}
						if mname != "" {
							ua["model"] = mname
						}
						follow = append(follow, call("get_user_access", ua))
						if strings.Contains(cat, "quota") || strings.Contains(cat, "rate") {
							follow = append(follow, call("get_quota_policies", map[string]any{"user": uid}))
						}
					}
					if p := t7Str(o.Request["provider_id"]); p != "" && up > 0 {
						follow = append(follow, call("get_provider", map[string]any{"provider": p}))
					}
					if mname != "" && (up == 0 || strings.Contains(cat, "model") || strings.Contains(cat, "route")) {
						follow = append(follow, call("get_model_routes", map[string]any{"model": mname}))
					}
				}
				if at, err := time.Parse(time.RFC3339Nano, t7Str(o.Request["created_at"])); err == nil {
					age := time.Since(at)
					if age > 0 {
						wh = t7Clamp(int(age/time.Hour)+2, wh, 24)
					}
					if s.IsAdmin && age < 160*time.Hour {
						tlArgs = map[string]any{"around": at.UTC().Format(time.RFC3339), "window_hours": 6}
					}
				}
			}
		}
	case in.Kind == "user" && in.Ref != "":
		filter["user"] = in.Ref
	case in.Kind == "model" && in.Ref != "":
		filter["model"] = in.Ref
	case in.Kind == "provider" && in.Ref != "":
		filter["provider"] = in.Ref
	}
	withFilter := func(extra map[string]any) map[string]any {
		m := map[string]any{"window_hours": wh}
		for k, v := range filter {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	if tlArgs == nil {
		tlArgs = map[string]any{"window_hours": 24}
	}

	var batch []ToolCall
	add := func(name string, args map[string]any) {
		if t7ToolsHave(tools, name) {
			batch = append(batch, call(name, args))
		}
	}
	add("search_requests", withFilter(nil))
	add("compare_windows", withFilter(nil))
	add("change_timeline", tlArgs)
	for _, f := range follow {
		if t7ToolsHave(tools, f.Name) {
			batch = append(batch, f)
		}
	}
	switch in.Kind {
	case "user":
		if in.Ref != "" {
			add("get_user_access", map[string]any{"user": in.Ref})
			add("get_quota_policies", map[string]any{"user": in.Ref})
		}
	case "model":
		if in.Ref != "" {
			add("get_model_routes", map[string]any{"model": in.Ref})
		}
	case "provider":
		if in.Ref != "" {
			add("get_provider", map[string]any{"provider": in.Ref})
		}
	}
	if len(batch) > 0 && ctx.Err() == nil {
		run(batch)
	}
	return calls, steps, ""
}

// t7HealthContext 把体检结果压成给模型看的紧凑文本（完整输出在 Steps 里，FactCheck 能核对）。
func t7HealthContext(fs []Finding, okCount int) string {
	type ev struct {
		Ref     string `json:"ref,omitempty"`
		Summary string `json:"summary"`
	}
	type item struct {
		CheckID  string   `json:"check_id"`
		Severity string   `json:"severity"`
		Level    string   `json:"level"`
		Title    string   `json:"title"`
		Impact   string   `json:"impact,omitempty"`
		Excluded []string `json:"excluded,omitempty"`
		Evidence []ev     `json:"evidence,omitempty"`
	}
	items := make([]item, 0, len(fs))
	for _, f := range fs {
		it := item{CheckID: f.CheckID, Severity: string(f.Severity), Level: string(f.Level), Title: f.Title, Impact: f.Impact, Excluded: f.Excluded}
		for _, e := range f.Evidence {
			if len(it.Evidence) >= 4 {
				break
			}
			it.Evidence = append(it.Evidence, ev{Ref: e.Ref, Summary: e.Summary})
		}
		items = append(items, it)
	}
	b, _ := json.Marshal(map[string]any{"ok_count": okCount, "findings": items})
	return "系统已先跑完固定体检（结果见下，ok_count 为通过的检查项数；完整原始输出已留存供核对）：\n" +
		t7ViewCut(string(b), 7000) +
		"\n请基于这份体检结果排查：体检已发现的问题要核实根因；体检未覆盖或证据不足的方向，用工具继续查（需要多个时同一轮并行调用）。不要因为体检没有异常就跳过用户原话里提到的对象。"
}

// t7Retryable 判断模型调用失败是否值得重试一次：5xx / 429 / 408、连接与读取错误、
// 响应残缺、单次调用超时。4xx 参数类错误、不支持工具、整体已超时或被取消都不重试。
func t7Retryable(ctx context.Context, err error) bool {
	if err == nil || ctx.Err() != nil || errors.Is(err, ErrNoTools) {
		return false
	}
	var he *t8HTTPError
	if errors.As(err, &he) {
		return he.Status >= 500 || he.Status == 429 || he.Status == 408
	}
	return true
}

// t7Chat 调用模型；可重试的失败在总时限允许时退避后重试一次。
func t7Chat(ctx context.Context, m LLM, msgs []Msg, specs []ToolSpec) (Reply, error) {
	reply, err := m.Chat(ctx, msgs, specs)
	if err == nil || !t7Retryable(ctx, err) {
		return reply, err
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) < t7RetryMinRemain {
		return reply, err
	}
	select {
	case <-time.After(t7RetryBackoff):
	case <-ctx.Done():
		return reply, err
	}
	return m.Chat(ctx, msgs, specs)
}

func t7Loop(ctx context.Context, m LLM, q Querier, reg *Registry, s Scope, in Input, history []Msg, progress func(Step)) ([]Step, []Finding, error) {
	tools := reg.For(s)
	specs := t7ToolSpecs(tools)
	msgs := []Msg{{Role: "system", Content: t7SystemWithTools(tools)}}
	msgs = append(msgs, history...)

	var pmu sync.Mutex // progress 回调串行化：并发工具完成时各自实时回调
	live := func(st Step) {
		if progress == nil {
			return
		}
		pmu.Lock()
		defer pmu.Unlock()
		progress(st)
	}

	var steps []Step
	preCalls, preSteps, extra := t7Prefetch(ctx, q, reg, s, in, tools, live)
	steps = append(steps, preSteps...)
	msgs = append(msgs, Msg{Role: "user", Content: t7Describe(s, in, len(preCalls) > 0)})
	if extra != "" {
		msgs = append(msgs, Msg{Role: "user", Content: extra})
	}
	if len(preCalls) > 0 {
		msgs = append(msgs, Msg{Role: "assistant", ToolCalls: preCalls})
		for i, c := range preCalls {
			msgs = append(msgs, Msg{Role: "tool", ToolCallID: c.ID, Name: c.Name,
				Content: t7ViewCut(t7ToolContent(preSteps[i]), t7PrefetchViewLen)})
		}
	}

	tokens, toolRounds, bad := 0, 0, 0
	nudged := false

	for {
		if !nudged && (toolRounds >= t7MaxRounds || t7TimeLeft(ctx) < t7WrapUpRemain) {
			msgs = append(msgs, Msg{Role: "user", Content: t7WrapUpMsg})
			nudged = true
		}
		reply, err := t7Chat(ctx, m, msgs, specs)
		if err != nil {
			switch {
			case errors.Is(err, ErrNoTools):
				return steps, nil, t7Deg("所选模型不支持工具调用，已改用固定排查")
			case errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil:
				return steps, nil, t7Deg("智能排查超过 3 分钟仍未完成，已改用固定排查")
			}
			return steps, nil, t7Deg("调用智能排查模型失败，已改用固定排查")
		}
		tokens += reply.PromptTokens + reply.CompletionTokens
		if tokens > t7TokenBudget {
			return steps, nil, t7Deg("智能排查用量超出预算，已改用固定排查")
		}
		if len(reply.ToolCalls) == 0 {
			findings, perr := t7ParseFindings(reply.Content, s)
			if perr != nil {
				return steps, nil, t7Deg("智能排查的结论格式不合法（%s），已改用固定排查", perr.Error())
			}
			return steps, findings, nil
		}
		toolRounds++
		if toolRounds > t7MaxRounds {
			return steps, nil, t7Deg("智能排查超过 %d 步仍未得出结论，已改用固定排查", t7MaxRounds)
		}
		msgs = append(msgs, Msg{Role: "assistant", Content: reply.Content, ToolCalls: reply.ToolCalls})
		res := t7ExecCalls(ctx, q, reg, s, reply.ToolCalls, live)
		for i, st := range res {
			c := reply.ToolCalls[i]
			steps = append(steps, st)
			switch st.Err {
			case t7ErrBadArgs, ErrUnknownTool.Error():
				bad++
			case ErrForbidden.Error():
				// 被禁止的工具：把结果回给模型，不计入格式错误
			default:
				bad = 0
			}
			msgs = append(msgs, Msg{Role: "tool", ToolCallID: c.ID, Name: c.Name, Content: t7ToolContent(st)})
		}
		if bad >= t7MaxBadCalls {
			return steps, nil, t7Deg("智能排查连续 2 次调用工具格式有误，已改用固定排查")
		}
		if ctx.Err() != nil {
			return steps, nil, t7Deg("智能排查超过 3 分钟仍未完成，已改用固定排查")
		}
	}
}

func t7TimeLeft(ctx context.Context) time.Duration {
	if dl, ok := ctx.Deadline(); ok {
		return time.Until(dl)
	}
	return time.Hour
}

// ---------- 结论解析 ----------

// t7ExtractJSON 取出回答中的 JSON 对象，容忍 ``` 围栏与前后多余文字。
func t7ExtractJSON(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		if nl := strings.Index(rest, "\n"); nl >= 0 {
			rest = rest[nl+1:]
		}
		if j := strings.Index(rest, "```"); j >= 0 {
			s = strings.TrimSpace(rest[:j])
		}
	}
	a, b := strings.Index(s, "{"), strings.LastIndex(s, "}")
	if a >= 0 && b > a {
		return s[a : b+1]
	}
	return s
}

func t7ParseFindings(content string, s Scope) ([]Finding, error) {
	var out struct {
		Findings []Finding `json:"findings"`
	}
	if err := json.Unmarshal([]byte(t7ExtractJSON(content)), &out); err != nil {
		return nil, errors.New("不是合法 JSON")
	}
	if len(out.Findings) == 0 {
		return nil, errors.New("没有给出任何结论")
	}
	for i := range out.Findings {
		f := &out.Findings[i]
		f.Title = strings.TrimSpace(f.Title)
		if f.Title == "" {
			return nil, errors.New("结论缺少标题")
		}
		switch f.Level {
		case LevelConfirmed, LevelSuspected, LevelUnknown:
		default:
			return nil, errors.New("结论级别不合法")
		}
		if f.Level != LevelUnknown && (len(f.Evidence) == 0 || len(f.Excluded) == 0) {
			return nil, errors.New("结论缺少证据或已排除项")
		}
		if f.CheckID == "" {
			f.CheckID = "ai_finding"
		}
		t7CapUpstreamBilling(f)
		switch f.Severity {
		case SevOK, SevWarn, SevError:
		default:
			f.Severity = SevWarn
		}
		if f.Advice == nil {
			f.Advice = []Advice{}
		}
		if !s.IsAdmin { // 员工看不到后台链接
			for j := range f.Advice {
				f.Advice[j].Link = ""
			}
		}
		if f.Excluded == nil {
			f.Excluded = []string{}
		}
		if f.Evidence == nil {
			f.Evidence = []Evidence{}
		}
		for j := range f.Evidence {
			e := &f.Evidence[j]
			if len(e.Raw) > t7MaxRawBytes {
				e.Raw = e.Raw[:t7MaxRawBytes]
			}
			e.Raw = Redact(e.Raw)
		}
	}
	return out.Findings, nil
}

// t7CapUpstreamBilling：网关看不到上游账户余额，"上游欠费/额度耗尽"最多只能是疑似。
// 网关侧的额度、钱包余额由网关自己判定，可以是确定，所以标题带"网关"的不降级。
func t7CapUpstreamBilling(f *Finding) {
	if f.Level != LevelConfirmed || strings.Contains(f.Title, "网关") {
		return
	}
	if !strings.Contains(f.Title, "上游") && !strings.Contains(f.Title, "渠道") {
		return
	}
	for _, k := range []string{"欠费", "余额不足", "额度不足", "额度耗尽", "额度用完", "充值"} {
		if strings.Contains(f.Title, k) {
			f.Level = LevelSuspected
			return
		}
	}
}
