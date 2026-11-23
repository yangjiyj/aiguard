package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- 假 LLM / 假工具 / 无库 Querier ----------

type t7LLM struct {
	mu    sync.Mutex
	fn    func(i int, msgs []Msg, tools []ToolSpec) (Reply, error)
	calls int
	tools []ToolSpec
	last  []Msg
}

func (l *t7LLM) Chat(_ context.Context, msgs []Msg, tools []ToolSpec) (Reply, error) {
	l.mu.Lock()
	i := l.calls
	l.calls++
	l.tools = tools
	l.last = msgs
	l.mu.Unlock()
	return l.fn(i, msgs, tools)
}

func t7Script(replies ...Reply) *t7LLM {
	return &t7LLM{fn: func(i int, _ []Msg, _ []ToolSpec) (Reply, error) {
		if i >= len(replies) {
			return replies[len(replies)-1], nil
		}
		return replies[i], nil
	}}
}

type t7NoDB struct{}

func (t7NoDB) Query(context.Context, string, ...any) ([]map[string]any, error) {
	return nil, errors.New("no db in this test")
}

type t7FakeTool struct {
	name  string
	admin bool
	out   string
}

func (t t7FakeTool) Name() string        { return t.name }
func (t t7FakeTool) Description() string { return "测试工具 " + t.name }
func (t t7FakeTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{}}`)
}
func (t t7FakeTool) AdminOnly() bool { return t.admin }
func (t t7FakeTool) Run(context.Context, Querier, Scope, json.RawMessage) (json.RawMessage, error) {
	return json.RawMessage(t.out), nil
}

const (
	t7ReqID  = "req_11111111-2222-4333-8444-555555555555"
	t7ReqBad = "req_99999999-2222-4333-8444-555555555555"
)

func t7AgentReg() *Registry {
	return NewRegistry(
		t7FakeTool{name: "get_request", out: `{"found":true,"request":{"request_id":"` + t7ReqID + `","upstream_status_code":429,"count":7}}`},
		t7FakeTool{name: "change_timeline", admin: true, out: `{"events":[]}`},
	)
}

func t7Call(id, name, args string) Reply {
	return Reply{ToolCalls: []ToolCall{{ID: id, Name: name, Args: json.RawMessage(args)}}, PromptTokens: 100, CompletionTokens: 10}
}

func t7Final(s string) Reply { return Reply{Content: s, PromptTokens: 100, CompletionTokens: 50} }

func t7FinalJSON(title, ref string) string {
	b, _ := json.Marshal(map[string]any{"findings": []Finding{{
		CheckID: "up_429", Severity: SevError, Level: LevelConfirmed, Title: title, Impact: "同渠道共 7 条",
		Advice:   []Advice{{Text: "降低并发"}},
		Excluded: []string{"已排除网关限流：该请求没有拦截记录"},
		Evidence: []Evidence{{Kind: "request", Ref: ref, Summary: "上游返回 429"}},
	}}})
	return string(b)
}

var t7Admin = Scope{TenantID: "t7ten", IsAdmin: true}
var t7Staff = Scope{TenantID: "t7ten", UserID: "u1"}
var t7In = Input{Kind: "request", Ref: t7ReqID, Text: "报错 " + t7ReqID}

func t7RunAgent(t *testing.T, m LLM, s Scope, progress func(Step)) *Report {
	t.Helper()
	rep, err := RunAgent(context.Background(), m, t7NoDB{}, t7AgentReg(), s, t7In, nil, progress)
	if err != nil {
		t.Fatal(err)
	}
	if rep == nil {
		t.Fatal("report 为空")
	}
	return rep
}

func t7AssertDegraded(t *testing.T, rep *Report, want string) {
	t.Helper()
	if rep.Tier != TierL2 {
		t.Fatalf("应降为 L2: %v", rep.Tier)
	}
	if !strings.Contains(rep.Degraded, want) {
		t.Fatalf("Degraded=%q，应包含 %q", rep.Degraded, want)
	}
	if len(rep.Findings) == 0 {
		t.Errorf("降档后仍应有 L2 结论")
	}
}

// ---------- 用例 ----------

func TestT7AgentNormal(t *testing.T) {
	llm := t7Script(t7Call("c1", "get_request", `{"request_id":"`+t7ReqID+`"}`),
		t7Final("```json\n"+t7FinalJSON("上游限流：返回 HTTP 429（请求频率过高）", t7ReqID)+"\n```"))
	var progress []Step
	rep := t7RunAgent(t, llm, t7Admin, func(s Step) { progress = append(progress, s) })
	if rep.Tier != TierL3 || rep.Degraded != "" {
		t.Fatalf("应为 L3 正常结论: tier=%v degraded=%q", rep.Tier, rep.Degraded)
	}
	if len(rep.Findings) != 1 || rep.Findings[0].Level != LevelConfirmed || len(rep.Findings[0].Evidence) == 0 {
		t.Errorf("结论: %+v", rep.Findings)
	}
	// 预取 2 步（get_request、change_timeline）+ 模型自己调的 1 步，每步都实时回调
	if len(progress) != 3 || progress[0].Tool != "get_request" || progress[0].Summary != "正在查这条请求的完整链路" {
		t.Errorf("progress 应回调 3 次（预取 2 + 模型 1）: %+v", progress)
	}
	if len(rep.Steps) != 3 {
		t.Errorf("steps=%d", len(rep.Steps))
	}
	// 系统提示词与工具
	sys := llm.last[0].Content
	for _, kw := range []string{"值班排障工程师", "网关缺陷，请导出诊断包联系厂商", "unknown", "change_timeline", "get_request"} {
		if !strings.Contains(sys, kw) {
			t.Errorf("系统提示词缺少 %q", kw)
		}
	}
	if len(llm.tools) != 2 {
		t.Errorf("管理员应拿到 2 个工具: %d", len(llm.tools))
	}
	// 用户消息带上原文
	user := llm.last[1].Content
	if !strings.Contains(user, t7ReqID) || !strings.Contains(user, "request") {
		t.Errorf("用户消息缺少输入描述: %s", user)
	}
}

func TestT7AgentHistoryIncluded(t *testing.T) {
	llm := t7Script(t7Final(t7FinalJSON("x", t7ReqID)))
	_, _ = RunAgent(context.Background(), llm, t7NoDB{}, t7AgentReg(), t7Admin, t7In,
		[]Msg{{Role: "user", Content: "上一轮的问题"}, {Role: "assistant", Content: "上一轮的回答"}}, nil)
	if len(llm.last) < 4 || llm.last[1].Content != "上一轮的问题" || llm.last[2].Content != "上一轮的回答" || !strings.Contains(llm.last[3].Content, "用户原文") {
		t.Errorf("历史应放在系统提示之后、本轮输入之前: %+v", llm.last)
	}
}

func TestT7AgentFabricatedIDDegrades(t *testing.T) {
	llm := t7Script(t7Call("c1", "get_request", `{"request_id":"`+t7ReqID+`"}`),
		t7Final(t7FinalJSON("上游限流", t7ReqBad)))
	rep := t7RunAgent(t, llm, t7Admin, nil)
	t7AssertDegraded(t, rep, "智能排查结论包含未经查证的数字，已改用固定排查")
	if len(rep.Steps) == 0 || rep.Steps[0].Tool != "get_request" {
		t.Errorf("降档后应保留 L3 已查过的步骤: %v", t7StepTools(rep))
	}
}

func TestT7AgentFabricatedNumberDegrades(t *testing.T) {
	llm := t7Script(t7Call("c1", "get_request", `{"request_id":"`+t7ReqID+`"}`),
		t7Final(t7FinalJSON("上游限流：共 8888 条请求被拒", t7ReqID)))
	t7AssertDegraded(t, t7RunAgent(t, llm, t7Admin, nil), "未经查证")
}

func TestT7AgentTooManySteps(t *testing.T) {
	llm := &t7LLM{fn: func(i int, _ []Msg, _ []ToolSpec) (Reply, error) {
		return t7Call("c", "get_request", `{"request_id":"`+t7ReqID+`"}`), nil
	}}
	n := 0
	rep := t7RunAgent(t, llm, t7Admin, func(Step) { n++ })
	t7AssertDegraded(t, rep, "10 步")
	if n != 12 { // 预取 2 步 + 10 轮
		t.Errorf("progress 应回调 12 次: %d", n)
	}
	if len(rep.Steps) < 12 {
		t.Errorf("应保留 L3 的 12 个步骤: %d", len(rep.Steps))
	}
}

func TestT7AgentBadToolArgsTwiceDegrades(t *testing.T) {
	llm := t7Script(t7Call("c1", "get_request", `not json`), t7Call("c2", "get_request", `[1,2]`),
		t7Final(t7FinalJSON("x", t7ReqID)))
	n := 0
	rep := t7RunAgent(t, llm, t7Admin, func(Step) { n++ })
	t7AssertDegraded(t, rep, "连续 2 次")
	if n != 4 { // 预取 2 步 + 两次错误调用
		t.Errorf("两次错误调用都应回调 progress: %d", n)
	}
	// 一次错误后恢复，不降档
	llm = t7Script(t7Call("c1", "get_request", `oops`), t7Call("c2", "get_request", `{"request_id":"`+t7ReqID+`"}`),
		t7Final(t7FinalJSON("上游限流", t7ReqID)))
	if rep = t7RunAgent(t, llm, t7Admin, nil); rep.Tier != TierL3 {
		t.Errorf("间隔的单次错误不应降档: %q", rep.Degraded)
	}
}

func TestT7AgentUnknownToolTwiceDegrades(t *testing.T) {
	llm := t7Script(t7Call("c1", "rm_rf", `{}`), t7Call("c2", "drop_table", `{}`), t7Final("x"))
	t7AssertDegraded(t, t7RunAgent(t, llm, t7Admin, nil), "连续 2 次")
}

func TestT7AgentStaffForbiddenToolContinues(t *testing.T) {
	llm := t7Script(
		t7Call("c1", "change_timeline", `{}`), t7Call("c2", "change_timeline", `{}`), // 连续两次被拒不算格式错误
		t7Call("c3", "get_request", `{"request_id":"`+t7ReqID+`"}`),
		t7Final(t7FinalJSON("上游限流", t7ReqID)))
	var steps []Step
	rep := t7RunAgent(t, llm, t7Staff, func(s Step) { steps = append(steps, s) })
	if rep.Tier != TierL3 {
		t.Fatalf("被拒后应继续而不是降档: %q", rep.Degraded)
	}
	if len(llm.tools) != 1 || llm.tools[0].Name != "get_request" {
		t.Errorf("员工只应拿到员工可用工具: %+v", llm.tools)
	}
	// 员工拿不到 change_timeline：预取只有 get_request 1 步，之后是 2 次被拒 + 1 次成功
	if len(steps) != 4 || steps[0].Err != "" || steps[1].Err != ErrForbidden.Error() {
		t.Errorf("被拒绝的调用应写入 Step.Err: %+v", steps)
	}
	// 被拒结果回给模型
	found := false
	for _, m := range llm.last {
		if m.Role == "tool" && strings.Contains(m.Content, ErrForbidden.Error()) {
			found = true
		}
	}
	if !found {
		t.Errorf("forbidden 应作为工具结果回给模型")
	}
}

func TestT7AgentDegradeReasons(t *testing.T) {
	cases := []struct {
		name string
		llm  *t7LLM
		want string
	}{
		{"ErrNoTools", &t7LLM{fn: func(int, []Msg, []ToolSpec) (Reply, error) { return Reply{}, ErrNoTools }}, "不支持工具调用"},
		{"模型报错", &t7LLM{fn: func(int, []Msg, []ToolSpec) (Reply, error) { return Reply{}, errors.New("HTTP 500") }}, "调用智能排查模型失败"},
		{"最终不是 JSON", t7Script(t7Final("我觉得是上游的问题")), "格式不合法"},
		{"findings 为空", t7Script(t7Final(`{"findings":[]}`)), "格式不合法"},
		{"缺少证据", t7Script(t7Final(`{"findings":[{"check_id":"a","severity":"error","level":"confirmed","title":"上游有问题","impact":"","advice":[],"excluded":[],"evidence":[]}]}`)), "格式不合法"},
		{"级别非法", t7Script(t7Final(`{"findings":[{"check_id":"a","level":"sure","title":"x","evidence":[{"kind":"request","ref":"a","summary":"b"}],"excluded":["c"]}]}`)), "格式不合法"},
		{"超 token", &t7LLM{fn: func(int, []Msg, []ToolSpec) (Reply, error) {
			r := t7Call("c", "get_request", `{"request_id":"`+t7ReqID+`"}`)
			r.PromptTokens = 40000
			return r, nil
		}}, "超出预算"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t7AssertDegraded(t, t7RunAgent(t, c.llm, t7Admin, nil), c.want)
		})
	}
}

func TestT7AgentTimeoutDegrades(t *testing.T) {
	llm := &t7LLM{fn: func(int, []Msg, []ToolSpec) (Reply, error) { return Reply{}, context.DeadlineExceeded }}
	t7AssertDegraded(t, t7RunAgent(t, llm, t7Admin, nil), "3 分钟")
}

func TestT7AgentNilModelAndCancel(t *testing.T) {
	rep, err := RunAgent(context.Background(), nil, t7NoDB{}, t7AgentReg(), t7Admin, t7In, nil, nil)
	if err != nil || rep.Tier != TierL2 || rep.Degraded == "" {
		t.Errorf("无模型应直接降档: %+v %v", rep, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	llm := &t7LLM{fn: func(int, []Msg, []ToolSpec) (Reply, error) { return Reply{}, context.Canceled }}
	if _, err = RunAgent(ctx, llm, t7NoDB{}, t7AgentReg(), t7Admin, t7In, nil, nil); err == nil {
		t.Errorf("调用方取消应返回错误")
	}
}

func TestT7AgentStaffStripsLinks(t *testing.T) {
	js := `{"findings":[{"check_id":"a","severity":"error","level":"confirmed","title":"上游限流","impact":"","advice":[{"text":"降低并发","link":"/providers"}],"excluded":["已排除网关限流"],"evidence":[{"kind":"request","ref":"` + t7ReqID + `","summary":"429"}]}]}`
	llm := t7Script(t7Call("c1", "get_request", `{"request_id":"`+t7ReqID+`"}`), t7Final(js))
	rep := t7RunAgent(t, llm, t7Staff, nil)
	if rep.Tier != TierL3 || rep.Findings[0].Advice[0].Link != "" {
		t.Errorf("员工结论不应带后台链接: %+v", rep.Findings)
	}
}

// ---------- 提速改造：预取 / 并行 / 重试 / 收尾 ----------

func TestT7PrefetchRecordedAsStepsAndFedToModel(t *testing.T) {
	llm := t7Script(t7Final(t7FinalJSON("上游限流：共 7 条", t7ReqID)))
	rep := t7RunAgent(t, llm, t7Admin, nil)
	if rep.Tier != TierL3 {
		t.Fatalf("预取证据足够时模型 0 轮工具即可收尾: %q", rep.Degraded)
	}
	if llm.calls != 1 {
		t.Errorf("预取后模型应只调用 1 次: %d", llm.calls)
	}
	if got := t7StepTools(rep); len(got) != 2 || got[0] != "get_request" || got[1] != "change_timeline" {
		t.Errorf("预取应记成 Step 供 FactCheck: %v", got)
	}
	if rep.Steps[0].Output == nil {
		t.Errorf("预取 Step 应保留完整输出")
	}
	var toolMsgs int
	for _, m := range llm.last {
		if m.Role == "tool" && strings.HasPrefix(m.ToolCallID, "pre_") {
			toolMsgs++
		}
	}
	if toolMsgs != 2 {
		t.Errorf("预取结果应作为 tool 消息喂给模型: %d", toolMsgs)
	}
}

func TestT7MultiToolCallsRunInParallelAndKeepOrder(t *testing.T) {
	var mu sync.Mutex
	cur, peak := 0, 0
	slow := func(name string) Tool {
		return t7SlowTool{name: name, enter: func() {
			mu.Lock()
			cur++
			if cur > peak {
				peak = cur
			}
			mu.Unlock()
		}, leave: func() { mu.Lock(); cur--; mu.Unlock() }}
	}
	reg := NewRegistry(slow("a_tool"), slow("b_tool"), slow("c_tool"))
	calls := []ToolCall{{ID: "1", Name: "a_tool", Args: json.RawMessage(`{}`)}, {ID: "2", Name: "b_tool", Args: json.RawMessage(`{}`)}, {ID: "3", Name: "c_tool", Args: json.RawMessage(`{}`)}}
	var live int32
	var lmu sync.Mutex
	res := t7ExecCalls(context.Background(), t7NoDB{}, reg, t7Admin, calls, func(Step) { lmu.Lock(); live++; lmu.Unlock() })
	if len(res) != 3 || res[0].Tool != "a_tool" || res[1].Tool != "b_tool" || res[2].Tool != "c_tool" {
		t.Fatalf("结果顺序应与调用一致: %+v", res)
	}
	if peak != t7ParallelTools {
		t.Errorf("并发峰值应为 %d（与只读执行器连接数对齐）: %d", t7ParallelTools, peak)
	}
	if live != 3 {
		t.Errorf("每个工具完成都应实时回调: %d", live)
	}
}

type t7SlowTool struct {
	name         string
	enter, leave func()
}

func (t t7SlowTool) Name() string        { return t.name }
func (t t7SlowTool) Description() string { return "slow" }
func (t t7SlowTool) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{}}`)
}
func (t t7SlowTool) AdminOnly() bool { return false }
func (t t7SlowTool) Run(context.Context, Querier, Scope, json.RawMessage) (json.RawMessage, error) {
	t.enter()
	time.Sleep(60 * time.Millisecond)
	t.leave()
	return json.RawMessage(`{"ok":true}`), nil
}

func TestT7ModelRetryOnce(t *testing.T) {
	old := t7RetryBackoff
	t7RetryBackoff = time.Millisecond
	defer func() { t7RetryBackoff = old }()

	mk := func(first error) *t7LLM {
		return &t7LLM{fn: func(i int, _ []Msg, _ []ToolSpec) (Reply, error) {
			if i == 0 {
				return Reply{}, first
			}
			return t7Final(t7FinalJSON("上游限流：共 7 条", t7ReqID)), nil
		}}
	}
	for _, c := range []struct {
		name    string
		err     error
		retried bool
	}{
		{"502 重试", &t8HTTPError{Status: 502}, true},
		{"429 重试", &t8HTTPError{Status: 429}, true},
		{"连接错误重试", errors.New("调用模型失败: connection reset"), true},
		{"400 不重试", &t8HTTPError{Status: 400}, false},
		{"401 不重试", &t8HTTPError{Status: 401}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			llm := mk(c.err)
			rep := t7RunAgent(t, llm, t7Admin, nil)
			if c.retried && (rep.Tier != TierL3 || llm.calls != 2) {
				t.Errorf("应重试一次后成功: tier=%v calls=%d degraded=%q", rep.Tier, llm.calls, rep.Degraded)
			}
			if !c.retried && (rep.Tier != TierL2 || llm.calls != 1) {
				t.Errorf("不应重试: tier=%v calls=%d", rep.Tier, llm.calls)
			}
		})
	}
	// 连续两次失败：只重试一次，然后降档
	llm := &t7LLM{fn: func(int, []Msg, []ToolSpec) (Reply, error) { return Reply{}, &t8HTTPError{Status: 503} }}
	rep := t7RunAgent(t, llm, t7Admin, nil)
	t7AssertDegraded(t, rep, "调用智能排查模型失败")
	if llm.calls != 2 {
		t.Errorf("总共应调用 2 次: %d", llm.calls)
	}
	// 不支持工具：不重试
	llm = &t7LLM{fn: func(int, []Msg, []ToolSpec) (Reply, error) { return Reply{}, ErrNoTools }}
	t7AssertDegraded(t, t7RunAgent(t, llm, t7Admin, nil), "不支持工具调用")
	if llm.calls != 1 {
		t.Errorf("ErrNoTools 不应重试: %d", llm.calls)
	}
}

func TestT7NoRetryWhenTimeAlmostUp(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), t7RetryMinRemain-5*time.Second)
	defer cancel()
	llm := &t7LLM{fn: func(int, []Msg, []ToolSpec) (Reply, error) { return Reply{}, &t8HTTPError{Status: 500} }}
	if _, err := t7Chat(ctx, llm, nil, nil); err == nil || llm.calls != 1 {
		t.Errorf("剩余时间不足时不应重试: err=%v calls=%d", err, llm.calls)
	}
}

func TestT7WrapUpNudgeAfterMaxRounds(t *testing.T) {
	llm := &t7LLM{fn: func(i int, msgs []Msg, _ []ToolSpec) (Reply, error) {
		if last := msgs[len(msgs)-1]; last.Role == "user" && strings.Contains(last.Content, "不要再调用任何工具") {
			return t7Final(t7FinalJSON("上游限流：共 7 条", t7ReqID)), nil
		}
		return t7Call("c", "get_request", `{"request_id":"`+t7ReqID+`"}`), nil
	}}
	rep := t7RunAgent(t, llm, t7Admin, nil)
	if rep.Tier != TierL3 {
		t.Fatalf("达到轮次上限时应催促收尾而不是降档: %q", rep.Degraded)
	}
	if llm.calls != t7MaxRounds+1 {
		t.Errorf("模型调用次数: %d", llm.calls)
	}
}

func TestT7PrefetchNoRequestID(t *testing.T) {
	reg := NewRegistry(
		t7FakeTool{name: "search_requests", out: `{"total":3}`},
		t7FakeTool{name: "compare_windows", out: `{"a":1}`},
		t7FakeTool{name: "change_timeline", admin: true, out: `{"events":[]}`},
	)
	// 指定了对象（模型）：预取统计+对比+变更
	calls, steps, extra := t7Prefetch(context.Background(), t7NoDB{}, reg, t7Admin, Input{Kind: "model", Ref: "gpt-x"}, reg.For(t7Admin), nil)
	if len(calls) != 3 || len(steps) != 3 || extra != "" {
		t.Fatalf("按对象预取应为统计+对比+变更: %d/%d", len(calls), len(steps))
	}
	calls, _, _ = t7Prefetch(context.Background(), t7NoDB{}, reg, t7Staff, Input{Kind: "model", Ref: "gpt-x"}, reg.For(t7Staff), nil)
	if len(calls) != 2 {
		t.Errorf("员工不应预取管理员工具: %d", len(calls))
	}
	// 体检：直接跑固定体检项，步骤记为 check:*，并给模型一段体检上下文
	calls, steps, extra = t7Prefetch(context.Background(), t7NoDB{}, reg, t7Admin, Input{Kind: "health"}, reg.For(t7Admin), nil)
	if len(calls) != 0 || len(steps) == 0 || !strings.HasPrefix(steps[0].Tool, "check:") || !strings.Contains(extra, "固定体检") {
		t.Errorf("体检应预取固定体检项: calls=%d steps=%d extra=%q", len(calls), len(steps), extra)
	}
}

func TestT7PrefetchRequestFollowUps(t *testing.T) {
	req := `{"found":true,"request":{"request_id":"` + t7ReqID + `","user_id":"u9","model_name":"gpt-x","provider_id":"p9","failure_category":"rate_limited","upstream_status_code":429,"created_at":"` + time.Now().Add(-time.Hour).UTC().Format(time.RFC3339) + `"}}`
	reg := NewRegistry(
		t7FakeTool{name: "get_request", out: req},
		t7FakeTool{name: "search_requests", out: `{}`}, t7FakeTool{name: "compare_windows", out: `{}`},
		t7FakeTool{name: "change_timeline", admin: true, out: `{}`},
		t7FakeTool{name: "get_user_access", admin: true, out: `{}`}, t7FakeTool{name: "get_quota_policies", admin: true, out: `{}`},
		t7FakeTool{name: "get_provider", admin: true, out: `{}`}, t7FakeTool{name: "get_model_routes", admin: true, out: `{}`},
	)
	_, steps, _ := t7Prefetch(context.Background(), t7NoDB{}, reg, t7Admin, t7In, reg.For(t7Admin), nil)
	got := map[string]bool{}
	for _, st := range steps {
		got[st.Tool] = true
	}
	for _, w := range []string{"get_request", "search_requests", "compare_windows", "change_timeline", "get_user_access", "get_quota_policies", "get_provider"} {
		if !got[w] {
			t.Errorf("缺少预取 %s: %v", w, got)
		}
	}
	if got["get_model_routes"] {
		t.Errorf("上游限流类请求不需要预取模型路由")
	}
}

func TestT7CapUpstreamBilling(t *testing.T) {
	cases := []struct {
		title   string
		in, out string
	}{
		{"上游渠道 A 欠费，请求全部 429", "confirmed", "suspected"},
		{"渠道「主」额度耗尽", "confirmed", "suspected"},
		{"网关额度耗尽：用户 alice 当日额度已用完", "confirmed", "confirmed"},
		{"上游拒绝参数 max_tokens", "confirmed", "confirmed"},
		{"上游疑似欠费", "suspected", "suspected"},
	}
	for _, c := range cases {
		f := Finding{Title: c.title}
		f.Level = Level(c.in)
		t7CapUpstreamBilling(&f)
		if string(f.Level) != c.out {
			t.Errorf("%s: got %s want %s", c.title, f.Level, c.out)
		}
	}
}
