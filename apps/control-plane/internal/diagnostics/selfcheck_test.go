package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// t8Fake 是脚本化的假 LLM：按用户题干中出现的请求编号区分题目。
type t8Fake struct {
	good  bool
	calls int
}

func t8UserText(msgs []Msg) string {
	for _, m := range msgs {
		if m.Role == "user" {
			return m.Content
		}
	}
	return ""
}

func t8ToolsSeen(msgs []Msg) []string {
	var n []string
	for _, m := range msgs {
		for _, c := range m.ToolCalls {
			n = append(n, c.Name)
		}
	}
	return n
}

func t8Has(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func t8Call(name string, args string) Reply {
	return Reply{ToolCalls: []ToolCall{{ID: "c_" + name, Name: name, Args: json.RawMessage(args)}}}
}

func (f *t8Fake) Chat(_ context.Context, msgs []Msg, _ []ToolSpec) (Reply, error) {
	f.calls++
	q := t8UserText(msgs)
	seen := t8ToolsSeen(msgs)
	if !f.good {
		return Reply{Content: "我觉得可能是网络问题，请重试。"}, nil
	}
	switch {
	case strings.Contains(q, t8Q1ID):
		if !t8Has(seen, "get_request") {
			return t8Call("get_request", `{"request_id":"`+t8Q1ID+`"}`), nil
		}
	case strings.Contains(q, t8Q2ID):
		if !t8Has(seen, "get_request") {
			return t8Call("get_request", `{"request_id":"`+t8Q2ID+`"}`), nil
		}
		if !t8Has(seen, "get_quota_policies") {
			return t8Call("get_quota_policies", `{}`), nil
		}
	case strings.Contains(q, t8Q3ID):
		if !t8Has(seen, "get_request") {
			return t8Call("get_request", `{"request_id":"`+t8Q3ID+`"}`), nil
		}
		if !t8Has(seen, "compare_windows") {
			return t8Call("compare_windows", `{"model":"gpt-x","window_hours":1}`), nil
		}
	case strings.Contains(q, t8Q4ID):
		if !t8Has(seen, "get_request") {
			return t8Call("get_request", `{"request_id":"`+t8Q4ID+`"}`), nil
		}
		return Reply{Content: `{"findings":[{"check_id":"x","severity":"warn","level":"unknown","title":"证据不足","impact":"未知","advice":[{"text":"补充信息"}],"excluded":[],"evidence":[]}]}`}, nil
	case strings.Contains(q, t8Q5ID):
		if !t8Has(seen, "get_request") {
			return t8Call("get_request", `{"request_id":"`+t8Q5ID+`"}`), nil
		}
		return Reply{Content: "```json\n" + `{"findings":[{"check_id":"upstream_429","severity":"error","level":"confirmed","title":"上游限流","impact":"该请求失败","advice":[{"text":"提高限额"}],"excluded":["非鉴权问题：状态码为429"],"evidence":[{"kind":"request","ref":"` + t8Q5ID + `","summary":"上游返回429"}]}]}` + "\n```"}, nil
	}
	return Reply{Content: "已完成"}, nil
}

func TestT8SelfCheckGood(t *testing.T) {
	r := SelfCheck(context.Background(), &t8Fake{good: true})
	if !r.Passed || r.Score != 5 || r.Total != 5 || len(r.Details) != 5 || r.TestedAt.IsZero() {
		t.Fatalf("%+v", r)
	}
}

func TestT8SelfCheckGarbage(t *testing.T) {
	r := SelfCheck(context.Background(), &t8Fake{good: false})
	if r.Passed || r.Score != 0 || r.Total != 5 {
		t.Fatalf("乱答应得 0 分: %+v", r)
	}
}

// 第一次工具调用参数错误 / 第 4 题不是 unknown，各扣一题：4 分仍通过，3 分不通过。
type t8Flawed struct {
	t8Fake
	wrongArg, wrongLevel, noJSON bool
}

func (f *t8Flawed) Chat(ctx context.Context, msgs []Msg, tools []ToolSpec) (Reply, error) {
	r, err := f.t8Fake.Chat(ctx, msgs, tools)
	q := t8UserText(msgs)
	if f.wrongArg && strings.Contains(q, t8Q1ID) && len(r.ToolCalls) > 0 {
		r.ToolCalls[0].Args = json.RawMessage(`{"request_id":"req_wrong"}`)
	}
	if f.wrongLevel && strings.Contains(q, t8Q4ID) && r.Content != "" {
		r.Content = strings.Replace(r.Content, `"unknown"`, `"confirmed"`, 1)
	}
	if f.noJSON && strings.Contains(q, t8Q5ID) && r.Content != "" {
		r.Content = `{"findings":[{"title":"只有标题"}]}`
	}
	return r, err
}

func TestT8SelfCheckThreshold(t *testing.T) {
	r := SelfCheck(context.Background(), &t8Flawed{t8Fake: t8Fake{good: true}, wrongArg: true})
	if !r.Passed || r.Score != 4 {
		t.Fatalf("应 4 分通过: %+v", r)
	}
	r = SelfCheck(context.Background(), &t8Flawed{t8Fake: t8Fake{good: true}, wrongArg: true, wrongLevel: true})
	if r.Passed || r.Score != 3 {
		t.Fatalf("应 3 分不通过: %+v", r)
	}
	r = SelfCheck(context.Background(), &t8Flawed{t8Fake: t8Fake{good: true}, noJSON: true})
	if r.Score != 4 {
		t.Fatalf("第5题字段不全应扣分: %+v", r)
	}
}

type t8ErrLLM struct{ err error }

func (e t8ErrLLM) Chat(context.Context, []Msg, []ToolSpec) (Reply, error) { return Reply{}, e.err }

func TestT8SelfCheckErrors(t *testing.T) {
	r := SelfCheck(context.Background(), t8ErrLLM{ErrNoTools})
	if r.Passed || r.Score != 0 || !strings.Contains(r.Details[0], "不支持工具调用") {
		t.Fatalf("%+v", r)
	}
	r = SelfCheck(context.Background(), t8ErrLLM{errors.New("boom")})
	if r.Passed || r.Score != 0 {
		t.Fatalf("%+v", r)
	}
}

// 一直调用工具不给最终答案：必须在有限轮数后判失败而不是死循环。
type t8Loop struct{ n int }

func (l *t8Loop) Chat(context.Context, []Msg, []ToolSpec) (Reply, error) {
	l.n++
	return t8Call("search_requests", `{}`), nil
}

func TestT8SelfCheckLoopBounded(t *testing.T) {
	l := &t8Loop{}
	r := SelfCheck(context.Background(), l)
	if r.Passed || l.n > 5*t8MaxRounds {
		t.Fatalf("%+v n=%d", r, l.n)
	}
}
