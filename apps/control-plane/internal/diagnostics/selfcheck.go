package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

type SelfCheckResult struct {
	Passed   bool      `json:"passed"`
	Score    int       `json:"score"`
	Total    int       `json:"total"`
	Details  []string  `json:"details"`
	TestedAt time.Time `json:"tested_at"`
}

const (
	t8SelfCheckTimeout = 3 * time.Minute
	t8MaxRounds        = 6
	t8PassScore        = 4

	t8Q1ID = "req_11111111-1111-4111-8111-111111111111"
	t8Q2ID = "req_22222222-2222-4222-8222-222222222222"
	t8Q3ID = "req_33333333-3333-4333-8333-333333333333"
	t8Q4ID = "req_44444444-4444-4444-8444-444444444444"
	t8Q5ID = "req_55555555-5555-4555-8555-555555555555"
)

const t8SystemPrompt = "你是网关运维诊断助手。只能依据工具返回的事实下结论，不得编造；需要数据时必须调用工具。"

const t8FindingsHint = `最终回答必须只输出一个 JSON 对象（不要多余文字），格式：
{"findings":[{"check_id":"","severity":"ok|warn|error","level":"confirmed|suspected|unknown","title":"结论一句话","impact":"影响面","advice":[{"text":"建议"}],"excluded":["已排除项及依据"],"evidence":[{"kind":"request","ref":"请求编号","summary":"证据一句话"}]}]}
证据不足、无法判断时 level 必须为 unknown，不得编造原因。`

type t8Question struct {
	prompt string
	tools  []ToolSpec
	reply  func(ToolCall) string
	judge  func(calls []ToolCall, final string) error
}

func t8Spec(name, desc string, props string, required ...string) ToolSpec {
	req := "[]"
	if len(required) > 0 {
		b, _ := json.Marshal(required)
		req = string(b)
	}
	return ToolSpec{Name: name, Description: desc,
		Schema: json.RawMessage(`{"type":"object","properties":{` + props + `},"required":` + req + `}`)}
}

func t8Tools() []ToolSpec {
	return []ToolSpec{
		t8Spec("get_request", "按请求编号查询一次请求的状态、上游状态码、失败分类与路由信息", `"request_id":{"type":"string","description":"请求编号，形如 req_xxx"}`, "request_id"),
		t8Spec("get_quota_policies", "查询当前租户的限额策略（每日 token、RPM 等）", `"user":{"type":"string","description":"可选，用户标识"}`),
		t8Spec("compare_windows", "对比两个时间窗口内同一模型/渠道的成功率与错误分布", `"model":{"type":"string"},"window_hours":{"type":"integer"}`),
		t8Spec("search_requests", "按条件搜索最近的请求列表", `"status":{"type":"string"},"model":{"type":"string"}`),
	}
}

func t8ArgString(c ToolCall, key string) string {
	var m map[string]any
	if json.Unmarshal(c.Args, &m) != nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func t8Called(calls []ToolCall, name string) bool {
	for _, c := range calls {
		if c.Name == name {
			return true
		}
	}
	return false
}

// t8ParseFindings 从最终回答中取出 {"findings":[...]}，容忍 ``` 代码围栏。
func t8ParseFindings(s string) ([]map[string]any, error) {
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
	var out struct {
		Findings []map[string]any `json:"findings"`
	}
	dec := json.NewDecoder(strings.NewReader(s))
	if err := dec.Decode(&out); err != nil {
		return nil, errors.New("最终回答不是合法 JSON")
	}
	if len(out.Findings) == 0 {
		return nil, errors.New("findings 为空")
	}
	return out.Findings, nil
}

func t8NonEmptyStr(m map[string]any, k string) bool {
	s, ok := m[k].(string)
	return ok && strings.TrimSpace(s) != ""
}

func t8Questions() []t8Question {
	tools := t8Tools()
	return []t8Question{
		{ // 1：给出编号必须先调用 get_request
			prompt: "请帮我排查一下请求 " + t8Q1ID + "，它好像失败了。",
			tools:  tools,
			reply: func(c ToolCall) string {
				return `{"request_id":"` + t8Q1ID + `","request_status":"provider_error","upstream_status_code":502,"failure_category":"upstream_unavailable"}`
			},
			judge: func(calls []ToolCall, _ string) error {
				if len(calls) == 0 || calls[0].Name != "get_request" {
					return errors.New("第一次工具调用不是 get_request")
				}
				if t8ArgString(calls[0], "request_id") != t8Q1ID {
					return errors.New("get_request 的 request_id 参数不正确")
				}
				return nil
			},
		},
		{ // 2：读懂 429，调用 get_quota_policies
			prompt: "用户反馈请求 " + t8Q2ID + " 报错了，请排查原因。",
			tools:  tools,
			reply: func(c ToolCall) string {
				switch c.Name {
				case "get_request":
					return `{"request_id":"` + t8Q2ID + `","request_status":"rate_limited","upstream_status_code":429,"failure_category":"rate_limited","error_message":"rate limit exceeded: rpm"}`
				case "get_quota_policies":
					return `{"policies":[{"scope":"tenant","rpm_limit":60,"daily_token_limit":1000000}]}`
				}
				return `{"note":"无相关数据"}`
			},
			judge: func(calls []ToolCall, _ string) error {
				if !t8Called(calls, "get_request") {
					return errors.New("没有先查询请求")
				}
				if !t8Called(calls, "get_quota_policies") {
					return errors.New("看到 429 后没有调用 get_quota_policies")
				}
				return nil
			},
		},
		{ // 3：两步推理，上游 400 后调用 compare_windows
			prompt: "请排查请求 " + t8Q3ID + " 失败的原因，并判断是个别请求还是整体变差。",
			tools:  tools,
			reply: func(c ToolCall) string {
				switch c.Name {
				case "get_request":
					return `{"request_id":"` + t8Q3ID + `","model":"gpt-x","request_status":"provider_error","upstream_status_code":400,"failure_category":"upstream_bad_request","error_message":"unsupported parameter"}`
				case "compare_windows":
					return `{"model":"gpt-x","current":{"total":50,"success_rate":0.2},"previous":{"total":48,"success_rate":0.98}}`
				}
				return `{"note":"无相关数据"}`
			},
			judge: func(calls []ToolCall, _ string) error {
				gi, ci := -1, -1
				for i, c := range calls {
					if c.Name == "get_request" && gi < 0 {
						gi = i
					}
					if c.Name == "compare_windows" && ci < 0 {
						ci = i
					}
				}
				if gi < 0 {
					return errors.New("没有先查询请求")
				}
				if ci < 0 || ci < gi {
					return errors.New("查到上游 400 后没有调用 compare_windows")
				}
				return nil
			},
		},
		{ // 4：证据不足必须 unknown
			prompt: "请排查请求 " + t8Q4ID + " 为什么失败，并给出结论。\n" + t8FindingsHint,
			tools:  tools,
			reply: func(c ToolCall) string {
				return `{"found":false,"note":"未找到该请求，也没有任何相关记录"}`
			},
			judge: func(_ []ToolCall, final string) error {
				fs, err := t8ParseFindings(final)
				if err != nil {
					return err
				}
				for _, f := range fs {
					if f["level"] != "unknown" {
						return errors.New("证据不足时 level 应为 unknown")
					}
				}
				return nil
			},
		},
		{ // 5：输出符合结论 schema
			prompt: "请排查请求 " + t8Q5ID + " 失败的原因，并给出结论。\n" + t8FindingsHint,
			tools:  tools,
			reply: func(c ToolCall) string {
				return `{"request_id":"` + t8Q5ID + `","request_status":"provider_error","upstream_status_code":429,"failure_category":"rate_limited","error_message":"rate limit exceeded"}`
			},
			judge: func(_ []ToolCall, final string) error {
				fs, err := t8ParseFindings(final)
				if err != nil {
					return err
				}
				for _, f := range fs {
					for _, k := range []string{"severity", "title", "impact"} {
						if !t8NonEmptyStr(f, k) {
							return fmt.Errorf("字段 %s 缺失或为空", k)
						}
					}
					if _, ok := f["check_id"].(string); !ok {
						return errors.New("字段 check_id 缺失")
					}
					switch f["severity"] {
					case "ok", "warn", "error":
					default:
						return errors.New("severity 取值非法")
					}
					switch f["level"] {
					case "confirmed", "suspected", "unknown":
					default:
						return errors.New("level 取值非法")
					}
					if a, ok := f["advice"].([]any); !ok || len(a) == 0 {
						return errors.New("advice 缺失或为空")
					}
					if _, ok := f["excluded"].([]any); !ok {
						return errors.New("excluded 缺失")
					}
					ev, ok := f["evidence"].([]any)
					if !ok || len(ev) == 0 {
						return errors.New("evidence 缺失或为空")
					}
					for _, e := range ev {
						em, ok := e.(map[string]any)
						if !ok || !t8NonEmptyStr(em, "kind") || !t8NonEmptyStr(em, "ref") || !t8NonEmptyStr(em, "summary") {
							return errors.New("evidence 项字段不全")
						}
					}
				}
				return nil
			},
		},
	}
}

func t8Run(ctx context.Context, m LLM, q t8Question) error {
	msgs := []Msg{{Role: "system", Content: t8SystemPrompt}, {Role: "user", Content: q.prompt}}
	var calls []ToolCall
	for round := 0; round < t8MaxRounds; round++ {
		r, err := t7Chat(ctx, m, msgs, q.tools) // 超时/5xx/连接错误重试一次；能力性失败（ErrNoTools 等）不重试
		if err != nil {
			return err
		}
		if len(r.ToolCalls) == 0 {
			return q.judge(calls, r.Content)
		}
		msgs = append(msgs, Msg{Role: "assistant", Content: r.Content, ToolCalls: r.ToolCalls})
		for _, c := range r.ToolCalls {
			calls = append(calls, c)
			msgs = append(msgs, Msg{Role: "tool", ToolCallID: c.ID, Name: c.Name, Content: q.reply(c)})
		}
	}
	return errors.New("超过最大对话轮数仍未给出最终回答")
}

// SelfCheck 用 5 道固定题（假工具、固定返回）检验模型的工具调用与结论格式能力。
func SelfCheck(ctx context.Context, m LLM) SelfCheckResult {
	ctx, cancel := context.WithTimeout(ctx, t8SelfCheckTimeout)
	defer cancel()
	qs := t8Questions()
	res := SelfCheckResult{Total: len(qs), TestedAt: time.Now().UTC(), Details: []string{}}
	for i, q := range qs {
		err := t8Run(ctx, m, q)
		switch {
		case err == nil:
			res.Score++
			res.Details = append(res.Details, fmt.Sprintf("第%d题：通过", i+1))
		case errors.Is(err, ErrNoTools):
			res.Details = append(res.Details, fmt.Sprintf("第%d题：失败（模型不支持工具调用）", i+1))
		default:
			res.Details = append(res.Details, fmt.Sprintf("第%d题：失败（%s）", i+1, err.Error()))
		}
	}
	res.Passed = res.Score >= t8PassScore
	return res
}
