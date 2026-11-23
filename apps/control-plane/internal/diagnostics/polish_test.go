package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func t7PolishReport() *Report {
	return &Report{
		Tier: TierL2,
		Findings: []Finding{{
			CheckID: "up_429", Severity: SevError, Level: LevelConfirmed,
			Title:    "上游限流：渠道返回 HTTP 429，共 7 条",
			Impact:   "涉及 2 个用户",
			Advice:   []Advice{{Text: "降低该渠道的并发", Link: "/providers"}},
			Excluded: []string{"已排除网关限流"},
			Evidence: []Evidence{{Kind: "request", Ref: t7ReqID, Summary: "上游返回 429"}},
		}},
		Steps: []Step{{Tool: "get_request", Output: json.RawMessage(`{"request_id":"` + t7ReqID + `","code":429,"count":7,"users":2}`)}},
	}
}

func t7PolishReply(mut func(it *t7PolishItem)) *t7LLM {
	it := t7PolishItem{CheckID: "up_429", Level: LevelConfirmed,
		Title: "上游在限流：渠道返回了 HTTP 429，一共 7 条", Impact: "共影响 2 个用户", Advice: []string{"建议先降低这个渠道的并发"}}
	if mut != nil {
		mut(&it)
	}
	b, _ := json.Marshal(map[string]any{"findings": []t7PolishItem{it}})
	return t7Script(Reply{Content: string(b)})
}

func TestT7PolishAccepts(t *testing.T) {
	r := t7PolishReport()
	got := Polish(context.Background(), t7PolishReply(nil), r)
	if got == r || got.Findings[0].Title != "上游在限流：渠道返回了 HTTP 429，一共 7 条" {
		t.Fatalf("合规改写应被采用: %+v", got.Findings[0])
	}
	if got.Findings[0].Advice[0].Link != "/providers" || len(got.Findings[0].Evidence) != 1 || got.Findings[0].CheckID != "up_429" {
		t.Errorf("链接 / 证据 / CheckID 必须保留: %+v", got.Findings[0])
	}
	if r.Findings[0].Title != "上游限流：渠道返回 HTTP 429，共 7 条" {
		t.Errorf("不得原地修改原报告")
	}
}

func TestT7PolishRejectsTampering(t *testing.T) {
	cases := map[string]func(it *t7PolishItem){
		"篡改数字":       func(it *t7PolishItem) { it.Title = "上游限流：共 70 条" },
		"新增数字":       func(it *t7PolishItem) { it.Impact = "共影响 2 个用户，约 5000 次" },
		"改了编号":       func(it *t7PolishItem) { it.Title = "上游限流 " + t7ReqBad },
		"改了 Level":   func(it *t7PolishItem) { it.Level = LevelSuspected },
		"改了 CheckID": func(it *t7PolishItem) { it.CheckID = "other" },
		"建议条数变化":     func(it *t7PolishItem) { it.Advice = []string{"a", "b"} },
		"标题为空":       func(it *t7PolishItem) { it.Title = "" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			r := t7PolishReport()
			if got := Polish(context.Background(), t7PolishReply(mut), r); got != r {
				t.Errorf("应放弃改写并返回原报告: %+v", got.Findings[0])
			}
		})
	}
}

func TestT7PolishRejectsStructureChange(t *testing.T) {
	r := t7PolishReport()
	two := t7Script(Reply{Content: `{"findings":[{"check_id":"up_429","level":"confirmed","title":"a 7","impact":"2","advice":["b"]},{"check_id":"x","level":"confirmed","title":"c","impact":"","advice":[]}]}`})
	if got := Polish(context.Background(), two, r); got != r {
		t.Errorf("Finding 数量变化应放弃")
	}
	for name, llm := range map[string]*t7LLM{
		"非 JSON": t7Script(Reply{Content: "好的，已润色"}),
		"模型报错":   {fn: func(int, []Msg, []ToolSpec) (Reply, error) { return Reply{}, errors.New("boom") }},
		"返回工具调用": t7Script(t7Call("c", "get_request", `{}`)),
	} {
		if got := Polish(context.Background(), llm, r); got != r {
			t.Errorf("%s 应返回原报告", name)
		}
	}
	if Polish(context.Background(), nil, r) != r || Polish(context.Background(), two, nil) != nil {
		t.Errorf("nil 入参应原样返回")
	}
	empty := &Report{}
	if Polish(context.Background(), two, empty) != empty {
		t.Errorf("没有结论时应原样返回")
	}
}
