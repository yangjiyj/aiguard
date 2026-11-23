package diagnostics

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Polish 让模型只改写 L2 报告的措辞（Title、Impact、Advice.Text），不增删结论，不改数字和编号。
// 任何不符合的改写都被放弃，返回原报告。

const t7PolishTimeout = 30 * time.Second

const t7PolishPrompt = `你是技术文案编辑。下面是网关运维诊断的结论，请只改写每条结论的 title、impact 和 advice 的措辞，让表达更自然、更像值班工程师在对客户说话。
规则：
- 不得增加、删除或合并结论；findings 的数量和顺序保持不变，每条的 check_id、level 原样返回。
- advice 的条数和顺序保持不变，只改 text。
- 所有数字、请求编号、模型名、渠道名、时间必须原样保留，不得改写、换算或增减。
- 不得添加原文没有的事实、原因或判断，也不得改变结论的肯定或推测语气。
- 全程用中文，只输出一个 JSON 对象：{"findings":[{"check_id":"","level":"","title":"","impact":"","advice":["",""]}]}`

type t7PolishItem struct {
	CheckID string   `json:"check_id"`
	Level   Level    `json:"level"`
	Title   string   `json:"title"`
	Impact  string   `json:"impact"`
	Advice  []string `json:"advice"`
}

// t7Facts 提取文本中的数字与请求编号（排序后用于逐项比较）。
func t7Facts(texts ...string) []string {
	var out []string
	for _, t := range texts {
		out = append(out, reqIDRe.FindAllString(t, -1)...)
		out = append(out, numberRe.FindAllString(reqIDRe.ReplaceAllString(t, " "), -1)...)
	}
	sort.Strings(out)
	return out
}

func t7SameFacts(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func t7FindingTexts(f Finding) []string {
	ts := []string{f.Title, f.Impact}
	for _, a := range f.Advice {
		ts = append(ts, a.Text)
	}
	return ts
}

// Polish 见文件头说明。m 为 nil、报告为空或没有结论时原样返回。
func Polish(ctx context.Context, m LLM, r *Report) *Report {
	if m == nil || r == nil || len(r.Findings) == 0 {
		return r
	}
	pctx, cancel := context.WithTimeout(ctx, t7PolishTimeout)
	defer cancel()

	items := make([]t7PolishItem, 0, len(r.Findings))
	for _, f := range r.Findings {
		it := t7PolishItem{CheckID: f.CheckID, Level: f.Level, Title: f.Title, Impact: f.Impact, Advice: []string{}}
		for _, a := range f.Advice {
			it.Advice = append(it.Advice, a.Text)
		}
		items = append(items, it)
	}
	payload, err := json.Marshal(map[string]any{"findings": items})
	if err != nil {
		return r
	}
	reply, err := m.Chat(pctx, []Msg{
		{Role: "system", Content: t7PolishPrompt},
		{Role: "user", Content: string(payload)},
	}, nil)
	if err != nil || len(reply.ToolCalls) > 0 {
		return r
	}
	var got struct {
		Findings []t7PolishItem `json:"findings"`
	}
	if json.Unmarshal([]byte(t7ExtractJSON(reply.Content)), &got) != nil || len(got.Findings) != len(r.Findings) {
		return r
	}

	out := *r
	out.Findings = make([]Finding, len(r.Findings))
	for i, f := range r.Findings {
		g := got.Findings[i]
		if g.CheckID != f.CheckID || g.Level != f.Level || len(g.Advice) != len(f.Advice) {
			return r
		}
		if strings.TrimSpace(g.Title) == "" || (strings.TrimSpace(f.Impact) != "" && strings.TrimSpace(g.Impact) == "") {
			return r
		}
		nf := f
		nf.Title, nf.Impact = strings.TrimSpace(g.Title), strings.TrimSpace(g.Impact)
		nf.Advice = make([]Advice, len(f.Advice))
		for j, a := range f.Advice {
			if strings.TrimSpace(g.Advice[j]) == "" {
				return r
			}
			nf.Advice[j] = Advice{Text: strings.TrimSpace(g.Advice[j]), Link: a.Link}
		}
		if !t7SameFacts(t7Facts(t7FindingTexts(f)...), t7Facts(t7FindingTexts(nf)...)) {
			return r
		}
		out.Findings[i] = nf
	}
	if FactCheck(&out) != nil {
		return r
	}
	return &out
}
