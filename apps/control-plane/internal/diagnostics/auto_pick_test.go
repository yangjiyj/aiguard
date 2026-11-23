package diagnostics

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// ---- 自检：瞬时错误重试一次，能力性失败不重试 ----

// t8Flaky 在每道题的第一次调用返回 firstErr，其后交给正常的假模型。
type t8Flaky struct {
	t8Fake
	firstErr error
	seen     map[string]int
	total    int
}

func (f *t8Flaky) Chat(ctx context.Context, msgs []Msg, tools []ToolSpec) (Reply, error) {
	f.total++
	q := t8UserText(msgs)
	if f.seen == nil {
		f.seen = map[string]int{}
	}
	f.seen[q]++
	if f.seen[q] == 1 && len(msgs) == 2 {
		return Reply{}, f.firstErr
	}
	return f.t8Fake.Chat(ctx, msgs, tools)
}

func TestT8SelfCheckRetriesTransientOnce(t *testing.T) {
	old := t7RetryBackoff
	t7RetryBackoff = time.Millisecond
	defer func() { t7RetryBackoff = old }()
	for name, e := range map[string]error{
		"超时":   errors.New("调用模型失败: context deadline exceeded"),
		"5xx":  &t8HTTPError{Status: 503},
		"连接错误": errors.New("connection reset by peer"),
	} {
		f := &t8Flaky{t8Fake: t8Fake{good: true}, firstErr: e}
		r := SelfCheck(context.Background(), f)
		if !r.Passed || r.Score != 5 {
			t.Fatalf("%s：瞬时错误应重试后通过: %+v", name, r)
		}
	}
	// 两次都失败：只重试一次，该题失败
	cnt := &t8Count{err: &t8HTTPError{Status: 502}}
	r := SelfCheck(context.Background(), cnt)
	if r.Score != 0 || cnt.n != 10 { // 5 题 × (1 次 + 重试 1 次)
		t.Fatalf("应每题恰好重试一次: score=%d n=%d", r.Score, cnt.n)
	}
}

type t8Count struct {
	err error
	n   int
}

func (c *t8Count) Chat(context.Context, []Msg, []ToolSpec) (Reply, error) {
	c.n++
	return Reply{}, c.err
}

func TestT8SelfCheckNoRetryOnCapabilityFailure(t *testing.T) {
	old := t7RetryBackoff
	t7RetryBackoff = time.Millisecond
	defer func() { t7RetryBackoff = old }()
	for name, e := range map[string]error{"不支持工具": ErrNoTools, "400": &t8HTTPError{Status: 400}} {
		c := &t8Count{err: e}
		r := SelfCheck(context.Background(), c)
		if r.Score != 0 || c.n != 5 {
			t.Fatalf("%s 不应重试: n=%d", name, c.n)
		}
	}
	// 没调对工具属于能力性失败：每题只调用一次
	g := &t8Fake{good: false}
	if r := SelfCheck(context.Background(), g); r.Score != 0 || g.calls != 5 {
		t.Fatalf("答错不应重试: calls=%d %+v", g.calls, r)
	}
}

// ---- 自动选型：候选逐个自检 ----

type t10TagLLM struct{ id string }

func (t10TagLLM) Chat(context.Context, []Msg, []ToolSpec) (Reply, error) { return Reply{}, nil }

// t10AutoFix 让引擎按模型 id 返回不同的自检得分，并让 Pick 支持“指定 id 即返回它”。
func t10AutoFix(t *testing.T, scores map[string]int, order ...string) (*t10Fix, map[string]*ModelChoice, *[]string, *int32) {
	f := t10NewFix(t)
	f.setChoice()
	chosen := map[string]*ModelChoice{}
	for _, id := range order {
		chosen[id] = &ModelChoice{ModelID: id, ModelName: "name-" + id, ProviderID: "t10p_" + f.sfx}
	}
	tested := &[]string{}
	var candCalls int32
	f.eng.Pick = func(ctx context.Context, q Querier, tenantID, preferred string) (*ModelChoice, error) {
		if c, ok := chosen[preferred]; ok {
			return c, nil
		}
		if preferred != "" {
			return f.picked, nil // 手动指定：沿用夹具里的真实模型
		}
		return chosen[order[0]], nil
	}
	f.eng.Candidates = func(ctx context.Context, q Querier, tenantID string, limit int) ([]*ModelChoice, error) {
		atomic.AddInt32(&candCalls, 1)
		var out []*ModelChoice
		for _, id := range order {
			out = append(out, chosen[id])
		}
		return out, nil
	}
	f.eng.LoadModel = func(ctx context.Context, c *ModelChoice) (LLM, error) { return t10TagLLM{c.ModelID}, nil }
	f.eng.SelfCheck = func(ctx context.Context, m LLM) SelfCheckResult {
		id := m.(t10TagLLM).id
		f.mu.Lock()
		*tested = append(*tested, id)
		f.mu.Unlock()
		s := scores[id]
		return SelfCheckResult{Passed: s >= t8PassScore, Score: s, Total: 5, TestedAt: time.Now().UTC(), Details: []string{}}
	}
	return f, chosen, tested, &candCalls
}

func TestT10AutoPickTriesCandidatesUntilPass(t *testing.T) {
	ctx := context.Background()
	f, _, tested, _ := t10AutoFix(t, map[string]int{"A": 3, "B": 5, "C": 5}, "A", "B", "C")
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "为什么慢"})
	f.waitDone(t, f.admin, id)
	f.eng.Wait()
	if got := *tested; len(got) != 2 || got[0] != "A" || got[1] != "B" {
		t.Fatalf("应依次测 A、B 后停止: %v", got)
	}
	st := f.eng.loadSettings(ctx, f.tenant)
	if st.Selfcheck == nil || st.Selfcheck.ModelID != "B" || !st.Selfcheck.Passed || st.Selfcheck.ModelName != "name-B" {
		t.Fatalf("应记录通过的 B: %+v", st.Selfcheck)
	}
	// 下一次会话用自检通过的 B 走 L3，而不是排序第一的 A
	id2, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "再问"})
	v := f.waitDone(t, f.admin, id2)
	if v.Report.Tier != TierL3 || v.Report.Model != "name-B" {
		t.Fatalf("应使用通过自检的 B: tier=%s model=%s", v.Report.Tier, v.Report.Model)
	}
	sv, _ := f.eng.GetSettings(ctx, f.admin)
	if sv.SelfCheck == nil || sv.SelfCheck.ModelName != "name-B" {
		t.Fatalf("设置应返回自检所用模型名: %+v", sv.SelfCheck)
	}
}

func TestT10AutoPickAllFailKeepsBestScore(t *testing.T) {
	ctx := context.Background()
	f, _, tested, _ := t10AutoFix(t, map[string]int{"A": 1, "B": 3, "C": 2}, "A", "B", "C")
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "为什么慢"})
	f.waitDone(t, f.admin, id)
	f.eng.Wait()
	if len(*tested) != 3 {
		t.Fatalf("全部不通过应测完所有候选: %v", *tested)
	}
	st := f.eng.loadSettings(ctx, f.tenant)
	if st.Selfcheck == nil || st.Selfcheck.ModelID != "B" || st.Selfcheck.Passed || st.Selfcheck.Score != 3 {
		t.Fatalf("应记录得分最高的 B: %+v", st.Selfcheck)
	}
	id2, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "再问"})
	if v := f.waitDone(t, f.admin, id2); v.Report.Tier != TierL2 {
		t.Fatalf("全部未通过应降级 L2: %s", v.Report.Tier)
	}
}

func TestT10ManualModelOnlyTestsThatOne(t *testing.T) {
	ctx := context.Background()
	f, _, tested, candCalls := t10AutoFix(t, map[string]int{"A": 5, "B": 5}, "A", "B")
	t10Exec(t, f.db, `INSERT INTO diag_settings (tenant_id, model_id) VALUES ($1, $2)`, f.tenant, f.picked.ModelID)
	f.eng.LoadModel = func(ctx context.Context, c *ModelChoice) (LLM, error) { return t10TagLLM{c.ModelID}, nil }
	// 手动指定的模型不在 scores 里 => 得 0 分不通过，但只应测它一个
	id, _ := f.eng.Start(ctx, f.admin, Input{Kind: "question", Text: "为什么慢"})
	f.waitDone(t, f.admin, id)
	f.eng.Wait()
	if len(*tested) != 1 || (*tested)[0] != f.picked.ModelID {
		t.Fatalf("手动指定只测指定的那个: %v", *tested)
	}
	if atomic.LoadInt32(candCalls) != 0 {
		t.Fatal("手动指定不应取候选列表")
	}
	st := f.eng.loadSettings(ctx, f.tenant)
	if st.Selfcheck == nil || st.Selfcheck.ModelID != f.picked.ModelID {
		t.Fatalf("%+v", st.Selfcheck)
	}
}

// 自检通过的模型已不可用时，回到成功率排序。
func TestT10PickForFallsBackWhenPassedModelGone(t *testing.T) {
	ctx := context.Background()
	f, chosen, _, _ := t10AutoFix(t, map[string]int{}, "A", "B")
	f.eng.Pick = func(ctx context.Context, q Querier, tenantID, preferred string) (*ModelChoice, error) {
		if preferred == "B" {
			return chosen["A"], nil // B 不再 active：PickModel 回落到排序第一
		}
		return chosen["A"], nil
	}
	sc := &t10SC{SelfCheckResult: SelfCheckResult{Passed: true}, ModelID: "B"}
	c, err := f.eng.pickFor(ctx, f.tenant, "", sc)
	if err != nil || c.ModelID != "A" {
		t.Fatalf("B 不可用应回到排序结果 A: %+v %v", c, err)
	}
	if t8IsImageModel(&ModelChoice{ModelName: "gpt-image-2"}) == false || t8IsImageModel(&ModelChoice{ModelName: "gpt-6-luna"}) {
		t.Fatal("图像类模型判断不对")
	}
}
