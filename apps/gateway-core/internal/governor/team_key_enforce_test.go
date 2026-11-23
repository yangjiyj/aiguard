package governor

import (
	"context"
	"testing"
)

// 任务 2.7 规格末段：team/key 维度超额 → 被拒。
//
// mergeUsage 对各 scope 取最高水位（与 scope 名称无关），故只要 team / key 维度
// 的用量写进了快照，enforce 模式下任一维度超额即触发处置。本用例以纯 team-scope
// 快照证明 enforce 侧早已消费 team/key 维度——写入侧补齐后整条链路即闭环。
func TestDecide_DeniesOnTeamScopeOverBudget(t *testing.T) {
	d := New(
		&singleScopeSnap{key: "team:team-1", snap: Snapshot{MonthCostMicros: 200}},
		&stubQuota{
			mode: "enforce",
			quota: EffectiveQuotaInput{
				MonthlyBudgetMicros: 100,
				OverageAction:       "rate_limit",
			},
		},
	)

	got := d.Decide(context.Background(), ScopeRef{TeamID: "team-1"})
	if got.Action != ActionRateLimit {
		t.Fatalf("team 维度超额（enforce）：期望 ActionRateLimit，实际 %s", got.Action)
	}
}

// 同理证明单 key 维度超额也被 enforce 侧消费。
func TestDecide_DeniesOnKeyScopeOverBudget(t *testing.T) {
	d := New(
		&singleScopeSnap{key: "key:key-id-1", snap: Snapshot{MonthCostMicros: 999}},
		&stubQuota{
			mode: "enforce",
			quota: EffectiveQuotaInput{
				MonthlyBudgetMicros: 100,
				OverageAction:       "rate_limit",
			},
		},
	)

	got := d.Decide(context.Background(), ScopeRef{KeyID: "key-id-1"})
	if got.Action != ActionRateLimit {
		t.Fatalf("key 维度超额（enforce）：期望 ActionRateLimit，实际 %s", got.Action)
	}
}

// singleScopeSnap 返回单一 scope 键的用量快照，键名可任意指定，
// 用于证明 decider 的合并/判定与 scope 名称无关。
type singleScopeSnap struct {
	key  string
	snap Snapshot
}

func (s *singleScopeSnap) GetMulti(ctx context.Context, ref ScopeRef) (map[string]Snapshot, error) {
	return map[string]Snapshot{s.key: s.snap}, nil
}
