package governor

// e2e_test.go — T50 E2E 6 关键路径决策器级验证
//
// 测试策略：使用 stub providers 注入预设状态，直接调用 Decider.Decide()，
// 验证每种业务路径下的 Decision.Action、TriggeredScope、AlertOnly 等字段。
// 不依赖真实 PG/Redis，所有 fixture 通过 stub 构造，可在 CI 中无依赖运行。
//
// 路径覆盖：
//   E2E-1: 部门超 80% 月预算 → 产生 ActionAlert (AlertOnly=true)，TriggeredScope 为 "team"
//   E2E-2: 部门超 100% 月预算 + overage_action=downgrade_model → ActionDowngradeMod + TriggeredScope="team"
//   E2E-3: 同 project 不同 user 配不同月预算 → 各自独立触发，互不干扰
//   E2E-4: Key 级 pause_key → 只封该 key，scope 为 "key"，不影响 user 其他 key
//   E2E-5: enforcement_mode 从 enforce 改 soft → 相同过载请求不再产生 blocking action
//   E2E-6: ENV kill switch (bypass mode) → 所有 governor 行为停止 (ActionNone)

import (
	"context"
	"testing"
)

// --- helpers ---------------------------------------------------------------

func newDecider(snap Snapshot, snapKey string, quota EffectiveQuotaInput, mode string) *Decider {
	return New(
		&multiSnap{snap: snap, key: snapKey},
		&stubQuota{mode: mode, quota: quota},
	)
}

// multiSnap returns a single scope snapshot under the given key.
type multiSnap struct {
	snap Snapshot
	key  string
}

func (m *multiSnap) GetMulti(_ context.Context, _ ScopeRef) (map[string]Snapshot, error) {
	return map[string]Snapshot{m.key: m.snap}, nil
}

// twoUserSnap returns two scope snapshots for two different users.
type twoUserSnap struct {
	snapA, snapB   Snapshot
	keyA, keyB     string
	currentUserIsA bool
}

func (t *twoUserSnap) GetMulti(_ context.Context, ref ScopeRef) (map[string]Snapshot, error) {
	if t.currentUserIsA {
		return map[string]Snapshot{t.keyA: t.snapA}, nil
	}
	return map[string]Snapshot{t.keyB: t.snapB}, nil
}

// twoQuotaProvider returns different quotas based on ScopeRef.UserID.
type twoQuotaProvider struct {
	userIDA, userIDB string
	quotaA, quotaB   EffectiveQuotaInput
	mode             string
}

func (p *twoQuotaProvider) GetEnforcementMode(_ context.Context, _ ScopeRef) string { return p.mode }
func (p *twoQuotaProvider) EffectiveQuota(_ context.Context, ref ScopeRef) (EffectiveQuotaInput, error) {
	if ref.UserID == p.userIDA {
		return p.quotaA, nil
	}
	return p.quotaB, nil
}

// --- E2E-1: 部门超 80% 月预算 → AlertOnly=true, TriggeredScope="team" ------

func TestE2E_TeamBudget80Pct_TriggersPreAlert(t *testing.T) {
	// 部门月预算 1000，当前用量 850 (85%)
	d := newDecider(
		Snapshot{MonthCostMicros: 850},
		"team:t1",
		EffectiveQuotaInput{
			MonthlyBudgetMicros: 1000,
			TriggeredScope:      "team",
		},
		"enforce",
	)

	got := d.Decide(context.Background(), ScopeRef{
		TenantID:  "ten1",
		TeamID:    "t1",
		ProjectID: "pj1",
	})

	if got.Action != ActionAlert {
		t.Errorf("E2E-1: want ActionAlert (pre-alert at 80%%), got %s", got.Action)
	}
	if !got.AlertOnly {
		t.Error("E2E-1: want AlertOnly=true (pre-alert should never block)")
	}
	if got.TriggeredScope != "team" {
		t.Errorf("E2E-1: want TriggeredScope='team', got %q", got.TriggeredScope)
	}
}

// --- E2E-2: 部门超 100% + downgrade_model → ActionDowngradeMod + TriggeredScope="team" ---

func TestE2E_TeamBudgetExceeded_DowngradeModel(t *testing.T) {
	// 部门月预算 1000，当前用量 1200 (超 100%)
	d := newDecider(
		Snapshot{MonthCostMicros: 1200},
		"team:t1",
		EffectiveQuotaInput{
			MonthlyBudgetMicros: 1000,
			OverageAction:       "downgrade_model",
			DowngradeTo:         "gpt-4o-mini",
			TriggeredScope:      "team",
		},
		"enforce",
	)

	got := d.Decide(context.Background(), ScopeRef{
		TenantID:  "ten1",
		TeamID:    "t1",
		ProjectID: "pj1",
	})

	if got.Action != ActionDowngradeMod {
		t.Errorf("E2E-2: want ActionDowngradeMod, got %s", got.Action)
	}
	if got.AlertOnly {
		t.Error("E2E-2: blocking action should NOT be AlertOnly")
	}
	if got.TriggeredScope != "team" {
		t.Errorf("E2E-2: want TriggeredScope='team', got %q", got.TriggeredScope)
	}
	if got.DowngradeTo != "gpt-4o-mini" {
		t.Errorf("E2E-2: want DowngradeTo='gpt-4o-mini', got %q", got.DowngradeTo)
	}
}

// --- E2E-3: 同 project 不同 user 独立月预算，各自独立触发 ------------------

func TestE2E_DifferentUsersIndependentBudgets(t *testing.T) {
	// userA: 预算 500，用量 600（超），触发 rate_limit
	// userB: 预算 1000，用量 300（正常），应通过

	quotaProviderA := &twoQuotaProvider{
		userIDA: "userA",
		userIDB: "userB",
		quotaA: EffectiveQuotaInput{
			MonthlyBudgetMicros: 500,
			OverageAction:       "rate_limit",
			TriggeredScope:      "user",
		},
		quotaB: EffectiveQuotaInput{
			MonthlyBudgetMicros: 1000,
			OverageAction:       "rate_limit",
			TriggeredScope:      "user",
		},
		mode: "enforce",
	}

	snapProviderA := &twoUserSnap{
		snapA:          Snapshot{MonthCostMicros: 600},
		snapB:          Snapshot{MonthCostMicros: 300},
		keyA:           "user:userA",
		keyB:           "user:userB",
		currentUserIsA: true,
	}

	// userA 应该被 rate_limit
	dA := New(snapProviderA, quotaProviderA)
	gotA := dA.Decide(context.Background(), ScopeRef{ProjectID: "pj1", UserID: "userA"})
	if gotA.Action != ActionRateLimit {
		t.Errorf("E2E-3 userA: want ActionRateLimit, got %s", gotA.Action)
	}

	// userB 用同样配置，但 snap 是 B
	snapProviderB := &twoUserSnap{
		snapA:          Snapshot{MonthCostMicros: 600},
		snapB:          Snapshot{MonthCostMicros: 300},
		keyA:           "user:userA",
		keyB:           "user:userB",
		currentUserIsA: false,
	}
	dB := New(snapProviderB, quotaProviderA)
	gotB := dB.Decide(context.Background(), ScopeRef{ProjectID: "pj1", UserID: "userB"})
	if gotB.Action != ActionNone {
		t.Errorf("E2E-3 userB: want ActionNone (within budget), got %s", gotB.Action)
	}
}

// --- E2E-4: Key 级 pause_key → 只封该 key，scope="key" -------------------

func TestE2E_PauseKeyOnlyAffectsThatKey(t *testing.T) {
	// key1 超预算，overage_action=pause_key
	d := newDecider(
		Snapshot{MonthCostMicros: 200},
		"key:key-id-1",
		EffectiveQuotaInput{
			MonthlyBudgetMicros: 100,
			OverageAction:       "pause_key",
			TriggeredScope:      "key",
		},
		"enforce",
	)

	// key1 请求 → 应该 pause
	gotKey1 := d.Decide(context.Background(), ScopeRef{
		TenantID: "ten1",
		UserID:   "user1",
		KeyID:    "key-id-1",
	})
	if gotKey1.Action != ActionPauseKey {
		t.Errorf("E2E-4 key1: want ActionPauseKey, got %s", gotKey1.Action)
	}
	if gotKey1.TriggeredScope != "key" {
		t.Errorf("E2E-4 key1: want TriggeredScope='key', got %q", gotKey1.TriggeredScope)
	}

	// 同 user 另一个 key（key2）用量正常，不应被触发
	d2 := newDecider(
		Snapshot{MonthCostMicros: 50},
		"key:key-id-2",
		EffectiveQuotaInput{
			MonthlyBudgetMicros: 100,
			OverageAction:       "pause_key",
			TriggeredScope:      "key",
		},
		"enforce",
	)
	gotKey2 := d2.Decide(context.Background(), ScopeRef{
		TenantID: "ten1",
		UserID:   "user1",
		KeyID:    "key-id-2",
	})
	if gotKey2.Action != ActionNone {
		t.Errorf("E2E-4 key2: want ActionNone (different key, within budget), got %s", gotKey2.Action)
	}
}

// --- E2E-5: enforcement_mode 从 enforce 改 soft → 相同请求不再被拦截 -------

func TestE2E_EnforcementModeSwitch_EnforceToSoft(t *testing.T) {
	usage := Snapshot{MonthCostMicros: 200}
	quota := EffectiveQuotaInput{
		MonthlyBudgetMicros: 100,
		OverageAction:       "rate_limit",
		TriggeredScope:      "project",
	}
	ref := ScopeRef{TenantID: "ten1", ProjectID: "pj1"}

	// enforce 模式：超预算 → rate_limit
	dEnforce := New(
		&multiSnap{snap: usage, key: "project:pj1"},
		&stubQuota{mode: "enforce", quota: quota},
	)
	gotEnforce := dEnforce.Decide(context.Background(), ref)
	if gotEnforce.Action != ActionRateLimit {
		t.Errorf("E2E-5 enforce: want ActionRateLimit, got %s", gotEnforce.Action)
	}

	// 切换到 soft 模式：相同请求 → ActionAlert (AlertOnly=true)，不再阻断
	dSoft := New(
		&multiSnap{snap: usage, key: "project:pj1"},
		&stubQuota{mode: "soft", quota: quota},
	)
	gotSoft := dSoft.Decide(context.Background(), ref)
	if gotSoft.Action == ActionRateLimit || gotSoft.Action == ActionPauseKey || gotSoft.Action == ActionDowngradeMod {
		t.Errorf("E2E-5 soft: want non-blocking action, got %s", gotSoft.Action)
	}
	if gotSoft.Action == ActionAlert && !gotSoft.AlertOnly {
		t.Error("E2E-5 soft: alert must be AlertOnly=true")
	}
}

// --- E2E-6: bypass mode (UAG_GOVERNOR_DISABLED=true 等价) → ActionNone -----

func TestE2E_KillSwitch_BypassMode_SkipsGovernor(t *testing.T) {
	// 即使预算严重超额，bypass 模式下也应完全放行
	d := newDecider(
		Snapshot{MonthCostMicros: 99999},
		"tenant:ten1",
		EffectiveQuotaInput{
			MonthlyBudgetMicros: 1,
			OverageAction:       "rate_limit",
			TriggeredScope:      "tenant",
		},
		"bypass",
	)

	got := d.Decide(context.Background(), ScopeRef{
		TenantID:  "ten1",
		ProjectID: "pj1",
	})

	if got.Action != ActionNone {
		t.Errorf("E2E-6: bypass mode kill switch — want ActionNone, got %s (governor should be fully disabled)", got.Action)
	}
	// bypass 下不应设置 TriggeredScope / TriggeredMetric
	if got.TriggeredScope != "" || got.TriggeredMetric != "" {
		t.Errorf("E2E-6: bypass mode should not populate TriggeredScope/TriggeredMetric, got scope=%q metric=%q", got.TriggeredScope, got.TriggeredMetric)
	}
}
