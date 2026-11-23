package handler

import "testing"

// 任务 3.2：个人月度预算接入 governor（P1-6，支柱③）。
//
// 现状根因：PatchUserPersonalBudget 只写 users.personal_monthly_budget_cny，
// 完全不 upsert quota_policies；而 gateway-core governor 只从 quota_policies
// 读取（quota_cache.go：scope_type='user' AND user_id=$3），故个人月度预算
// 永远到不了 governor，个人维度护栏永远空跑。
//
// 设计（与 3.1 团队预算对称，reject-not-coerce）：新增纯函数 buildUserQuotaPolicy，
// 把个人预算请求映射为 quota_policies 行（scope_type=user，填 UserID 不填 ScopeRef——
// 与 governor 的 user_id 匹配列严格对齐）；enforcement_mode/overage_action 复用同包
// normalizeEnforcementMode/normalizeOverageAction 白名单：空串向后兼容回退 soft/notify，
// 合法透传，非法返回 error 由 handler 回 400，绝不静默降级（个人预算同样不能 fail-open）。

func TestBuildUserQuotaPolicy_ReadsEnforcementAndUserScope(t *testing.T) {
	p, err := buildUserQuotaPolicy("tenant-1", "user-1", 300, "enforce", "rate_limit")
	if err != nil {
		t.Fatalf("合法配置不应报错：%v", err)
	}
	if p.ScopeType != "user" {
		t.Fatalf("scope_type 应为 user，实际 %q", p.ScopeType)
	}
	// 关键差异化断言：user 维度必须落在 user_id 列，scope_ref 必须为空——
	// 否则既匹配不上 governor 的 user_id=$3，又可能污染 team 的 scope_ref 匹配。
	if p.UserID != "user-1" {
		t.Fatalf("user 维度应填 UserID=user-1，实际 %q", p.UserID)
	}
	if p.ScopeRef != "" {
		t.Fatalf("user 维度不应写 ScopeRef（会污染 team 匹配），实际 %q", p.ScopeRef)
	}
	if p.KeyPrefix != "" {
		t.Fatalf("user 维度不应写 KeyPrefix，实际 %q", p.KeyPrefix)
	}
	if p.EnforcementMode != "enforce" {
		t.Fatalf("enforcement_mode 应读取请求值 enforce，实际 %q（硬编码 soft 回归）", p.EnforcementMode)
	}
	if p.OverageAction != "rate_limit" {
		t.Fatalf("overage_action 应读取请求值 rate_limit，实际 %q（硬编码 notify 回归）", p.OverageAction)
	}
	if p.MonthlyBudgetLimit != 300 {
		t.Fatalf("月度预算映射错误：monthly=%v", p.MonthlyBudgetLimit)
	}
	if p.TenantID != "tenant-1" || p.Status != "active" {
		t.Fatalf("租户/状态映射错误：tenant=%q status=%q", p.TenantID, p.Status)
	}
}

func TestBuildUserQuotaPolicy_DefaultsZeroAndWhitelist(t *testing.T) {
	// 空值 → 安全默认 soft/notify（兼容旧前端：只传 personal_monthly_budget_cny），不报错。
	def, err := buildUserQuotaPolicy("t", "u", 100, "", "")
	if err != nil {
		t.Fatalf("空值应回退默认而非报错：%v", err)
	}
	if def.EnforcementMode != "soft" || def.OverageAction != "notify" {
		t.Fatalf("空枚举应回退 soft/notify，实际 mode=%q action=%q", def.EnforcementMode, def.OverageAction)
	}

	// monthly=0（清空预算 / 调用方传 nil 时由 handler 解引用为 0）→ 写入 0，
	// governor 视 MonthlyBudgetLimit==0 为不约束（inert），策略仍 active 不报错。
	zero, err := buildUserQuotaPolicy("t", "u", 0, "soft", "notify")
	if err != nil {
		t.Fatalf("monthly=0 应可写入 inert 策略而非报错：%v", err)
	}
	if zero.MonthlyBudgetLimit != 0 {
		t.Fatalf("monthly=0 应写 0（inert），实际 %v", zero.MonthlyBudgetLimit)
	}

	// 非法 enforcement_mode → 拒绝（error + nil），绝不静默降级为 soft。
	if p, err := buildUserQuotaPolicy("t", "u", 100, "ENFORCE_HARD", "notify"); err == nil || p != nil {
		t.Fatalf("非法 enforcement_mode 应返回 error 且 policy 为 nil，实际 err=%v p=%v", err, p)
	}
	// 非法 overage_action → 拒绝（与 SetQuotaPolicy 一致）。
	if p, err := buildUserQuotaPolicy("t", "u", 100, "enforce", "delete_everything"); err == nil || p != nil {
		t.Fatalf("非法 overage_action 应返回 error 且 policy 为 nil，实际 err=%v p=%v", err, p)
	}

	// 只有所有入口都可执行的动作才允许新配置。
	got, err := buildUserQuotaPolicy("t", "u", 1, "bypass", "rate_limit")
	if err != nil {
		t.Fatalf("合法枚举不应报错：%v", err)
	}
	if got.EnforcementMode != "bypass" || got.OverageAction != "rate_limit" {
		t.Fatalf("合法枚举应透传：mode=%q action=%q", got.EnforcementMode, got.OverageAction)
	}
	for _, unsupported := range []string{"pause_key", "downgrade_model"} {
		if policy, err := buildUserQuotaPolicy("t", "u", 1, "enforce", unsupported); err == nil || policy != nil {
			t.Fatalf("未完整执行的动作 %q 必须拒绝，得到 policy=%v err=%v", unsupported, policy, err)
		}
	}
}
