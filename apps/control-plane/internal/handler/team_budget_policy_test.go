package handler

import "testing"

// 任务 3.1：团队预算从硬编码→可配（P1-5，支柱③）。
//
// 现状根因：UpdateTeamBudget 把 quota_policies 的 enforcement_mode/overage_action
// 硬编码为 soft/notify，团队预算无论管理员意图如何都永远只监控、不拦截。
//
// 设计分叉裁决（reject-not-coerce）：同包已存在 normalizeOverageAction（handler.go），
// 其契约是「空→notify 默认、合法透传、非法→"" 由调用方拒绝」，canonical 的 SetQuotaPolicy
// 对非法 overage_action 直接回 400。本任务复用该契约，而非另造一套静默降级白名单——
// 安全控制宁可拒绝也不能把打字错误（如 "ENFORCE" 拼错）悄悄降级成 soft/放行（静默 fail-open，
// 管理员以为预算在拦截、实则只监控）。故 buildTeamQuotaPolicy 对非法枚举返回 error，
// 由 handler 回 400；空串才向后兼容回退 soft/notify。

func TestBuildTeamQuotaPolicy_ReadsEnforcementFromRequest(t *testing.T) {
	p, err := buildTeamQuotaPolicy("tenant-1", "team-1", 500, 50, "enforce", "rate_limit")
	if err != nil {
		t.Fatalf("合法配置不应报错：%v", err)
	}
	if p.EnforcementMode != "enforce" {
		t.Fatalf("enforcement_mode 应读取请求值 enforce，实际 %q（硬编码 soft 回归）", p.EnforcementMode)
	}
	if p.OverageAction != "rate_limit" {
		t.Fatalf("overage_action 应读取请求值 rate_limit，实际 %q（硬编码 notify 回归）", p.OverageAction)
	}
	if p.ScopeType != "team" || p.ScopeRef != "team-1" {
		t.Fatalf("team scope 映射错误：scope_type=%q scope_ref=%q", p.ScopeType, p.ScopeRef)
	}
	if p.MonthlyBudgetLimit != 500 || p.DailyBudgetLimit != 50 {
		t.Fatalf("预算额度映射错误：monthly=%v daily=%v", p.MonthlyBudgetLimit, p.DailyBudgetLimit)
	}
	if p.TenantID != "tenant-1" || p.Status != "active" {
		t.Fatalf("租户/状态映射错误：tenant=%q status=%q", p.TenantID, p.Status)
	}
}

func TestBuildTeamQuotaPolicy_DefaultsAndWhitelist(t *testing.T) {
	// 空值 → 安全默认 soft/notify（兼容旧客户端：不传即沿用原软限行为），不报错。
	def, err := buildTeamQuotaPolicy("t", "tm", 100, 0, "", "")
	if err != nil {
		t.Fatalf("空值应回退默认而非报错：%v", err)
	}
	if def.EnforcementMode != "soft" {
		t.Fatalf("空 enforcement_mode 应回退 soft，实际 %q", def.EnforcementMode)
	}
	if def.OverageAction != "notify" {
		t.Fatalf("空 overage_action 应回退 notify，实际 %q", def.OverageAction)
	}

	// 非法 enforcement_mode → 拒绝（返回 error + nil 策略），绝不静默降级为 soft。
	if p, err := buildTeamQuotaPolicy("t", "tm", 100, 0, "ENFORCE_HARD", "notify"); err == nil || p != nil {
		t.Fatalf("非法 enforcement_mode 应返回 error 且 policy 为 nil，实际 err=%v p=%v", err, p)
	}
	// 非法 overage_action → 拒绝（与 SetQuotaPolicy 一致）。
	if p, err := buildTeamQuotaPolicy("t", "tm", 100, 0, "enforce", "delete_everything"); err == nil || p != nil {
		t.Fatalf("非法 overage_action 应返回 error 且 policy 为 nil，实际 err=%v p=%v", err, p)
	}

	// 只有所有入口都可执行的动作才允许新配置。
	got, err := buildTeamQuotaPolicy("t", "tm", 1, 0, "bypass", "rate_limit")
	if err != nil {
		t.Fatalf("合法枚举不应报错：%v", err)
	}
	if got.EnforcementMode != "bypass" || got.OverageAction != "rate_limit" {
		t.Fatalf("合法枚举应透传：mode=%q action=%q", got.EnforcementMode, got.OverageAction)
	}
	for _, unsupported := range []string{"pause_key", "downgrade_model"} {
		if policy, err := buildTeamQuotaPolicy("t", "tm", 1, 0, "enforce", unsupported); err == nil || policy != nil {
			t.Fatalf("未完整执行的动作 %q 必须拒绝，得到 policy=%v err=%v", unsupported, policy, err)
		}
	}
}
