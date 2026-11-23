package repository

import (
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/executionmode"
)

// 策略模拟的“会不会真拦”与数据面同口径：两个键一次读出交给 executionmode.FromValues。
// 2.9.22（D7）：部署变量 SECURITY_AUDIT_ONLY=true 只在库里没有显式执行模式时作初值。
// 合流统一后的行为变化：旧键 security_audit_only 开始生效；读库失败按记录模式；
// 库里什么都没有时按安全默认记录模式（原来按防护模拟）。
func TestSimulationAuditOnlyUsesExecutionModeResolution(t *testing.T) {
	mode := func(v string) map[string]string { return map[string]string{executionmode.SettingKey: v} }
	legacy := func(v string) map[string]string { return map[string]string{executionmode.LegacySettingKey: v} }
	for _, tc := range []struct {
		name   string
		env    string
		values map[string]string
		readOK bool
		want   bool
	}{
		{"显式防护压过部署变量", "true", mode("protect"), true, false},
		{"显式记录", "true", mode("record"), true, true},
		{"部署变量作初值", "true", map[string]string{}, true, true},
		{"部署变量压过旧键", "true", legacy("false"), true, true},
		{"显式防护", "", mode("protect"), true, false},
		{"显式记录无部署变量", "", mode("record"), true, true},
		{"都没有按安全默认记录", "", map[string]string{}, true, true},
		{"nil 按安全默认记录", "", nil, true, true},
		{"部署变量 false 不算初值", "false", mode("protect"), true, false},
		{"旧键 false 生效", "", legacy("false"), true, false},
		{"旧键 true 生效", "", legacy(" TRUE "), true, true},
		{"非法显式值退到旧键", "", map[string]string{executionmode.SettingKey: "block", executionmode.LegacySettingKey: "false"}, true, false},
		{"读库失败按记录", "", mode("protect"), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECURITY_AUDIT_ONLY", tc.env)
			if got := resolveSimulationAuditOnly(tc.values, tc.readOK); got != tc.want {
				t.Fatalf("env=%q values=%v readOK=%v got=%v want=%v", tc.env, tc.values, tc.readOK, got, tc.want)
			}
		})
	}
}
