package handler

import (
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// 提示文案里的金额符号必须跟随币种，不做汇率换算，也不能把美元写成 ¥。
func TestFormatAllowanceMicrosFollowsCurrency(t *testing.T) {
	cases := []struct {
		currency string
		want     string
	}{
		{"CNY", "¥1,234.50"},
		{"USD", "$1,234.50"},
		{"", "¥1,234.50"}, // 历史调用没带币种时沿用旧展示，不抛错
	}
	for _, c := range cases {
		if got := formatAllowanceMicros(1_234_500_000, c.currency); got != c.want {
			t.Fatalf("币种 %q 期望 %s，实际 %s", c.currency, c.want, got)
		}
	}
}

func TestBudgetStatusMessageUsesTenantCurrencySymbol(t *testing.T) {
	policy := billing.BudgetPolicyScope{Scope: "team", ScopeID: "d1", Name: "研发部", Timezone: "UTC"}
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	usd := budgetStatusMessage(policy, "本月", 5_000_000_000, 5_000_000_000, now, false, "USD")
	if !strings.Contains(usd, "$5,000.00 / $5,000.00") || strings.Contains(usd, "¥") {
		t.Fatalf("美元租户的预算提示不应出现 ¥：%s", usd)
	}
	cny := budgetStatusMessage(policy, "今日", 100_000_000, 100_000_000, now, true, "CNY")
	if !strings.Contains(cny, "¥100.00 / ¥100.00") || strings.Contains(cny, "$") {
		t.Fatalf("人民币租户的预算提示应保持 ¥：%s", cny)
	}
}

func TestAllowanceExhaustedMessageUsesErrorCurrency(t *testing.T) {
	err := &billing.AllowanceExhaustedError{Username: "alice", Currency: "USD", Timezone: "UTC", LimitMicros: 2_000_000, UsedMicros: 2_000_000, MonthEnd: time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)}
	msg := allowanceExhaustedMessage(err)
	if !strings.Contains(msg, "$2.00 / $2.00") || strings.Contains(msg, "¥") {
		t.Fatalf("美元额度用尽提示：%s", msg)
	}
	err.Currency = "CNY"
	if msg = allowanceExhaustedMessage(err); !strings.Contains(msg, "¥2.00 / ¥2.00") {
		t.Fatalf("人民币额度用尽提示：%s", msg)
	}
}
