package handler

import (
	"fmt"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// budgetExhaustedCode 是预算断流统一返回的 error.code，OpenAI 与 Anthropic 客户端都按它识别。
const budgetExhaustedCode = "budget_exhausted"

// 被预算断流拒绝的请求写入 request_logs.billing_outcome 的取值，控制台映射为中文“预算用尽被拒”。
const (
	billingOutcomeBudgetExhausted   = "budget_exhausted"
	billingOutcomeBudgetUnpriced    = "budget_unpriced"
	billingOutcomeBudgetUnavailable = "budget_unavailable"
)

// formatBudgetMicros 把微元金额格式化为 ¥1,234.56 / $1,234.56（四舍五入到分，千分位）。
// 符号跟随计价币种，只换符号不做汇率换算；币种为空沿用历史的 ¥。
func formatBudgetMicros(micros int64, currency string) string {
	negative := micros < 0
	if negative {
		micros = -micros
	}
	cents := (micros + 5_000) / 10_000
	whole, fraction := cents/100, cents%100
	digits := fmt.Sprintf("%d", whole)
	var grouped strings.Builder
	for index, digit := range digits {
		if index > 0 && (len(digits)-index)%3 == 0 {
			grouped.WriteByte(',')
		}
		grouped.WriteRune(digit)
	}
	sign := ""
	if negative {
		sign = "-"
	}
	symbol := "¥"
	if strings.EqualFold(strings.TrimSpace(currency), "USD") {
		symbol = "$"
	}
	return fmt.Sprintf("%s%s%s.%02d", sign, symbol, grouped.String(), fraction)
}

func budgetScopeLayer(scope string) string {
	switch scope {
	case "tenant":
		return "组织"
	case "team":
		return "部门"
	case "project":
		return "项目"
	case "user":
		return "个人"
	case "key":
		return "密钥"
	default:
		return "组织"
	}
}

// budgetResetPhrase 返回“11 月 1 日自动恢复”这样的重置说明；未知时间给出通用说法。
func budgetResetPhrase(resetAt time.Time) string {
	if resetAt.IsZero() {
		return "额度重置后自动恢复"
	}
	return fmt.Sprintf("%d 月 %d 日自动恢复", int(resetAt.Month()), resetAt.Day())
}

// budgetExhaustedMessage 生成断流开启后的中文拒绝说明：哪一层用尽、已用/额度、何时恢复。
func budgetExhaustedMessage(limitErr *governor.AdmissionLimitError) string {
	period := "本月"
	if limitErr.Metric == "day_cost_micros" {
		period = "今日"
	}
	layer := budgetScopeLayer(limitErr.Scope)
	name := ""
	if limitErr.ScopeName != "" {
		name = limitErr.ScopeName + "，"
	}
	// 已用 = 已结算 + 在途预占；与额度比较时不会超过额度本身，避免显示“已用 ¥6,000 / ¥5,000”。
	used := limitErr.Used + limitErr.Reserved
	if used > limitErr.Limit {
		used = limitErr.Limit
	}
	return fmt.Sprintf("%s%s预算已用完（%s已用 %s / %s），%s，如需追加请联系管理员",
		period, layer, name, formatBudgetMicros(used, limitErr.Currency), formatBudgetMicros(limitErr.Limit, limitErr.Currency), budgetResetPhrase(limitErr.ResetAt))
}

// legacyQuotaMessage 是未开启断流时的限额拒绝说明（中文化，错误码保持 quota_exceeded）。
func legacyQuotaMessage(limitErr *governor.AdmissionLimitError) string {
	return "组织用量额度已超限，请稍后重试或联系管理员"
}

// markBudgetOutcome 在请求被预算断流拒绝时给信封打上 billing_outcome，
// 随后的 FinalizeRequestLog 会把它写进 request_logs，控制台据此显示“预算用尽被拒”。
func markBudgetOutcome(envelope *modelrouter.RequestEnvelope, outcome string) {
	if envelope != nil && outcome != "" {
		envelope.BillingOutcome = outcome
	}
}
