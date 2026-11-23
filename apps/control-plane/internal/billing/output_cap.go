package billing

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5"
)

// OutputTokenCapForBudget 给“流式超额截断”算出本次请求最多还能产出多少输出 token。
// budget 是本次可用的金额（本次预占 + 剩余额度）。先按 usage（输出置 0）算输入侧费用，
// 剩余部分按输出与推理单价中较贵的一个折算，向下取整，保证截断点不会超出预算。
// 第二个返回值为 false 表示输出免费，没有可计算的上限。
func OutputTokenCapForBudget(usage Usage, price DirectPrice, budget Micros) (int64, bool, error) {
	rate := price.OutputPerMillionMicros
	if price.Extensions.ReasoningPerMillionMicros != nil && *price.Extensions.ReasoningPerMillionMicros > rate {
		rate = *price.Extensions.ReasoningPerMillionMicros
	}
	if rate <= 0 {
		return 0, false, nil
	}
	inputOnly := usage
	inputOnly.OutputTokens, inputOnly.ReasoningTokens, inputOnly.ImageOutputTokens = 0, 0, 0
	charge, err := CalculateDirectCharge(inputOnly, price)
	if err != nil {
		return 0, false, err
	}
	left := budget - charge.TotalMicros
	if left <= 0 {
		return 0, true, nil
	}
	tokens := new(big.Int).Mul(big.NewInt(int64(left)), big.NewInt(ratioScale))
	tokens.Quo(tokens, big.NewInt(int64(rate)))
	if !tokens.IsInt64() {
		return 0, false, nil
	}
	return tokens.Int64(), true, nil
}

// EmployeeAllowanceBudgetFor 返回员工月额度里本次请求可用的金额：额度 - 已结算 - 其他请求的在途预占
// （即“本次预占 + 剩余额度”）。未配置额度时第二个返回值为 false。只读。
func (s *Store) EmployeeAllowanceBudgetFor(ctx context.Context, tenantID, userID, requestID, currency string, at time.Time) (Micros, bool, error) {
	if tenantID == "" || userID == "" {
		return 0, false, nil
	}
	cfg, err := s.GetEmployeeSettings(ctx, tenantID)
	if err != nil {
		return 0, false, err
	}
	if currency != cfg.Currency {
		return 0, false, nil
	}
	start, end, err := allowanceMonth(at, cfg.Timezone)
	if err != nil {
		return 0, false, err
	}
	var limit *int64
	err = s.db.QueryRow(ctx, `SELECT COALESCE(a.monthly_micros,c.default_monthly_micros) FROM users u LEFT JOIN billing_employee_settings c ON c.tenant_id=u.tenant_id LEFT JOIN billing_employee_allowances a ON a.tenant_id=u.tenant_id AND a.user_id=u.id WHERE u.tenant_id=$1 AND u.id=$2`, tenantID, userID).Scan(&limit)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && limit == nil) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	var used, reserved int64
	err = s.db.QueryRow(ctx, `SELECT
	 COALESCE((SELECT SUM(f.billable_amount_micros) FROM billing_usage_facts f WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.currency=$3 AND f.status='settled' AND f.usage_source NOT IN ('forward_proxy','reverse_proxy') AND COALESCE(f.admitted_at,f.occurred_at)>=$4 AND COALESCE(f.admitted_at,f.occurred_at)<$5),0)::bigint,
	 COALESCE((SELECT SUM(r.amount_micros) FROM billing_employee_reservations r WHERE r.tenant_id=$1 AND r.user_id=$2 AND r.month_start=$4 AND r.request_id<>$6 AND NOT EXISTS(SELECT 1 FROM billing_usage_facts f WHERE f.tenant_id=r.tenant_id AND f.request_id=r.request_id)),0)::bigint`,
		tenantID, userID, currency, start, end, requestID).Scan(&used, &reserved)
	if err != nil {
		return 0, false, err
	}
	left := *limit - used - reserved
	if left < 0 {
		left = 0
	}
	return Micros(left), true, nil
}
