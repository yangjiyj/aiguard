package billing

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// EmployeeAllowanceStatus 是员工本人能看到的本月额度状态（聊天门户“客户中心”）。
// 已用只算已结算金额，与预算预警同口径；预占另列，便于员工理解“在途请求”。
type EmployeeAllowanceStatus struct {
	LimitMicros    int64                `json:"limit_micros"`
	UsedMicros     int64                `json:"used_micros"`
	ReservedMicros int64                `json:"reserved_micros"`
	Percent        int64                `json:"percent"`
	Threshold      int                  `json:"threshold"` // 0 / 80 / 100
	Currency       string               `json:"currency"`
	MonthStart     time.Time            `json:"month_start"`
	MonthEnd       time.Time            `json:"month_end"`
	MonthlyStatus  *MonthlyWalletStatus `json:"monthly_status"`
}

// NewEmployeeAllowanceStatus distinguishes an explicit zero cap from an unset cap.
func NewEmployeeAllowanceStatus(a EmployeeAllowance) *EmployeeAllowanceStatus {
	if a.EffectiveMicros == nil {
		return nil
	}
	limit := *a.EffectiveMicros
	return &EmployeeAllowanceStatus{LimitMicros: limit, UsedMicros: a.UsedMicros, ReservedMicros: a.ReservedMicros,
		Percent: budgetPercent(limit, a.UsedMicros), Threshold: budgetThreshold(limit, a.UsedMicros),
		Currency: a.Currency, MonthStart: a.MonthStart, MonthEnd: a.MonthEnd}
}

// EmployeeAllowanceForUser 读取单个员工本月额度（与 ListEmployeeAllowances 同口径），只读该租户该员工。
func (s *Store) EmployeeAllowanceForUser(ctx context.Context, tenantID, userID string, at time.Time) (*EmployeeAllowanceStatus, error) {
	if tenantID == "" || userID == "" {
		return nil, nil
	}
	monthly, err := s.MonthlyWalletStatus(ctx, tenantID, userID, at)
	if errors.Is(err, ErrInvalidWalletState) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	cfg, err := s.GetEmployeeSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	start, end, err := allowanceMonth(at, cfg.Timezone)
	if err != nil {
		return nil, err
	}
	item := EmployeeAllowance{Currency: cfg.Currency, MonthStart: start, MonthEnd: end}
	err = s.db.QueryRow(ctx, `SELECT COALESCE(a.monthly_micros,c.default_monthly_micros),
 COALESCE((SELECT SUM(f.billable_amount_micros) FROM billing_usage_facts f WHERE f.tenant_id=u.tenant_id AND f.user_id=u.id AND f.currency=$3 AND f.status='settled' AND f.usage_source NOT IN ('forward_proxy','reverse_proxy') AND COALESCE(f.admitted_at,f.occurred_at)>=$4 AND COALESCE(f.admitted_at,f.occurred_at)<$5),0)::bigint,
 COALESCE((SELECT SUM(r.amount_micros) FROM billing_employee_reservations r WHERE r.tenant_id=u.tenant_id AND r.user_id=u.id AND r.month_start=$4 AND NOT EXISTS(SELECT 1 FROM billing_usage_facts f WHERE f.tenant_id=r.tenant_id AND f.request_id=r.request_id)),0)::bigint
 FROM users u LEFT JOIN billing_employee_settings c ON c.tenant_id=u.tenant_id LEFT JOIN billing_employee_allowances a ON a.tenant_id=u.tenant_id AND a.user_id=u.id
 WHERE u.tenant_id=$1 AND u.id=$2`, tenantID, userID, cfg.Currency, start, end).Scan(&item.EffectiveMicros, &item.UsedMicros, &item.ReservedMicros)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	status := NewEmployeeAllowanceStatus(item)
	if status == nil && monthly != nil {
		status = &EmployeeAllowanceStatus{Currency: cfg.Currency, MonthStart: start, MonthEnd: end}
	}
	if status != nil {
		status.MonthlyStatus = monthly
		if w, e := s.GetWalletByUser(ctx, tenantID, userID, cfg.Currency); e == nil {
			status.ReservedMicros = int64(w.ReservedMicros)
		} else if !errors.Is(e, pgx.ErrNoRows) {
			return nil, e
		}
	}
	return status, nil
}
