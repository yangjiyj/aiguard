package billing

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// EmployeeAllowanceCutoff 返回员工月额度是否已用尽（已结算 + 在途预占 >= 额度）。
// 没有配置额度、或额度还有余量时返回 nil。只读，不占用额度。
func (s *Store) EmployeeAllowanceCutoff(ctx context.Context, tenantID, userID string, at time.Time) (*AllowanceExhaustedError, error) {
	if tenantID == "" || userID == "" {
		return nil, nil
	}
	cfg, err := s.GetEmployeeSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	start, end, err := allowanceMonth(at, cfg.Timezone)
	if err != nil {
		return nil, err
	}
	var limit *int64
	var username, department string
	err = s.db.QueryRow(ctx, `SELECT COALESCE(a.monthly_micros,c.default_monthly_micros),u.username,COALESCE(t.name,'')
		FROM users u
		LEFT JOIN billing_employee_settings c ON c.tenant_id=u.tenant_id
		LEFT JOIN billing_employee_allowances a ON a.tenant_id=u.tenant_id AND a.user_id=u.id
		LEFT JOIN teams t ON t.id=u.department_id AND t.tenant_id=u.tenant_id
		WHERE u.tenant_id=$1 AND u.id=$2`, tenantID, userID).Scan(&limit, &username, &department)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && limit == nil) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var used, reserved int64
	err = s.db.QueryRow(ctx, `SELECT
	 COALESCE((SELECT SUM(f.billable_amount_micros) FROM billing_usage_facts f WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.currency=$3 AND f.status='settled' AND f.usage_source NOT IN ('forward_proxy','reverse_proxy') AND COALESCE(f.admitted_at,f.occurred_at)>=$4 AND COALESCE(f.admitted_at,f.occurred_at)<$5),0)::bigint,
	 COALESCE((SELECT SUM(r.amount_micros) FROM billing_employee_reservations r WHERE r.tenant_id=$1 AND r.user_id=$2 AND r.month_start=$4 AND NOT EXISTS(SELECT 1 FROM billing_usage_facts f WHERE f.tenant_id=r.tenant_id AND f.request_id=r.request_id)),0)::bigint`,
		tenantID, userID, cfg.Currency, start, end).Scan(&used, &reserved)
	if err != nil {
		return nil, err
	}
	if used+reserved < *limit {
		return nil, nil
	}
	return &AllowanceExhaustedError{
		UserID: userID, Username: username, DepartmentName: department, Currency: cfg.Currency, Timezone: cfg.Timezone,
		LimitMicros: *limit, UsedMicros: used, ReservedMicros: reserved,
		MonthStart: start, MonthEnd: end,
	}, nil
}

// BudgetPolicyScope 是用户所在链路上一个配置了金额预算的作用域（租户、部门及其祖先、个人）。
type BudgetPolicyScope struct {
	Scope         string `json:"scope"`
	ScopeID       string `json:"scope_id"`
	Name          string `json:"name"`
	MonthlyMicros int64  `json:"monthly_micros"`
	DailyMicros   int64  `json:"daily_micros"`
	Timezone      string `json:"timezone"`
}

// UserBudgetPolicies 返回对该用户生效、且配置了金额预算的策略：租户级、所属部门及全部祖先部门、个人级。
func (s *Store) UserBudgetPolicies(ctx context.Context, tenantID, userID string) ([]BudgetPolicyScope, error) {
	if tenantID == "" || userID == "" {
		return nil, nil
	}
	rows, err := s.db.Query(ctx, `
		WITH me AS (
		  SELECT u.id AS user_id, u.department_id, COALESCE(t.path, '') AS path
		  FROM users u LEFT JOIN teams t ON t.id = u.department_id AND t.tenant_id = u.tenant_id
		  WHERE u.tenant_id = $1 AND u.id = $2
		), chain AS (
		  SELECT ancestor.id, ancestor.name
		  FROM me
		  CROSS JOIN LATERAL unnest(string_to_array(trim(BOTH '/' FROM me.path), '/')) AS path_id(id)
		  JOIN teams ancestor ON ancestor.id = path_id.id AND ancestor.tenant_id = $1
		)
		SELECT p.scope_type,
		       CASE p.scope_type WHEN 'tenant' THEN p.tenant_id WHEN 'team' THEN COALESCE(p.scope_ref,'') WHEN 'user' THEN COALESCE(p.user_id,'') END,
		       COALESCE(chain.name, ''),
		       COALESCE(p.monthly_budget_micros, CASE WHEN COALESCE(p.monthly_budget_limit,0) > 0 THEN ROUND(p.monthly_budget_limit * 1000000)::bigint END, 0),
		       COALESCE(p.daily_budget_micros, CASE WHEN COALESCE(p.daily_budget_limit,0) > 0 THEN ROUND(p.daily_budget_limit * 1000000)::bigint END, 0),
		       COALESCE(p.quota_timezone, 'Asia/Shanghai')
		FROM quota_policies p
		LEFT JOIN chain ON p.scope_type = 'team' AND chain.id = p.scope_ref
		WHERE p.tenant_id = $1 AND p.status = 'active' AND p.enforcement_mode = 'enforce' AND COALESCE(p.overage_action,'rate_limit') <> 'notify'
		  AND (
		    p.scope_type = 'tenant'
		    OR (p.scope_type = 'team' AND p.scope_ref IN (SELECT id FROM chain))
		    OR (p.scope_type = 'user' AND p.user_id = $2)
		  )
		  AND (COALESCE(p.monthly_budget_micros, 0) > 0 OR COALESCE(p.daily_budget_micros, 0) > 0
		       OR COALESCE(p.monthly_budget_limit, 0) > 0 OR COALESCE(p.daily_budget_limit, 0) > 0)
		ORDER BY p.created_at
	`, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("user budget policies: %w", err)
	}
	defer rows.Close()
	result := []BudgetPolicyScope{}
	for rows.Next() {
		var item BudgetPolicyScope
		if err := rows.Scan(&item.Scope, &item.ScopeID, &item.Name, &item.MonthlyMicros, &item.DailyMicros, &item.Timezone); err != nil {
			return nil, fmt.Errorf("scan user budget policy: %w", err)
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

// ResolveUserBySourceIP 通过“登录态映射”把源 IP 归到一个用户：窗口内该 IP 上成功登录的用户必须恰好一人。
// 多人共用同一 IP（NAT、跳板机）时返回空，宁可不归属也不误伤。
func (s *Store) ResolveUserBySourceIP(ctx context.Context, tenantID, sourceIP string, window time.Duration) (string, error) {
	sourceIP = strings.TrimSpace(sourceIP)
	if tenantID == "" || sourceIP == "" {
		return "", nil
	}
	if window <= 0 {
		window = 12 * time.Hour
	}
	rows, err := s.db.Query(ctx, `
		SELECT DISTINCT h.user_id
		FROM user_login_history h
		JOIN users u ON u.id = h.user_id AND u.tenant_id = $1 AND u.status = 'active'
		WHERE h.ip = $2 AND h.success = TRUE AND h.event = 'login' AND h.logged_at >= $3 AND h.user_id IS NOT NULL
		LIMIT 2
	`, tenantID, sourceIP, time.Now().Add(-window))
	if err != nil {
		return "", fmt.Errorf("resolve user by source ip: %w", err)
	}
	defer rows.Close()
	var users []string
	for rows.Next() {
		var userID string
		if err := rows.Scan(&userID); err != nil {
			return "", err
		}
		users = append(users, userID)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(users) != 1 {
		return "", nil
	}
	return users[0], nil
}

// WalletCutoff 报告 prepaid 钱包是否已无可用余额；没有钱包等同于没有余额。
func (s *Store) WalletCutoff(ctx context.Context, tenantID, userID string) (bool, error) {
	if tenantID == "" || userID == "" {
		return false, nil
	}
	var available *int64
	err := s.db.QueryRow(ctx, `SELECT MAX(balance_micros - reserved_micros) FROM billing_wallets WHERE tenant_id = $1 AND user_id = $2 AND (prepaid_configured OR balance_micros<>0)`, tenantID, userID).Scan(&available)
	if err != nil {
		return false, fmt.Errorf("wallet cutoff: %w", err)
	}
	return available != nil && *available <= 0, nil
}

func (s *Store) HasMoneyQuota(ctx context.Context, tenantID, userID string) (bool, error) {
	limited, err := s.HasEmployeeAllowance(ctx, tenantID, userID)
	if err != nil || limited {
		return limited, err
	}
	policies, err := s.UserBudgetPolicies(ctx, tenantID, userID)
	if err != nil || len(policies) > 0 {
		return len(policies) > 0, err
	}
	var exists bool
	err = s.db.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2 AND (prepaid_configured OR balance_micros<>0))`, tenantID, userID).Scan(&exists)
	return exists, err
}
