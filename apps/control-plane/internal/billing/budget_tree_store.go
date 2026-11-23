package billing

import (
	"context"
	"fmt"
	"time"
)

// LoadBudgetTreeInput 读取预算树需要的结构与配置：租户名、部门层级、员工本月额度与已用、
// 组织与部门的生效月预算。部门/组织的“本月已用”由调用方从预算快照（与断流判定同一数据源）补齐。
//
// 预算口径与断流判定 UserBudgetPolicies 一致：只取 status=active 且 enforcement_mode 为
// soft/enforce 的策略；bypass 策略不参与断流，所以树上也按“未设置”展示。
func (s *Store) LoadBudgetTreeInput(ctx context.Context, tenantID string, at time.Time) (BudgetTreeInput, error) {
	in := BudgetTreeInput{TenantID: tenantID, DepartmentBudgets: map[string]BudgetTreePolicy{}, DepartmentUsed: map[string]*int64{}, PersonalBudgets: map[string]BudgetTreePolicy{}, PersonalUsed: map[string]*int64{}}
	if tenantID == "" {
		return in, ErrInvalidWalletState
	}
	if err := s.db.QueryRow(ctx, `SELECT COALESCE(name,id) FROM tenants WHERE id=$1`, tenantID).Scan(&in.TenantName); err != nil {
		return in, fmt.Errorf("budget tree tenant: %w", err)
	}
	cfg, err := s.GetEmployeeSettings(ctx, tenantID)
	if err != nil {
		return in, err
	}
	in.Currency = cfg.Currency
	rows, err := s.db.Query(ctx, `SELECT id,name,COALESCE(parent_team_id,'') FROM teams WHERE tenant_id=$1 ORDER BY path, name`, tenantID)
	if err != nil {
		return in, fmt.Errorf("budget tree teams: %w", err)
	}
	for rows.Next() {
		var d BudgetTreeDepartment
		if err := rows.Scan(&d.ID, &d.Name, &d.ParentID); err != nil {
			rows.Close()
			return in, err
		}
		in.Departments = append(in.Departments, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return in, err
	}

	policies, err := s.db.Query(ctx, `
		SELECT scope_type, CASE WHEN scope_type='user' THEN COALESCE(user_id,'') ELSE COALESCE(scope_ref,'') END,
		       COALESCE(monthly_budget_micros, CASE WHEN COALESCE(monthly_budget_limit,0) > 0 THEN ROUND(monthly_budget_limit * 1000000)::bigint END),
		       COALESCE(monthly_budget_blocked,false), COALESCE(quota_timezone,'Asia/Shanghai')
		FROM quota_policies
		WHERE tenant_id=$1 AND status='active' AND enforcement_mode IN ('soft','enforce') AND scope_type IN ('tenant','team','user')
		ORDER BY created_at`, tenantID)
	if err != nil {
		return in, fmt.Errorf("budget tree policies: %w", err)
	}
	for policies.Next() {
		var scope, ref, tz string
		var monthly *int64
		var blocked bool
		if err := policies.Scan(&scope, &ref, &monthly, &blocked, &tz); err != nil {
			policies.Close()
			return in, err
		}
		p := BudgetTreePolicy{MonthlyMicros: monthly, Blocked: blocked, Timezone: tz}
		switch {
		case scope == "tenant":
			in.OrganizationBudget = &p
		case scope == "team" && ref != "":
			in.DepartmentBudgets[ref] = p
		case scope == "user" && ref != "":
			in.PersonalBudgets[ref] = p
		}
	}
	policies.Close()
	if err := policies.Err(); err != nil {
		return in, err
	}

	start, end, err := allowanceMonth(at, cfg.Timezone)
	if err != nil {
		return in, err
	}
	in.EmployeeMonthStart = start
	// 与 ListEmployeeAllowances 同口径（只算 settled 事实 + 未结算预占），多返回部门 ID 用于挂树。
	emps, err := s.db.Query(ctx, `SELECT u.id,u.username,COALESCE(u.department_id,''),a.monthly_micros,COALESCE(a.monthly_micros,c.default_monthly_micros),
 COALESCE((SELECT SUM(f.billable_amount_micros) FROM billing_usage_facts f WHERE f.tenant_id=u.tenant_id AND f.user_id=u.id AND f.currency=$2 AND f.status='settled' AND f.usage_source NOT IN ('forward_proxy','reverse_proxy') AND COALESCE(f.admitted_at,f.occurred_at)>=$3 AND COALESCE(f.admitted_at,f.occurred_at)<$4),0)::bigint,
 COALESCE((SELECT SUM(r.amount_micros) FROM billing_employee_reservations r WHERE r.tenant_id=u.tenant_id AND r.user_id=u.id AND r.month_start=$3 AND NOT EXISTS(SELECT 1 FROM billing_usage_facts f WHERE f.tenant_id=r.tenant_id AND f.request_id=r.request_id)),0)::bigint
 FROM users u LEFT JOIN billing_employee_settings c ON c.tenant_id=u.tenant_id LEFT JOIN billing_employee_allowances a ON a.tenant_id=u.tenant_id AND a.user_id=u.id
 WHERE u.tenant_id=$1 AND u.status NOT IN ('deleted','retired') AND u.role <> 'platform_connector' ORDER BY u.username LIMIT 2000`, tenantID, cfg.Currency, start, end)
	if err != nil {
		return in, fmt.Errorf("budget tree employees: %w", err)
	}
	defer emps.Close()
	for emps.Next() {
		var e BudgetTreeEmployee
		if err := emps.Scan(&e.UserID, &e.Username, &e.DepartmentID, &e.MonthlyMicros, &e.EffectiveMicros, &e.UsedMicros, &e.ReservedMicros); err != nil {
			return in, err
		}
		in.Employees = append(in.Employees, e)
	}
	return in, emps.Err()
}
