package billing

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"
)

// 月度分账单（内部分账）：选一个月份，按部门汇总；部门下按员工、再按模型拆出调用次数、token、金额。
//
// 口径：
//   - 账期按员工月额度的时区（billing_employee_settings.timezone，默认 Asia/Shanghai）切自然月，
//     与员工月额度“每月 1 日恢复”一致；时间取 COALESCE(admitted_at, occurred_at)。
//   - 已计费金额只累计 status=settled 的事实；未定价（unpriced）与用量未知（usage_unknown）单列为
//     “未计费”，不并入 0 元；失败（failed）与已释放（released）只计调用次数，不计金额。
//   - 只读 billing_usage_facts（追加写、不可改），不重算价格。
type StatementLine struct {
	EstimatedRequests    int64  `json:"estimated_requests"`
	ModelName            string `json:"model_name"`
	Requests             int64  `json:"requests"`
	TotalTokens          int64  `json:"total_tokens"`
	BilledMicros         int64  `json:"billed_micros"`
	BilledRequests       int64  `json:"billed_requests"`
	UnbilledRequests     int64  `json:"unbilled_requests"`
	UnpricedRequests     int64  `json:"unpriced_requests"`
	UsageUnknownRequests int64  `json:"usage_unknown_requests"`
	FailedRequests       int64  `json:"failed_requests"`
}

type StatementEmployee struct {
	UserID   string `json:"user_id"`
	UserName string `json:"user_name"`
	StatementLine
	Models []StatementLine `json:"models"`
}

type StatementDepartment struct {
	DepartmentID   string `json:"department_id"`
	DepartmentName string `json:"department_name"`
	StatementLine
	Employees []StatementEmployee `json:"employees"`
}

type MonthlyStatement struct {
	Month       string                `json:"month"`
	Timezone    string                `json:"timezone"`
	Currency    string                `json:"currency"`
	PeriodStart time.Time             `json:"period_start"`
	PeriodEnd   time.Time             `json:"period_end_exclusive"`
	Total       StatementLine         `json:"total"`
	Departments []StatementDepartment `json:"departments"`
	GeneratedAt time.Time             `json:"generated_at"`
}

var statementMonthPattern = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])$`)

func (l *StatementLine) add(o StatementLine) {
	l.EstimatedRequests += o.EstimatedRequests
	l.Requests += o.Requests
	l.TotalTokens += o.TotalTokens
	l.BilledMicros += o.BilledMicros
	l.BilledRequests += o.BilledRequests
	l.UnbilledRequests += o.UnbilledRequests
	l.UnpricedRequests += o.UnpricedRequests
	l.UsageUnknownRequests += o.UsageUnknownRequests
	l.FailedRequests += o.FailedRequests
}

func (s *Store) MonthlyStatement(ctx context.Context, tenantID, month string) (*MonthlyStatement, error) {
	if tenantID == "" || !statementMonthPattern.MatchString(month) {
		return nil, fmt.Errorf("%w: month must be YYYY-MM", ErrInvalidUsage)
	}
	cfg, err := s.GetEmployeeSettings(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	loc, err := time.LoadLocation(cfg.Timezone)
	if err != nil {
		return nil, err
	}
	first, err := time.ParseInLocation("2006-01", month, loc)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid month", ErrInvalidUsage)
	}
	start, end := first.UTC(), first.AddDate(0, 1, 0).UTC()
	rows, err := s.db.Query(ctx, `
		SELECT COALESCE(department_id,''), COALESCE(NULLIF(department_name,''),''),
		       COALESCE(user_id,''), COALESCE(NULLIF(user_name,''),''), model_name,
		       COUNT(*)::bigint,
		       COALESCE(SUM(prompt_tokens + output_tokens),0)::bigint,
		       COALESCE(SUM(billable_amount_micros) FILTER (WHERE status='settled'),0)::bigint,
		       COUNT(*) FILTER (WHERE status='settled')::bigint,
		       COUNT(*) FILTER (WHERE status='unpriced')::bigint,
		       COUNT(*) FILTER (WHERE status='usage_unknown')::bigint,
		       COUNT(*) FILTER (WHERE status IN ('failed','released'))::bigint,
		       COUNT(*) FILTER (WHERE estimated)::bigint
		FROM billing_usage_facts
		WHERE tenant_id=$1 AND usage_source NOT IN ('forward_proxy','reverse_proxy') AND (currency=$2 OR status IN ('unpriced','usage_unknown','failed','released'))
		  AND COALESCE(admitted_at, occurred_at) >= $3 AND COALESCE(admitted_at, occurred_at) < $4
		GROUP BY 1,2,3,4,5`, tenantID, cfg.Currency, start, end)
	if err != nil {
		return nil, fmt.Errorf("monthly statement: %w", err)
	}
	defer rows.Close()
	type deptAcc struct {
		dept StatementDepartment
		emps map[string]*StatementEmployee
	}
	depts := map[string]*deptAcc{}
	result := &MonthlyStatement{Month: month, Timezone: cfg.Timezone, Currency: cfg.Currency, PeriodStart: start, PeriodEnd: end, GeneratedAt: time.Now().UTC()}
	for rows.Next() {
		var deptID, deptName, userID, userName string
		var line StatementLine
		if err := rows.Scan(&deptID, &deptName, &userID, &userName, &line.ModelName, &line.Requests, &line.TotalTokens,
			&line.BilledMicros, &line.BilledRequests, &line.UnpricedRequests, &line.UsageUnknownRequests, &line.FailedRequests, &line.EstimatedRequests); err != nil {
			return nil, err
		}
		line.UnbilledRequests = line.UnpricedRequests + line.UsageUnknownRequests
		if deptID == "" {
			deptName = "未分配部门"
		} else if deptName == "" {
			deptName = "已删除部门"
		}
		if userName == "" {
			userName = map[bool]string{true: "未识别员工", false: "已删除员工"}[userID == ""]
		}
		acc := depts[deptID]
		if acc == nil {
			acc = &deptAcc{dept: StatementDepartment{DepartmentID: deptID, DepartmentName: deptName}, emps: map[string]*StatementEmployee{}}
			depts[deptID] = acc
		}
		emp := acc.emps[userID]
		if emp == nil {
			emp = &StatementEmployee{UserID: userID, UserName: userName}
			acc.emps[userID] = emp
		}
		emp.Models = append(emp.Models, line)
		emp.add(line)
		acc.dept.add(line)
		result.Total.add(line)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// 排序：金额从高到低；未分配部门放最后；同额按名称，保证导出稳定。
	byBilled := func(a, b StatementLine, an, bn string) bool {
		if a.BilledMicros != b.BilledMicros {
			return a.BilledMicros > b.BilledMicros
		}
		if a.Requests != b.Requests {
			return a.Requests > b.Requests
		}
		return an < bn
	}
	for _, acc := range depts {
		for _, emp := range acc.emps {
			sort.Slice(emp.Models, func(i, j int) bool {
				return byBilled(emp.Models[i], emp.Models[j], emp.Models[i].ModelName, emp.Models[j].ModelName)
			})
			acc.dept.Employees = append(acc.dept.Employees, *emp)
		}
		sort.Slice(acc.dept.Employees, func(i, j int) bool {
			a, b := acc.dept.Employees[i], acc.dept.Employees[j]
			return byBilled(a.StatementLine, b.StatementLine, a.UserName, b.UserName)
		})
		result.Departments = append(result.Departments, acc.dept)
	}
	sort.Slice(result.Departments, func(i, j int) bool {
		a, b := result.Departments[i], result.Departments[j]
		if (a.DepartmentID == "") != (b.DepartmentID == "") {
			return b.DepartmentID == ""
		}
		return byBilled(a.StatementLine, b.StatementLine, a.DepartmentName, b.DepartmentName)
	})
	if result.Departments == nil {
		result.Departments = []StatementDepartment{}
	}
	return result, nil
}
