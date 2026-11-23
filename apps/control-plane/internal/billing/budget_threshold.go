package billing

import "time"

// 预算 80% / 100% 预警候选：员工月额度、部门预算、组织预算。
//
// 只按已结算金额判断（员工不含未结算预占），避免在途请求随后释放造成误报；部门、组织用量读预算快照，
// 读不到时不猜、不通知。禁止调用（预算为 0 / 已停用）不是“用到了阈值”，不通知。
// 这里只产出候选，去重（每周期每阈值一次）与外发由 opsalert.BudgetThresholdScanner 负责。

const (
	BudgetScopeEmployee     = "employee"
	BudgetScopeDepartment   = "department"
	BudgetScopeOrganization = "organization"
)

type BudgetThresholdCandidate struct {
	TenantID    string
	ScopeType   string
	ScopeID     string
	Name        string
	Threshold   int // 80 或 100：本周期已达到的最高阈值
	Percent     int64
	UsedMicros  int64
	LimitMicros int64
	Currency    string
	PeriodStart time.Time
}

// budgetThreshold 返回已达到的最高阈值（0 表示未到 80%）。与预算树口径一致：
// 已用 ≥ 预算为 100；剩余 ≤ ⌊预算/5⌋ 为 80。
func budgetThreshold(limit, used int64) int {
	if limit <= 0 {
		return 0
	}
	switch remain := limit - used; {
	case remain <= 0:
		return 100
	case remain <= limit/5:
		return 80
	}
	return 0
}

func budgetPercent(limit, used int64) int64 {
	if limit <= 0 {
		return 0
	}
	if used > (1<<62)/100 { // 防溢出；这种量级按 100 倍以上展示即可
		return used / limit * 100
	}
	return used * 100 / limit
}

func policyPeriodStart(at time.Time, timezone string) time.Time {
	if timezone == "" {
		timezone = "Asia/Shanghai"
	}
	start, _, err := allowanceMonth(at, timezone)
	if err != nil {
		start, _, _ = allowanceMonth(at, "Asia/Shanghai")
	}
	return start
}

func BudgetThresholdCandidates(in BudgetTreeInput, at time.Time) []BudgetThresholdCandidate {
	currency := in.Currency
	if currency == "" {
		currency = "CNY"
	}
	var out []BudgetThresholdCandidate
	add := func(scope, id, name string, limit, used int64, period time.Time) {
		if th := budgetThreshold(limit, used); th > 0 {
			out = append(out, BudgetThresholdCandidate{TenantID: in.TenantID, ScopeType: scope, ScopeID: id, Name: name, Threshold: th,
				Percent: budgetPercent(limit, used), UsedMicros: used, LimitMicros: limit, Currency: currency, PeriodStart: period})
		}
	}
	for _, e := range in.Employees {
		if e.EffectiveMicros == nil || *e.EffectiveMicros <= 0 {
			continue
		}
		add(BudgetScopeEmployee, e.UserID, e.Username, *e.EffectiveMicros, e.UsedMicros, in.EmployeeMonthStart)
	}
	names := map[string]string{}
	for _, d := range in.Departments {
		names[d.ID] = d.Name
	}
	for id, p := range in.DepartmentBudgets {
		p := p
		limit, used := policyLimit(&p), in.DepartmentUsed[id]
		if limit == nil || *limit <= 0 || used == nil || names[id] == "" {
			continue
		}
		add(BudgetScopeDepartment, id, names[id], *limit, *used, policyPeriodStart(at, p.Timezone))
	}
	if limit := policyLimit(in.OrganizationBudget); limit != nil && *limit > 0 && in.OrganizationUsed != nil {
		add(BudgetScopeOrganization, in.TenantID, in.TenantName, *limit, *in.OrganizationUsed, policyPeriodStart(at, in.OrganizationBudget.Timezone))
	}
	return out
}
