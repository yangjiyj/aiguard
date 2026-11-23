package billing

import (
	"testing"
	"time"
)

func i64(v int64) *int64 { return &v }

func TestBudgetThresholdCandidatesCoverEmployeeDepartmentOrganization(t *testing.T) {
	at := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	monthStart := time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)
	in := BudgetTreeInput{
		TenantID: "t", TenantName: "XX科技", Currency: "CNY", EmployeeMonthStart: monthStart,
		Departments:        []BudgetTreeDepartment{{ID: "d1", Name: "研发部"}, {ID: "d2", Name: "市场部"}, {ID: "d3", Name: "法务部"}},
		OrganizationBudget: &BudgetTreePolicy{MonthlyMicros: i64(1000), Timezone: "Asia/Shanghai"},
		OrganizationUsed:   i64(1000),
		DepartmentBudgets: map[string]BudgetTreePolicy{
			"d1": {MonthlyMicros: i64(100), Timezone: "Asia/Shanghai"},
			"d2": {MonthlyMicros: i64(100), Timezone: "Asia/Shanghai"},
			"d3": {MonthlyMicros: i64(100), Blocked: true, Timezone: "Asia/Shanghai"},
		},
		DepartmentUsed: map[string]*int64{"d1": i64(80), "d2": i64(79), "d3": i64(0)},
		Employees: []BudgetTreeEmployee{
			{UserID: "u1", Username: "张三", EffectiveMicros: i64(1000), UsedMicros: 800, ReservedMicros: 0},
			// 预占不计入：只按已结算金额判断，避免在途请求随后释放造成误报
			{UserID: "u2", Username: "李四", EffectiveMicros: i64(1000), UsedMicros: 700, ReservedMicros: 300},
			{UserID: "u3", Username: "王五", EffectiveMicros: i64(1000), UsedMicros: 1200},
			{UserID: "u4", Username: "赵六", EffectiveMicros: nil, UsedMicros: 99999},
			{UserID: "u5", Username: "孙七", EffectiveMicros: i64(0), UsedMicros: 0},
		},
	}
	got := map[string]BudgetThresholdCandidate{}
	for _, c := range BudgetThresholdCandidates(in, at) {
		got[c.ScopeType+":"+c.ScopeID] = c
	}
	if len(got) != 4 {
		t.Fatalf("candidates = %#v", got)
	}
	if c := got["employee:u1"]; c.Threshold != 80 || c.Name != "张三" || !c.PeriodStart.Equal(monthStart) || c.Percent != 80 {
		t.Fatalf("u1 = %#v", c)
	}
	if c := got["employee:u3"]; c.Threshold != 100 || c.Percent != 120 {
		t.Fatalf("u3 = %#v", c)
	}
	if c := got["department:d1"]; c.Threshold != 80 || c.Name != "研发部" || !c.PeriodStart.Equal(monthStart) {
		t.Fatalf("d1 = %#v", c)
	}
	if c := got["organization:t"]; c.Threshold != 100 || c.Name != "XX科技" {
		t.Fatalf("org = %#v", c)
	}
	for _, absent := range []string{"employee:u2", "employee:u4", "employee:u5", "department:d2", "department:d3"} {
		if _, ok := got[absent]; ok {
			t.Fatalf("%s 不应触发", absent)
		}
	}
	// 读不到部门/组织用量（预算快照不可用）时不猜、不通知
	in.OrganizationUsed, in.DepartmentUsed = nil, map[string]*int64{}
	for _, c := range BudgetThresholdCandidates(in, at) {
		if c.ScopeType != "employee" {
			t.Fatalf("用量未知不应触发: %#v", c)
		}
	}
}
