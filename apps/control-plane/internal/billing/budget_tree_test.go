package billing

import "testing"

func ptr(v int64) *int64 { return &v }

// 预算节点状态：未设置 / 用量未知 / 正常 / 80% 预警 / 已用尽。
func TestBudgetNodeStatus(t *testing.T) {
	cases := []struct {
		name        string
		limit, used *int64
		wantStatus  string
		wantRemain  *int64
	}{
		{name: "未设置预算", limit: nil, used: ptr(5), wantStatus: BudgetStatusUnlimited},
		{name: "预算为 0 等于禁止调用", limit: ptr(0), used: ptr(0), wantStatus: BudgetStatusExhausted, wantRemain: ptr(0)},
		{name: "用量读不到", limit: ptr(100), used: nil, wantStatus: BudgetStatusUnknown},
		{name: "正常", limit: ptr(100), used: ptr(79), wantStatus: BudgetStatusNormal, wantRemain: ptr(21)},
		{name: "80% 预警", limit: ptr(100), used: ptr(80), wantStatus: BudgetStatusWarning, wantRemain: ptr(20)},
		{name: "刚好用尽", limit: ptr(100), used: ptr(100), wantStatus: BudgetStatusExhausted, wantRemain: ptr(0)},
		{name: "超出不出现负剩余", limit: ptr(100), used: ptr(130), wantStatus: BudgetStatusExhausted, wantRemain: ptr(0)},
		{name: "大额不溢出", limit: ptr(9_000_000_000_000_000), used: ptr(7_300_000_000_000_000), wantStatus: BudgetStatusWarning, wantRemain: ptr(1_700_000_000_000_000)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, remain := budgetNodeStatus(tc.limit, tc.used)
			if status != tc.wantStatus {
				t.Fatalf("status=%s want %s", status, tc.wantStatus)
			}
			if (remain == nil) != (tc.wantRemain == nil) || (remain != nil && *remain != *tc.wantRemain) {
				t.Fatalf("remaining=%v want %v", remain, tc.wantRemain)
			}
		})
	}
}

// 部门树按 parent 组装，孤儿部门（父部门不在本租户）挂到组织下，不丢失。
func TestBuildBudgetTreeNestsDepartmentsAndEmployees(t *testing.T) {
	in := BudgetTreeInput{
		TenantID: "t1", TenantName: "某单位",
		Departments: []BudgetTreeDepartment{
			{ID: "d-root", Name: "研发中心"},
			{ID: "d-child", Name: "平台组", ParentID: "d-root"},
			{ID: "d-orphan", Name: "历史部门", ParentID: "missing"},
		},
		Employees: []BudgetTreeEmployee{
			{UserID: "u1", Username: "alice", DepartmentID: "d-child", EffectiveMicros: ptr(1_000_000), UsedMicros: 900_000},
			{UserID: "u2", Username: "bob", EffectiveMicros: nil, UsedMicros: 10},
		},
		OrganizationBudget: &BudgetTreePolicy{MonthlyMicros: ptr(10_000_000)},
		OrganizationUsed:   ptr(1_000_000),
		DepartmentBudgets:  map[string]BudgetTreePolicy{"d-root": {MonthlyMicros: ptr(2_000_000)}},
		DepartmentUsed:     map[string]*int64{"d-root": ptr(2_000_000)},
	}
	root := BuildBudgetTree(in)
	if root.Kind != "organization" || root.Name != "某单位" || root.Status != BudgetStatusNormal {
		t.Fatalf("root=%+v", root)
	}
	if len(root.Children) != 3 {
		t.Fatalf("org children=%d want 3 (研发中心、历史部门、未分配部门的员工)", len(root.Children))
	}
	rd := root.Children[0]
	if rd.ID != "d-root" || rd.Status != BudgetStatusExhausted || len(rd.Children) != 1 || rd.Children[0].ID != "d-child" {
		t.Fatalf("研发中心=%+v", rd)
	}
	child := rd.Children[0]
	if child.Status != BudgetStatusUnlimited || len(child.Children) != 1 || child.Children[0].Status != BudgetStatusWarning {
		t.Fatalf("平台组=%+v", child)
	}
	if root.Children[1].ID != "d-orphan" {
		t.Fatalf("孤儿部门应挂在组织下: %+v", root.Children[1])
	}
	unassigned := root.Children[2]
	if unassigned.Kind != "unassigned" || len(unassigned.Children) != 1 || unassigned.Children[0].ID != "u2" {
		t.Fatalf("未分配部门=%+v", unassigned)
	}
	if unassigned.Children[0].Status != BudgetStatusUnlimited {
		t.Fatalf("未设额度的员工应为未设置: %+v", unassigned.Children[0])
	}
}

// 旧的“个人预算”（用户维度配额）也参与断流判定，树上必须可见，不能被员工月额度遮住。
func TestBuildBudgetTreeShowsLegacyPersonalBudget(t *testing.T) {
	root := BuildBudgetTree(BudgetTreeInput{
		TenantID: "t1", TenantName: "单位",
		Employees:       []BudgetTreeEmployee{{UserID: "u1", Username: "alice", EffectiveMicros: ptr(10_000_000), UsedMicros: 1_000_000}},
		PersonalBudgets: map[string]BudgetTreePolicy{"u1": {MonthlyMicros: ptr(2_000_000)}},
		PersonalUsed:    map[string]*int64{"u1": ptr(2_000_000)},
	})
	emp := root.Children[0].Children[0]
	if emp.Status != BudgetStatusNormal || emp.PersonalBudgetMicros == nil || *emp.PersonalBudgetMicros != 2_000_000 || emp.PersonalStatus != BudgetStatusExhausted {
		t.Fatalf("employee=%+v", emp)
	}
}
