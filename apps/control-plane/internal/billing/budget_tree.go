package billing

import (
	"sort"
	"time"
)

// 预算树：组织总预算 → 部门预算（按部门层级）→ 员工月额度，供“预算与额度”页只读展示。
// 这里只做展示组装，不参与断流判定；判定仍是 evaluateUserCutoff（员工月额度 → 部门/组织/个人预算 → 钱包）。
const (
	BudgetStatusUnlimited = "unlimited" // 未设置预算
	BudgetStatusNormal    = "normal"
	BudgetStatusWarning   = "warning" // 已用 ≥ 80%
	BudgetStatusExhausted = "exhausted"
	BudgetStatusUnknown   = "unknown" // 设置了预算但读不到用量
)

type BudgetTreePolicy struct {
	MonthlyMicros *int64
	Blocked       bool
	Timezone      string
}

type BudgetTreeDepartment struct {
	ID, Name, ParentID string
}

type BudgetTreeEmployee struct {
	UserID, Username, DepartmentID string
	MonthlyMicros                  *int64 // 个人设置；nil 表示跟随新人默认额度
	EffectiveMicros                *int64 // 生效额度；nil 表示未限制
	UsedMicros, ReservedMicros     int64
}

type BudgetTreeInput struct {
	TenantID, TenantName string
	Currency             string
	Departments          []BudgetTreeDepartment
	Employees            []BudgetTreeEmployee
	OrganizationBudget   *BudgetTreePolicy
	OrganizationUsed     *int64
	DepartmentBudgets    map[string]BudgetTreePolicy
	DepartmentUsed       map[string]*int64
	// PersonalBudgets 是旧的用户维度配额月预算（quota_policies scope=user），与员工月额度是两层，都参与断流。
	PersonalBudgets map[string]BudgetTreePolicy
	PersonalUsed    map[string]*int64
	// EmployeeMonthStart 是员工月额度当前周期的开始（员工额度设置的时区），用于预警去重。
	EmployeeMonthStart time.Time
}

type BudgetTreeNode struct {
	Kind           string `json:"kind"` // organization | department | unassigned | employee
	ID             string `json:"id"`
	Name           string `json:"name"`
	BudgetMicros   *int64 `json:"budget_micros"`
	UsedMicros     *int64 `json:"used_micros"`
	ReservedMicros int64  `json:"reserved_micros,omitempty"`
	RemainMicros   *int64 `json:"remaining_micros"`
	Status         string `json:"status"`
	Inherited      bool   `json:"inherited,omitempty"` // 员工：额度来自新人默认额度
	Currency       string `json:"currency"`
	// 员工节点：旧个人预算（如有），单独给出状态，便于发现“员工月额度没用完却被个人预算停用”。
	PersonalBudgetMicros *int64            `json:"personal_budget_micros,omitempty"`
	PersonalUsedMicros   *int64            `json:"personal_used_micros,omitempty"`
	PersonalStatus       string            `json:"personal_status,omitempty"`
	Children             []*BudgetTreeNode `json:"children,omitempty"`
}

// budgetNodeStatus：limit 为 nil 是未设置；0 等于禁止调用（直接视为已用尽）。
func budgetNodeStatus(limit, used *int64) (string, *int64) {
	if limit == nil {
		return BudgetStatusUnlimited, nil
	}
	if *limit <= 0 {
		zero := int64(0)
		return BudgetStatusExhausted, &zero
	}
	if used == nil {
		return BudgetStatusUnknown, nil
	}
	remain := *limit - *used
	if remain <= 0 {
		zero := int64(0)
		return BudgetStatusExhausted, &zero
	}
	// 已用 ≥ 80% ⇔ 剩余*5 ≤ 预算 ⇔ 剩余 ≤ ⌊预算/5⌋（整数下取整精确等价），不做乘法避免大额溢出。
	if remain <= *limit/5 {
		return BudgetStatusWarning, &remain
	}
	return BudgetStatusNormal, &remain
}

func policyLimit(p *BudgetTreePolicy) *int64 {
	if p == nil {
		return nil
	}
	if p.Blocked {
		zero := int64(0)
		return &zero
	}
	// 历史口径：0 表示“本级不限”，不是禁止。
	if p.MonthlyMicros != nil && *p.MonthlyMicros == 0 {
		return nil
	}
	return p.MonthlyMicros
}

func BuildBudgetTree(in BudgetTreeInput) *BudgetTreeNode {
	currency := in.Currency
	if currency == "" {
		currency = "CNY"
	}
	node := func(kind, id, name string, limit, used *int64) *BudgetTreeNode {
		status, remain := budgetNodeStatus(limit, used)
		return &BudgetTreeNode{Kind: kind, ID: id, Name: name, BudgetMicros: limit, UsedMicros: used, RemainMicros: remain, Status: status, Currency: currency}
	}
	root := node("organization", in.TenantID, in.TenantName, policyLimit(in.OrganizationBudget), in.OrganizationUsed)
	depts := map[string]*BudgetTreeNode{}
	for _, d := range in.Departments {
		var p *BudgetTreePolicy
		if v, ok := in.DepartmentBudgets[d.ID]; ok {
			p = &v
		}
		depts[d.ID] = node("department", d.ID, d.Name, policyLimit(p), in.DepartmentUsed[d.ID])
	}
	for _, d := range in.Departments {
		parent := root
		if p, ok := depts[d.ParentID]; ok && d.ParentID != d.ID {
			parent = p
		}
		parent.Children = append(parent.Children, depts[d.ID])
	}
	var unassigned *BudgetTreeNode
	for _, e := range in.Employees {
		used := e.UsedMicros + e.ReservedMicros
		emp := node("employee", e.UserID, e.Username, e.EffectiveMicros, &used)
		emp.UsedMicros = &e.UsedMicros
		emp.ReservedMicros = e.ReservedMicros
		emp.Inherited = e.MonthlyMicros == nil && e.EffectiveMicros != nil
		if p, ok := in.PersonalBudgets[e.UserID]; ok {
			if limit := policyLimit(&p); limit != nil {
				emp.PersonalBudgetMicros = limit
				emp.PersonalUsedMicros = in.PersonalUsed[e.UserID]
				emp.PersonalStatus, _ = budgetNodeStatus(limit, emp.PersonalUsedMicros)
			}
		}
		parent, ok := depts[e.DepartmentID]
		if !ok {
			if unassigned == nil {
				unassigned = &BudgetTreeNode{Kind: "unassigned", ID: "unassigned", Name: "未分配部门", Status: BudgetStatusUnlimited, Currency: currency}
			}
			parent = unassigned
		}
		parent.Children = append(parent.Children, emp)
	}
	if unassigned != nil {
		root.Children = append(root.Children, unassigned)
	}
	sortTree(root)
	return root
}

// 部门在前、员工在后，各自保持输入顺序（部门按层级、员工按用户名）。
func sortTree(n *BudgetTreeNode) {
	sort.SliceStable(n.Children, func(i, j int) bool {
		rank := func(k string) int {
			switch k {
			case "department":
				return 0
			case "unassigned":
				return 1
			}
			return 2
		}
		return rank(n.Children[i].Kind) < rank(n.Children[j].Kind)
	})
	for _, c := range n.Children {
		sortTree(c)
	}
}
