package handler

import (
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
)

// GetBillingBudgetTree 返回“预算与额度”页的预算树（只读）：组织总预算 → 部门预算 → 员工月额度。
//
// 部门与组织的“本月已用”读预算快照（Redis，与断流判定 evaluateUserCutoff 同一数据源）；
// 员工“本月已用”读计费事实，与员工月额度判定同口径。快照不可用时设置了预算的节点显示“用量未知”，
// 绝不把读不到当成 0。平台管理员可读任一租户，单位管理员只读本单位。
func GetBillingBudgetTree(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		tenantID, ok := billingTenant(w, r)
		if !ok {
			return
		}
		// 平台管理员可看任一租户；单位管理员只看本单位（原“配额与限流”页它本就能配组织/部门预算）。
		// 其余角色（含部门负责人、审计员、安全员）一律拒绝，与改造前计费管理接口一致。
		switch {
		case user.Role == "platform_admin":
		case (user.Role == "tenant_owner" || user.Role == "tenant_admin") && tenantID == user.TenantID:
		default:
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions for budget tree")
			return
		}
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing store")
			return
		}
		in, err := store.LoadBudgetTreeInput(r.Context(), tenantID, time.Now().UTC())
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		if deps.BudgetSnapshot != nil {
			scopes := make([]budget.SnapshotScope, 0, len(in.DepartmentBudgets)+len(in.PersonalBudgets)+1)
			if in.OrganizationBudget != nil {
				scopes = append(scopes, budget.SnapshotScope{Scope: "tenant", ID: tenantID, Timezone: in.OrganizationBudget.Timezone})
			}
			for id, p := range in.DepartmentBudgets {
				scopes = append(scopes, budget.SnapshotScope{Scope: "team", ID: id, Timezone: p.Timezone})
			}
			for id, p := range in.PersonalBudgets {
				scopes = append(scopes, budget.SnapshotScope{Scope: "user", ID: id, Timezone: p.Timezone})
			}
			if len(scopes) > 0 {
				usage, snapErr := deps.BudgetSnapshot.Get(r.Context(), tenantID, scopes)
				if snapErr == nil {
					if in.OrganizationBudget != nil {
						v := usage["tenant:"+tenantID].MonthCostMicros
						in.OrganizationUsed = &v
					}
					for id := range in.DepartmentBudgets {
						v := usage["team:"+id].MonthCostMicros
						in.DepartmentUsed[id] = &v
					}
					for id := range in.PersonalBudgets {
						v := usage["user:"+id].MonthCostMicros
						in.PersonalUsed[id] = &v
					}
				}
			}
		}
		writeJSON(w, map[string]any{"data": billing.BuildBudgetTree(in)})
	}
}
