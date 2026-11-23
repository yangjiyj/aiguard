package handler

import (
	"encoding/json"
	"net/http"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// dataSecurityPackItem 是「内容和数据安全」配置页只读展示的一条预置规则。
// 它直接来自引擎按方案A编译下发的同一批内置规则，是「当前生效数据安全规则」的单一事实源——
// 字段全部给人看（规则名/类型/分级/动作），不暴露内部 ID 编码以外的实现细节。
type dataSecurityPackItem struct {
	RuleID    string `json:"rule_id"`
	Name      string `json:"name"`
	Category  string `json:"category"`
	RuleType  string `json:"rule_type"`
	DataLevel string `json:"data_level"` // L1–L4，来自 scope_json.data_level
	Severity  string `json:"severity"`
	Action    string `json:"action"`
}

// buildDataSecurityPack 把内置规则转成给人看的预置包条目：
// 分级取自 scope_json.data_level（缺省 L1）；category 取自 match_config_json，空则回退 rule_type，
// 与编译器「category 默认等于 rule_type」的口径一致，保证展示与下发同源。
func buildDataSecurityPack(rules []*repository.Rule) []dataSecurityPackItem {
	items := make([]dataSecurityPackItem, 0, len(rules))
	for _, rule := range rules {
		var scope struct {
			DataLevel string `json:"data_level"`
		}
		_ = json.Unmarshal(rule.ScopeJSON, &scope)
		dataLevel := scope.DataLevel
		if dataLevel == "" {
			dataLevel = "L1"
		}
		var match struct {
			Category string `json:"category"`
		}
		_ = json.Unmarshal(rule.MatchConfigJSON, &match)
		category := match.Category
		if category == "" {
			category = rule.RuleType
		}
		items = append(items, dataSecurityPackItem{
			RuleID:    rule.ID,
			Name:      rule.Name,
			Category:  category,
			RuleType:  rule.RuleType,
			DataLevel: dataLevel,
			Severity:  rule.Severity,
			Action:    rule.Action,
		})
	}
	return items
}

// writeIndustryPack 输出 {industry, packs:[…]}：行业 + 该行业当前生效的内置数据安全预置包。
// packs 与引擎实际编译下发的规则同源（同一 industry 过滤口径），杜绝「配置页所见≠引擎所防」。
func writeIndustryPack(w http.ResponseWriter, deps *Dependencies, r *http.Request, industry string) {
	industry = normalizeIndustry(industry)
	rulesList, err := deps.RuleRepo.ListBuiltinDataSecurityRules(r.Context(), industry)
	if err != nil {
		writeError(w, "internal_error", "failed to list builtin data security rules")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"industry": industry,
		"packs":    buildDataSecurityPack(rulesList),
	})
}

// GetContentSecurityIndustry 返回当前租户行业 + 该行业当前生效的内置数据安全预置包（只读展示）。
// 租户在服务端经登录态解析（auth.GetUser），前端不传 tenant id；任意本租户登录用户可查看。
func GetContentSecurityIndustry(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "user not found")
			return
		}
		tenant, err := deps.TenantRepo.GetByID(r.Context(), user.TenantID)
		if err != nil || tenant == nil {
			writeError(w, "internal_error", "failed to load tenant")
			return
		}
		writeIndustryPack(w, deps, r, tenant.Industry)
	}
}

type updateContentSecurityIndustryRequest struct {
	Industry string `json:"industry"`
}

// UpdateContentSecurityIndustry 切换当前租户行业，自动挂载对应内置数据安全预置包。
//
// 安全要点：
//   - 仅管理员（platform_admin / tenant_owner）可改；租户经登录态解析，前端不传 tenant id。
//   - industry 经 normalizeIndustry 白名单收敛，非法输入兜底 generic，绝不落库任意值。
//   - 只更新 industry：先 GetByID 读当前行，再以原 name/edition/status 回填 Update——
//     因为 TenantRepository.Update 是整行 SET，若直接用请求体会抹掉租户名/版本/状态。
func UpdateContentSecurityIndustry(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := requireContentSecurityAdmin(w, r)
		if user == nil {
			return
		}
		var req updateContentSecurityIndustryRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request", "invalid JSON format")
			return
		}
		industry := normalizeIndustry(req.Industry)

		tenant, err := deps.TenantRepo.GetByID(r.Context(), user.TenantID)
		if err != nil || tenant == nil {
			writeError(w, "internal_error", "failed to load tenant")
			return
		}
		// 只改 industry，其余字段原样回填（Update 为整行 SET，缺字段会被清空）。
		tenant.Industry = industry
		if err := deps.TenantRepo.Update(r.Context(), tenant); err != nil {
			writeError(w, "internal_error", "failed to update tenant industry")
			return
		}
		logAudit(r, deps, "content_security.industry.update",
			map[string]any{"tenant_id": user.TenantID, "industry": industry},
			"tenant", user.TenantID)

		writeIndustryPack(w, deps, r, industry)
	}
}
