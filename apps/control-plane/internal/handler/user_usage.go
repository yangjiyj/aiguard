package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 用户级用量看板：管理员下钻查看指定用户的用量。仅 platform_admin/tenant_owner/tenant_admin 可调用。
// 复用 usage_rollup_hourly 读模型与现有 repository 查询，通过构造「强制单用户」的 UsageScope 实现过滤，
// 不新增迁移、不新增物化表。

// isAdminRole 判断是否为可管理他人的角色。
func isAdminRole(role string) bool {
	return role == "platform_admin" || role == "tenant_owner" || role == "tenant_admin" || role == "admin"
}

// resolveTargetUser 取出路径里的 user_id，校验存在性 + 跨租户越权防护。
// 返回 (target, current, ok)；ok=false 时响应已写出。
func resolveTargetUser(w http.ResponseWriter, r *http.Request, deps *Dependencies) (*repository.User, *repository.User, bool) {
	if deps == nil || deps.UserRepo == nil {
		writeError(w, "internal_error", "user repository is not configured")
		return nil, nil, false
	}
	current := auth.GetUser(r.Context())
	if current == nil {
		writeUnauthorized(w, "user not found")
		return nil, nil, false
	}
	if !isAdminRole(current.Role) {
		writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "仅管理员可查看他人用量")
		return nil, nil, false
	}
	targetID := chi.URLParam(r, "user_id")
	if targetID == "" {
		writeError(w, "invalid_request", "user_id is required")
		return nil, nil, false
	}
	target, err := deps.UserRepo.GetByID(r.Context(), targetID)
	if err != nil || target == nil {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "用户不存在")
		return nil, nil, false
	}
	// 跨租户防护：非平台超管只能看本租户用户。
	if current.Role != "platform_admin" && target.TenantID != current.TenantID {
		writeErrorWithStatus(w, http.StatusNotFound, "not_found", "用户不存在")
		return nil, nil, false
	}
	return target, current, true
}

// forcedUserScope 构造一个「强制限定到指定用户」的 UsageScope。
// FullTenant=false 且无 ProjectIDs，使 usageScopeWhereRollup/usageScopeWhere 自动追加 user_id 过滤。
func forcedUserScope(target *repository.User) repository.UsageScope {
	return repository.UsageScope{
		TenantID:   target.TenantID,
		UserID:     target.ID,
		FullTenant: false,
	}
}

// userUsageSummaryResponse 个人用量汇总，带环比。
type userUsageSummaryResponse struct {
	Requests        int     `json:"requests"`
	SuccessRequests int     `json:"success_requests"`
	InputTokens     int64   `json:"input_tokens"`
	OutputTokens    int64   `json:"output_tokens"`
	TotalTokens     int64   `json:"total_tokens"`
	TotalCost       float64 `json:"total_cost"`
	SuccessRate     float64 `json:"success_rate"` // 成功率（百分比）
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	// 环比：与上一等长周期对比的变化率（百分比，正增负减）。无对比基准时为 null。
	RequestsChange       *float64 `json:"requests_change"`
	InputTokensChange    *float64 `json:"input_tokens_change"`
	OutputTokensChange   *float64 `json:"output_tokens_change"`
	TotalCostChange      *float64 `json:"total_cost_change"`
	TotalTokensChange    *float64 `json:"total_tokens_change"`
}

func pctChange(curr, prev float64) *float64 {
	if prev == 0 {
		if curr == 0 {
			return nil
		}
		v := 100.0 // 从 0 到非 0 视为 +100%
		return &v
	}
	v := (curr - prev) / prev * 100
	return &v
}

// GetUserUsageSummary GET /admin/v1/users/{user_id}/usage/summary?start_date&end_date
// 返回该用户区间汇总 + 环比（与上一等长周期对比）。
func GetUserUsageSummary(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.UsageRollupRepo == nil {
			writeError(w, "internal_error", "usage repository is not configured")
			return
		}
		target, _, ok := resolveTargetUser(w, r, deps)
		if !ok {
			return
		}
		scope := forcedUserScope(target)
		startDate, endDate := parseUsageRange(r)
		curr, err := deps.UsageRollupRepo.GetUsageSummaryScoped(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get user usage summary")
			return
		}
		// 等长上一期
		dur := endDate.Sub(startDate)
		prevStart := startDate.Add(-dur)
		prevEnd := startDate
		prev, err := deps.UsageRollupRepo.GetUsageSummaryScoped(r.Context(), scope, prevStart, prevEnd)
		if err != nil {
			prev = &repository.UsageRollupSummary{}
		}

		resp := userUsageSummaryResponse{
			Requests:        curr.Requests,
			SuccessRequests: curr.SuccessRequests,
			InputTokens:     curr.InputTokens,
			OutputTokens:    curr.OutputTokens,
			TotalTokens:     curr.TotalTokens(),
			TotalCost:       curr.TotalCost,
		}
		if curr.Requests > 0 {
			resp.SuccessRate = float64(curr.SuccessRequests) / float64(curr.Requests) * 100
		}
		if curr.LatencyMsSum > 0 && curr.Requests > 0 {
			resp.AvgLatencyMs = float64(curr.LatencyMsSum) / float64(curr.Requests)
		}
		resp.RequestsChange = pctChange(float64(curr.Requests), float64(prev.Requests))
		resp.InputTokensChange = pctChange(float64(curr.InputTokens), float64(prev.InputTokens))
		resp.OutputTokensChange = pctChange(float64(curr.OutputTokens), float64(prev.OutputTokens))
		resp.TotalCostChange = pctChange(curr.TotalCost, prev.TotalCost)
		resp.TotalTokensChange = pctChange(float64(curr.TotalTokens()), float64(prev.TotalTokens()))

		// 审计：管理员查看某人用量属敏感访问。
		logAudit(r, deps, "usage.user.read", map[string]interface{}{
			"target_user_id": target.ID,
			"start_date":     startDate.Format("2006-01-02"),
			"end_date":       endDate.Format("2006-01-02"),
		}, "user_usage", target.ID)

		writeJSON(w, resp)
	}
}

// GetUserUsageTrend GET /admin/v1/users/{user_id}/usage/trend?start_date&end_date
// 该用户按天趋势（成本/token/请求数）。
func GetUserUsageTrend(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.UsageDailyRepo == nil {
			writeError(w, "internal_error", "usage repository is not configured")
			return
		}
		target, _, ok := resolveTargetUser(w, r, deps)
		if !ok {
			return
		}
		scope := forcedUserScope(target)
		startDate, endDate := parseUsageRange(r)
		points, err := deps.UsageDailyRepo.GetTrendScoped(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get user usage trend")
			return
		}
		writeJSON(w, map[string]interface{}{"data": points})
	}
}

// GetUserUsageByModel GET /admin/v1/users/{user_id}/usage/by-model?start_date&end_date
// 该用户按模型分布（请求数/成本/占比）。
func GetUserUsageByModel(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.UsageDailyRepo == nil {
			writeError(w, "internal_error", "usage repository is not configured")
			return
		}
		target, _, ok := resolveTargetUser(w, r, deps)
		if !ok {
			return
		}
		scope := forcedUserScope(target)
		startDate, endDate := parseUsageRange(r)
		items, err := deps.UsageDailyRepo.GetByModel(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get user usage by model")
			return
		}
		writeJSON(w, mapCostDimensionRows(items))
	}
}

// GetUserUsageRecords GET /admin/v1/users/{user_id}/usage/records?...
// 该用户最近调用明细（强制 user_id = 路径参数）。
func GetUserUsageRecords(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.UsageDailyRepo == nil {
			writeError(w, "internal_error", "usage repository is not configured")
			return
		}
		target, current, ok := resolveTargetUser(w, r, deps)
		if !ok {
			return
		}
		// 复用 records 的 scope 解析（管理员全租户维度），但通过 filter.UserID 强制限定到目标用户。
		scope := repository.UsageScope{TenantID: target.TenantID, FullTenant: isAdminRole(current.Role)}
		filter, err := parseUsageRecordFilter(r, true)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}
		filter.UserID = target.ID // 路径参数强制覆盖，忽略任何 query 里的 user_id
		records, total, err := deps.UsageDailyRepo.ListUsageRecords(r.Context(), scope, filter)
		if err != nil {
			writeError(w, "internal_error", "failed to list user usage records")
			return
		}
		resp := map[string]interface{}{"records": records}
		if total >= 0 {
			resp["total"] = total
		}
		if filter.Limit > 0 && len(records) == filter.Limit {
			last := records[len(records)-1]
			resp["next_cursor"] = encodeUsageCursor(last.CreatedAt, last.ID)
			resp["has_more"] = true
		} else {
			resp["has_more"] = false
		}
		writeJSON(w, resp)
	}
}
