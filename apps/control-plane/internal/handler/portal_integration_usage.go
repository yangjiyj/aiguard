package handler

import (
	"net/http"
	"strings"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// parseCommaProjectIDs 解析逗号分隔的 project_ids 参数：去空白、丢空串；全空返回 nil。
func parseCommaProjectIDs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if v := strings.TrimSpace(p); v != "" {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// portalUsageScope 从请求解析用量查询 scope。可选 project_ids（逗号分隔）→ 按项目服务端收窄
// （repo usageScopeWhere / usageScopeWhereRollup 已支持 UsageScope.ProjectIDs）；
// 无 project_ids 则保持租户全量（FullTenant:true），与 portal-integration 历史行为一致。
func portalUsageScope(r *http.Request, tenantID string) repository.UsageScope {
	projectIDs := parseCommaProjectIDs(r.URL.Query().Get("project_ids"))
	if len(projectIDs) > 0 {
		return repository.UsageScope{TenantID: tenantID, ProjectIDs: projectIDs}
	}
	return repository.UsageScope{TenantID: tenantID, FullTenant: true}
}

// GetPortalUsageTrend 逐日用量趋势（复用 GetTrendScoped，趋势图唯一源）。
// 参数：start_date/end_date（YYYY-MM-DD，Asia/Shanghai）、可选 project_ids。
func GetPortalUsageTrend(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if deps == nil || deps.UsageDailyRepo == nil {
			portalNotConfigured(w, "usage repository")
			return
		}
		startDate, endDate := parseUsageRange(r)
		scope := portalUsageScope(r, tenantID)
		points, err := deps.UsageDailyRepo.GetTrendScoped(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get usage trend")
			return
		}
		if points == nil {
			points = []*repository.UsageTrendPoint{}
		}
		writeJSON(w, map[string]interface{}{"data": points})
	}
}

// GetPortalUsageByModel 模型维度用量分布（复用 GetByModel）。
func GetPortalUsageByModel(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if deps == nil || deps.UsageDailyRepo == nil {
			portalNotConfigured(w, "usage repository")
			return
		}
		startDate, endDate := parseUsageRange(r)
		scope := portalUsageScope(r, tenantID)
		items, err := deps.UsageDailyRepo.GetByModel(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get usage by model")
			return
		}
		writeJSON(w, mapCostDimensionRows(items))
	}
}

// GetPortalUsageSummary topline 汇总卡片（复用 GetSummaryScoped，读 rollup 读模型）。
func GetPortalUsageSummary(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		if deps == nil || deps.UsageDailyRepo == nil {
			portalNotConfigured(w, "usage repository")
			return
		}
		startDate, endDate := parseUsageRange(r)
		scope := portalUsageScope(r, tenantID)
		summary, err := deps.UsageDailyRepo.GetSummaryScoped(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get usage summary")
			return
		}
		writeUsageSummaryResponse(w, summary.TenantID, summary.Requests, summary.InputTokens, summary.OutputTokens, summary.TotalCost, nil)
	}
}
