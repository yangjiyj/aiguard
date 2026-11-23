package handler

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/types"
)

func parseUsageRange(r *http.Request) (time.Time, time.Time) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	now := time.Now().In(loc)
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, -30)
	end := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).AddDate(0, 0, 1)

	if value := firstQuery(r, "start_date", "from"); value != "" {
		if parsed, err := time.ParseInLocation("2006-01-02", value, loc); err == nil {
			start = parsed
		}
	}
	if value := firstQuery(r, "end_date", "to"); value != "" {
		if parsed, err := time.ParseInLocation("2006-01-02", value, loc); err == nil {
			end = parsed.AddDate(0, 0, 1)
		}
	}

	return start.UTC(), end.UTC()
}

func firstQuery(r *http.Request, keys ...string) string {
	for _, key := range keys {
		if value := r.URL.Query().Get(key); value != "" {
			return value
		}
	}
	return ""
}

func resolveUsageScope(r *http.Request, deps *Dependencies) (repository.UsageScope, bool) {
	user := auth.GetUser(r.Context())
	if user == nil {
		return repository.UsageScope{}, false
	}

	scope := repository.UsageScope{TenantID: user.TenantID, UserID: user.ID}
	if roles.IsTenantWideSecurityReader(user.Role) {
		scope.FullTenant = true
		return scope, true
	}
	if deps != nil && deps.TeamMemberRepo != nil {
		if teamIDs, err := deps.TeamMemberRepo.ListTeamIDsByUser(r.Context(), user.ID); err == nil {
			scope.TeamIDs = teamIDs
		}
		if projectIDs, err := deps.TeamMemberRepo.ListProjectIDsByUserTeams(r.Context(), user.TenantID, user.ID); err == nil && len(projectIDs) > 0 {
			scope.ProjectIDs = projectIDs
			return scope, true
		}
	}
	if deps != nil && deps.ProjectUserRepo != nil {
		projectIDs, err := deps.ProjectUserRepo.GetProjectsByUser(r.Context(), user.ID)
		if err == nil && len(projectIDs) > 0 {
			scope.ProjectIDs = projectIDs
		}
	}
	return scope, true
}

func writeJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(data)
}

func mapCostDimensionRow(item *repository.CostDimension) types.CostDimensionRow {
	row := types.CostDimensionRow{
		ID:               item.ID,
		Name:             item.Name,
		ProviderName:     item.ProviderName,
		ProviderType:     item.ProviderType,
		ModelID:          item.ModelID,
		ProjectID:        item.ProjectID,
		ProjectName:      item.ProjectName,
		UserID:           item.UserID,
		Username:         item.Username,
		KeyPrefix:        item.KeyPrefix,
		Requests:         item.Requests,
		InputTokens:      item.InputTokens,
		OutputTokens:     item.OutputTokens,
		TotalTokens:      item.InputTokens + item.OutputTokens,
		TotalCost:        item.TotalCost,
		CostPercent:      item.CostPercent,
		AverageCost:      item.AverageCost,
		SuccessRate:      item.SuccessRate,
		BudgetUsageRate:  item.BudgetUsageRate,
		AverageLatencyMs: item.AverageLatencyMs,
		ModelCount:       item.ModelCount,
		AbnormalGrowth:   item.AbnormalGrowth,
	}
	if item.LastCalledAt != nil {
		row.LastCalledAt = item.LastCalledAt.UTC().Format(time.RFC3339)
	}
	return row
}

func mapCostDimensionRows(items []*repository.CostDimension) []types.CostDimensionRow {
	rows := make([]types.CostDimensionRow, 0, len(items))
	for _, item := range items {
		rows = append(rows, mapCostDimensionRow(item))
	}
	return rows
}

func mapCostRecommendation(item *repository.CostRecommendation) types.CostRecommendation {
	return types.CostRecommendation{
		ID:           item.ID,
		Severity:     item.Severity,
		Problem:      item.Problem,
		Impact:       item.Impact,
		ImpactCost:   item.ImpactCost,
		ImpactTokens: item.ImpactTokens,
		ProjectID:    item.ProjectID,
		UserID:       item.UserID,
		ModelID:      item.ModelID,
		Suggestion:   item.Suggestion,
	}
}

func GetUsageCostCoverage(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}
		startDate, endDate := parseUsageRange(r)
		coverage, err := deps.UsageDailyRepo.GetCostCoverage(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get cost coverage")
			return
		}
		writeJSON(w, types.CostCoverageInfo{
			TotalRequests:        coverage.TotalRequests,
			PricedRequests:       coverage.PricedRequests,
			UnpricedRequests:     coverage.UnpricedRequests,
			CoverageRate:         coverage.CoverageRate,
			UnpricedModelCount:   coverage.UnpricedModelCount,
			CostTrustedStartDate: coverage.CostTrustedStartDate,
		})
	}
}

func GetUsageByModel(deps *Dependencies) http.HandlerFunc {
	return usageDimensionHandler(deps, func(ctx requestContext) ([]*repository.CostDimension, error) {
		return deps.UsageDailyRepo.GetByModel(ctx.Request.Context(), ctx.Scope, ctx.StartDate, ctx.EndDate)
	})
}

func GetUsageByUser(deps *Dependencies) http.HandlerFunc {
	return usageDimensionHandler(deps, func(ctx requestContext) ([]*repository.CostDimension, error) {
		return deps.UsageDailyRepo.GetByUser(ctx.Request.Context(), ctx.Scope, ctx.StartDate, ctx.EndDate)
	})
}

func GetUsageByKey(deps *Dependencies) http.HandlerFunc {
	return usageDimensionHandler(deps, func(ctx requestContext) ([]*repository.CostDimension, error) {
		return deps.UsageDailyRepo.GetByKey(ctx.Request.Context(), ctx.Scope, ctx.StartDate, ctx.EndDate)
	})
}

func GetUsageByProvider(deps *Dependencies) http.HandlerFunc {
	return usageDimensionHandler(deps, func(ctx requestContext) ([]*repository.CostDimension, error) {
		return deps.UsageDailyRepo.GetByProvider(ctx.Request.Context(), ctx.Scope, ctx.StartDate, ctx.EndDate)
	})
}

type requestContext struct {
	Request   *http.Request
	Scope     repository.UsageScope
	StartDate time.Time
	EndDate   time.Time
}

func usageDimensionHandler(deps *Dependencies, load func(requestContext) ([]*repository.CostDimension, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}
		startDate, endDate := parseUsageRange(r)
		items, err := load(requestContext{Request: r, Scope: scope, StartDate: startDate, EndDate: endDate})
		if err != nil {
			writeError(w, "internal_error", "failed to get usage dimension")
			return
		}
		writeJSON(w, mapCostDimensionRows(items))
	}
}

func GetUsageRecommendations(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}
		startDate, endDate := parseUsageRange(r)
		recs, err := deps.UsageDailyRepo.GetCostRecommendations(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get usage recommendations")
			return
		}
		resp := make([]types.CostRecommendation, 0, len(recs))
		for _, rec := range recs {
			resp = append(resp, mapCostRecommendation(rec))
		}
		writeJSON(w, resp)
	}
}

func GetUsageTrend(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}
		startDate, endDate := parseUsageRange(r)
		points, err := deps.UsageDailyRepo.GetTrendScoped(r.Context(), scope, startDate, endDate)
		if err != nil {
			writeError(w, "internal_error", "failed to get usage trend")
			return
		}
		writeJSON(w, map[string]interface{}{"data": points})
	}
}
