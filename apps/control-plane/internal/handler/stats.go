package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// agentStatsDefaultWindow 是 agent 统计无显式时间窗时的默认回看窗口。收敛到有界窗口可走
// idx_request_logs_tenant_agent_type_created,避免对 request_logs 全表扫(千人级生死项)。
// 需要全时段时显式传 ?all=true(或 all_time=1 / range=all)。
const agentStatsDefaultWindow = 90 * 24 * time.Hour

func statsRankingTimeWindow(r *http.Request) (time.Time, time.Time, bool, error) {
	if firstQuery(r, "start_time", "start", "start_date", "from", "end_time", "end", "end_date", "to") == "" {
		return time.Time{}, time.Time{}, false, nil
	}
	start, end, err := defaultBoundedTimeWindow(r, 30*24*time.Hour)
	if err != nil {
		return time.Time{}, time.Time{}, false, err
	}
	return start, end, true, nil
}

func agentStatsAllTimeRequested(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(firstQuery(r, "all", "all_time", "range"))) {
	case "1", "true", "yes", "all":
		return true
	default:
		return false
	}
}

func getAgentStatsScopedForRequest(ctx context.Context, r *http.Request, statsRepo *repository.StatsRepository, scope repository.UsageScope) ([]repository.AgentStats, error) {
	if agentStatsAllTimeRequested(r) {
		return statsRepo.GetAgentStatsScoped(ctx, scope)
	}
	start, end, err := defaultBoundedTimeWindow(r, agentStatsDefaultWindow)
	if err != nil {
		return nil, err
	}
	return statsRepo.GetAgentStatsScopedBetween(ctx, scope, start, end)
}

func getAgentTypeDistributionForRequest(ctx context.Context, r *http.Request, statsRepo *repository.StatsRepository, scope repository.UsageScope) ([]repository.AgentTypeDistribution, error) {
	if agentStatsAllTimeRequested(r) {
		return statsRepo.GetAgentTypeDistributionScoped(ctx, scope)
	}
	start, end, err := defaultBoundedTimeWindow(r, agentStatsDefaultWindow)
	if err != nil {
		return nil, err
	}
	return statsRepo.GetAgentTypeDistributionScopedBetween(ctx, scope, start, end)
}

// GetStatsOverview returns system overview statistics
func GetStatsOverview(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}

		statsRepo := repository.NewStatsRepository(deps.UsageDailyRepo.DB())
		loc, tzName := statsRepo.TenantReportTimezone(r.Context(), scope.TenantID)
		overview, err := statsRepo.GetSystemOverviewScopedIn(r.Context(), scope, loc)
		if err != nil {
			writeError(w, "internal_error", "failed to get overview")
			return
		}
		// W8 8.3/8.5/8.9：随概览下发统计时区、「所有时间」起点与当前执行模式，
		// 前端页眉与导出报告据此注明口径，不再各自猜。
		resp := statsOverviewResponse{SystemOverview: overview, Timezone: tzName}
		if earliest, ok, err := statsRepo.EarliestUsageBucket(r.Context(), scope); err == nil && ok {
			resp.DataStart = earliest.In(loc).Format("2006-01-02")
		}
		if mode := statsExecutionMode(r, deps); mode != nil {
			resp.ExecutionMode = mode
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

type statsOverviewResponse struct {
	*repository.SystemOverview
	Timezone      string                     `json:"timezone"`
	DataStart     string                     `json:"data_start,omitempty"`
	ExecutionMode *securityExecutionModeView `json:"execution_mode,omitempty"`
}

func statsExecutionMode(r *http.Request, deps *Dependencies) *securityExecutionModeView {
	if deps == nil || deps.SystemRepo == nil {
		return nil
	}
	settings, err := deps.SystemRepo.GetAll(r.Context())
	if err != nil {
		return nil
	}
	view := securityExecutionModeForSettings(r.Context(), deps, settings)
	return &view
}

// userStatsWithTotals 是 with_totals=true 时的响应：rows 为排行，totals 为同窗口分母。
type userStatsWithTotals struct {
	Data   []repository.UserStats     `json:"data"`
	Totals repository.UserUsageTotals `json:"totals"`
}

func userStatsTotalsRequested(r *http.Request) bool {
	switch strings.ToLower(strings.TrimSpace(r.URL.Query().Get("with_totals"))) {
	case "1", "true", "yes":
		return true
	}
	return false
}

// GetUserStats returns user statistics ranking
// Supports query parameters:
// - limit: number of results (default 10)
// - by: ranking criteria - "tokens" or "requests" (default "tokens")
func GetUserStats(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}

		// Parse limit parameter
		limit := 10
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		// Parse by parameter
		by := r.URL.Query().Get("by")
		if by == "" {
			by = "tokens"
		}

		statsRepo := repository.NewStatsRepository(deps.UsageDailyRepo.DB())
		var stats []repository.UserStats
		var err error
		start, end, hasWindow, rangeErr := statsRankingTimeWindow(r)
		if rangeErr != nil {
			writeError(w, "invalid_request", "invalid statistics time range")
			return
		}

		switch by {
		case "requests":
			if hasWindow {
				stats, err = statsRepo.GetUserRequestRankingScopedBetween(r.Context(), scope, limit, start, end)
			} else {
				stats, err = statsRepo.GetUserRequestRankingScoped(r.Context(), scope, limit)
			}
		case "tokens":
			if hasWindow {
				stats, err = statsRepo.GetUserTokenRankingScopedBetween(r.Context(), scope, limit, start, end)
			} else {
				stats, err = statsRepo.GetUserTokenRankingScoped(r.Context(), scope, limit)
			}
		default:
			writeError(w, "invalid_request", "invalid 'by' parameter, must be 'tokens' or 'requests'")
			return
		}

		if err != nil {
			writeError(w, "internal_error", "failed to get user stats")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if userStatsTotalsRequested(r) {
			// 8.1：占比分母与排行同窗口、同可见范围，不再用全历史或固定 30 天。
			var totals repository.UserUsageTotals
			if hasWindow {
				totals, err = statsRepo.GetUserUsageTotalsScopedBetween(r.Context(), scope, start, end)
			} else {
				totals, err = statsRepo.GetUserUsageTotalsScoped(r.Context(), scope)
			}
			if err != nil {
				writeError(w, "internal_error", "failed to get user stats")
				return
			}
			json.NewEncoder(w).Encode(userStatsWithTotals{Data: stats, Totals: totals})
			return
		}
		json.NewEncoder(w).Encode(stats)
	}
}

// GetAppStats returns application statistics
// Supports query parameter:
// - limit: number of results (default 10)
func GetAppStats(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}

		// Parse limit parameter
		limit := 10
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		statsRepo := repository.NewStatsRepository(deps.UsageDailyRepo.DB())
		stats, err := statsRepo.GetAppStatsScoped(r.Context(), scope, limit)
		if err != nil {
			writeError(w, "internal_error", "failed to get app stats")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	}
}

// GetModelStats returns model statistics with cost percentage
// Supports query parameter:
// - limit: number of results (default 10)
func GetModelStats(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}

		// Parse limit parameter
		limit := 10
		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				limit = parsed
			}
		}

		statsRepo := repository.NewStatsRepository(deps.UsageDailyRepo.DB())
		start, end, hasWindow, rangeErr := statsRankingTimeWindow(r)
		if rangeErr != nil {
			writeError(w, "invalid_request", "invalid statistics time range")
			return
		}
		var stats []repository.ModelStats
		var err error
		if hasWindow {
			stats, err = statsRepo.GetModelStatsScopedBetween(r.Context(), scope, limit, start, end)
		} else {
			stats, err = statsRepo.GetModelStatsScoped(r.Context(), scope, limit)
		}
		if err != nil {
			writeError(w, "internal_error", "failed to get model stats")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	}
}

// GetAgentStats returns agent type distribution statistics
func GetAgentStats(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}

		statsRepo := repository.NewStatsRepository(deps.UsageDailyRepo.DB())
		stats, err := getAgentStatsScopedForRequest(r.Context(), r, statsRepo, scope)
		if err != nil {
			writeError(w, "internal_error", "failed to get agent stats")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	}
}
