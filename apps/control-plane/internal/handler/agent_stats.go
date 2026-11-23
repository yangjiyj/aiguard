package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

// GetAgentUsageStats returns agent type usage statistics
// Note: This is already implemented in stats.go as GetAgentStats, but we keep this
// for potential extended usage statistics in the future
func GetAgentUsageStats(deps *Dependencies) http.HandlerFunc {
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

// GetUserAgentDetail returns agent usage details for a specific user
func GetUserAgentDetail(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.GetSession(r.Context())
		if session == nil {
			writeUnauthorized(w, "not authenticated")
			return
		}

		userID := chi.URLParam(r, "user_id")
		if userID == "" {
			userID = r.URL.Query().Get("user_id")
		}
		if userID == "" {
			writeError(w, "invalid_request", "user_id required")
			return
		}

		statsRepo := repository.NewStatsRepository(deps.UsageDailyRepo.DB())
		start, end, hasWindow, rangeErr := statsRankingTimeWindow(r)
		if rangeErr != nil {
			writeError(w, "invalid_request", "invalid statistics time range")
			return
		}
		var stats []repository.UserAgentDetail
		var err error
		if hasWindow {
			stats, err = statsRepo.GetUserAgentDetailBetween(r.Context(), session.TenantID, userID, start, end)
		} else {
			stats, err = statsRepo.GetUserAgentDetail(r.Context(), session.TenantID, userID)
		}
		if err != nil {
			writeError(w, "internal_error", "failed to get user agent detail")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(stats)
	}
}

// ListAgentSessionsByType returns sessions for a specific agent type with filtering
func ListAgentSessionsByType(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session := auth.GetSession(r.Context())
		if session == nil {
			writeUnauthorized(w, "not authenticated")
			return
		}

		agentType := r.URL.Query().Get("agent_type")
		userID := r.URL.Query().Get("user_id")
		limit := parseIntParam(r.URL.Query().Get("limit"), 50)
		offset := parseIntParam(r.URL.Query().Get("offset"), 0)

		statsRepo := repository.NewStatsRepository(deps.UsageDailyRepo.DB())
		sessions, total, err := statsRepo.ListAgentSessionsByType(r.Context(), session.TenantID, agentType, userID, limit, offset)
		if err != nil {
			writeError(w, "internal_error", "failed to list agent sessions")
			return
		}

		resp := map[string]interface{}{
			"data":  sessions,
			"total": total,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// GetAgentTypeDistribution returns pie chart data for agent types
func GetAgentTypeDistribution(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}

		statsRepo := repository.NewStatsRepository(deps.UsageDailyRepo.DB())
		distribution, err := getAgentTypeDistributionForRequest(r.Context(), r, statsRepo, scope)
		if err != nil {
			writeError(w, "internal_error", "failed to get distribution")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(distribution)
	}
}

// parseIntParam parses an integer parameter with a default value
func _parseIntParam(s string, defaultValue int) int {
	n := defaultValue
	if parsed, err := strconv.Atoi(s); err == nil && parsed > 0 {
		n = parsed
	}
	return n
}
