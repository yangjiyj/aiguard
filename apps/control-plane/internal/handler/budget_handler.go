package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/org"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// GetBudgetSnapshot handles GET /admin/v1/budgets/snapshot
// Query params: scope_type (tenant|team|project|user|key), scope_id
func GetBudgetSnapshot(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		// 预算快照口径同样不可按 team 收窄（scope_id 调用者可控），限管理员档。
		if !isFullTenantRole(user.Role) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		if deps.BudgetSnapshot == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "budget snapshot not configured")
			return
		}

		scopeType := r.URL.Query().Get("scope_type")
		scopeID := r.URL.Query().Get("scope_id")
		if scopeType == "" {
			scopeType = "tenant"
		}
		if scopeType == "tenant" && scopeID == "" {
			scopeID = user.TenantID
		}
		if scopeID == "" {
			writeError(w, "invalid_request", "scope_id required")
			return
		}

		if deps.OrgService == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "quota_lookup_unavailable")
			return
		}
		ref := org.ScopeRef{TenantID: user.TenantID}
		switch scopeType {
		case "tenant":
			if scopeID != user.TenantID {
				writeErrorWithStatus(w, http.StatusNotFound, "not_found", "scope not found")
				return
			}
		case "team":
			ref.TeamID = scopeID
		case "project":
			ref.ProjectID = scopeID
		case "user":
			ref.UserID = scopeID
		case "key":
			ref.KeyID = scopeID
		default:
			writeError(w, "invalid_request", "invalid scope_type")
			return
		}
		owned, err := deps.OrgService.AccountingScopeOwned(r.Context(), user.TenantID, scopeType, scopeID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "scope_lookup_failed")
			return
		}
		if !owned {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "scope not found")
			return
		}
		// The limits may inherit, but the scope's accounting bucket never does.
		timezone, err := deps.OrgService.AccountingScopeTimezone(r.Context(), user.TenantID, scopeType, scopeID)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "quota_lookup_failed")
			return
		}
		effectiveQuota, err := deps.OrgService.EffectiveQuota(r.Context(), ref)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "quota_lookup_failed")
			return
		}

		scopes := []budget.SnapshotScope{{Scope: scopeType, ID: scopeID, Timezone: timezone}}
		snapshot, err := deps.BudgetSnapshot.Get(r.Context(), user.TenantID, scopes)
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "budget_snapshot_failed")
			return
		}
		usage := snapshot[scopeType+":"+scopeID]

		var quotaBody map[string]interface{}
		if effectiveQuota != nil {
			quotaBody = map[string]interface{}{
				"daily_token_limit":     effectiveQuota.DailyTokenLimit,
				"monthly_token_limit":   effectiveQuota.MonthlyTokenLimit,
				"daily_budget_micros":   effectiveQuota.DailyBudgetMicros,
				"monthly_budget_micros": effectiveQuota.MonthlyBudgetMicros,
				// Exact decimal CNY strings derived from micros for legacy readers.
				"daily_budget_limit":   budget.FormatMicrosCNY(effectiveQuota.DailyBudgetMicros),
				"monthly_budget_limit": budget.FormatMicrosCNY(effectiveQuota.MonthlyBudgetMicros),
				"rpm_limit":            effectiveQuota.RPMLimit,
				"concurrency_limit":    effectiveQuota.ConcurrencyLimit,
				"triggered_scope":      effectiveQuota.TriggeredScope,
				"quota_timezone":       budget.NormalizedQuotaTimezone(effectiveQuota.QuotaTimezone),
			}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"scope_type":               scopeType,
			"scope_id":                 scopeID,
			"quota_timezone":           budget.NormalizedQuotaTimezone(timezone),
			"month":                    usage.MonthBucket,
			"day":                      usage.DayBucket,
			"month_tokens":             usage.MonthTokens,
			"month_cost_micros":        usage.MonthCostMicros,
			"month_cost":               budget.FormatMicrosCNY(usage.MonthCostMicros),
			"month_requests":           usage.MonthRequests,
			"day_tokens":               usage.DayTokens,
			"day_cost_micros":          usage.DayCostMicros,
			"day_cost":                 budget.FormatMicrosCNY(usage.DayCostMicros),
			"day_requests":             usage.DayRequests,
			"rpm":                      usage.Rpm,
			"concurrency":              usage.Concurrency,
			"effective_quota":          quotaBody,
			"month_cost_quality":       costQualityBody(usage.MonthCostMicros, usage.MonthCostEstimatedRequests, usage.MonthCostUnpricedRequests, usage.MonthFields),
			"day_cost_quality":         costQualityBody(usage.DayCostMicros, usage.DayCostEstimatedRequests, usage.DayCostUnpricedRequests, usage.DayFields),
			"month_tokens_available":   usage.MonthFields["tokens"],
			"day_tokens_available":     usage.DayFields["tokens"],
			"month_requests_available": usage.MonthFields["requests"],
			"day_requests_available":   usage.DayFields["requests"],
		})
	}
}

// PauseKey handles POST /admin/v1/budgets/keys/{key_prefix}/pause
func PauseKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.PauseLogRepo == nil || deps.RedisClient == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "budget pause not configured")
			return
		}

		keyPrefix := chi.URLParam(r, "key_prefix")
		if keyPrefix == "" {
			writeError(w, "invalid_request", "key_prefix required")
			return
		}

		var req struct {
			Reason string `json:"reason"`
		}
		json.NewDecoder(r.Body).Decode(&req)

		id := uuid.New().String()
		pl, err := deps.PauseLogRepo.Pause(r.Context(), id, user.TenantID, keyPrefix, user.ID, req.Reason)
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		// Set Redis pause marker (no TTL – explicit unpause required)
		if err := deps.RedisClient.Set(r.Context(), budget.PauseKey(keyPrefix), "1", 0).Err(); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to set pause marker: "+err.Error())
			return
		}

		logAudit(r, deps, "budget.pause_key", map[string]interface{}{
			"key_prefix": keyPrefix,
			"reason":     req.Reason,
		}, "key", keyPrefix)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(pl)
	}
}

// UnpauseKey handles POST /admin/v1/budgets/keys/{key_prefix}/unpause
func UnpauseKey(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.PauseLogRepo == nil || deps.RedisClient == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "budget pause not configured")
			return
		}

		keyPrefix := chi.URLParam(r, "key_prefix")
		if keyPrefix == "" {
			writeError(w, "invalid_request", "key_prefix required")
			return
		}

		if err := deps.PauseLogRepo.Unpause(r.Context(), keyPrefix, user.ID); err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}

		// Remove Redis pause marker
		deps.RedisClient.Del(r.Context(), budget.PauseKey(keyPrefix))

		logAudit(r, deps, "budget.unpause_key", map[string]interface{}{
			"key_prefix": keyPrefix,
		}, "key", keyPrefix)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "unpaused", "key_prefix": keyPrefix})
	}
}

// ListPauseLog handles GET /admin/v1/budgets/pause-log
// Query params: active=true (default), limit=int
func ListPauseLog(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil {
			writeUnauthorized(w, "no user")
			return
		}
		if deps.PauseLogRepo == nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "service_unavailable", "budget pause not configured")
			return
		}

		activeOnly := r.URL.Query().Get("active") != "false"
		limit := parseIntParam(r.URL.Query().Get("limit"), 50)

		var entries []*repository.PauseLog
		var err error
		if activeOnly {
			entries, err = deps.PauseLogRepo.ListActive(r.Context(), user.TenantID)
		} else {
			entries, err = deps.PauseLogRepo.List(r.Context(), user.TenantID, limit)
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", err.Error())
			return
		}
		if entries == nil {
			entries = []*repository.PauseLog{}
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"items": entries})
	}
}
