package handler

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func billingAnalyticsFilter(w http.ResponseWriter, r *http.Request, deps *Dependencies) (billing.AnalyticsFilter, bool) {
	scope, ok := resolveUsageScope(r, deps)
	if !ok {
		writeUnauthorized(w, "user not found")
		return billing.AnalyticsFilter{}, false
	}
	currency := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("currency")))
	if currency != "" && currency != "USD" && currency != "CNY" {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_currency", "币种必须为 USD 或 CNY")
		return billing.AnalyticsFilter{}, false
	}
	user := auth.GetUser(r.Context())
	if user != nil && user.Role == "platform_admin" {
		if tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id")); tenantID != "" {
			scope.TenantID = tenantID
		}
	}
	if currency == "" {
		store, available := billingStore(deps)
		if !available {
			portalNotConfigured(w, "billing analytics")
			return billing.AnalyticsFilter{}, false
		}
		var err error
		currency, err = store.BillingCurrencyForTenant(r.Context(), scope.TenantID)
		if err != nil {
			billingHTTPError(w, err)
			return billing.AnalyticsFilter{}, false
		}
	}
	start, end, ok := parseBillingAnalyticsRange(r)
	if !ok {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_time_range", "from/to must be RFC3339 or YYYY-MM-DD and span at most 366 days")
		return billing.AnalyticsFilter{}, false
	}
	dimensionFilters, ok := parseBillingAnalyticsDimensionFilters(r)
	if !ok {
		writeErrorWithStatus(w, http.StatusBadRequest, "invalid_dimension_filter", "dimension filters accept at most 100 values of 128 characters each")
		return billing.AnalyticsFilter{}, false
	}
	return billing.AnalyticsFilter{
		Currency: currency, TenantID: scope.TenantID, Start: start, End: end, FullTenant: scope.FullTenant,
		TeamIDs: scope.TeamIDs, ProjectIDs: scope.ProjectIDs, UserID: scope.UserID,
		FilterDepartmentIDs: dimensionFilters.DepartmentIDs,
		FilterProjectIDs:    dimensionFilters.ProjectIDs,
		FilterUserIDs:       dimensionFilters.UserIDs,
		FilterModelIDs:      dimensionFilters.ModelIDs,
		FilterProviderIDs:   dimensionFilters.ProviderIDs,
		FilterAgentTypes:    dimensionFilters.AgentTypes,
	}, true
}

type billingAnalyticsDimensionFilters struct {
	DepartmentIDs []string
	ProjectIDs    []string
	UserIDs       []string
	ModelIDs      []string
	ProviderIDs   []string
	AgentTypes    []string
}

func parseBillingAnalyticsDimensionFilters(r *http.Request) (billingAnalyticsDimensionFilters, bool) {
	parse := func(key string) ([]string, bool) {
		values := append([]string{}, r.URL.Query()[key]...)
		values = append(values, r.URL.Query()[key+"[]"]...)
		result := make([]string, 0)
		seen := make(map[string]struct{})
		for _, value := range values {
			for _, item := range strings.Split(value, ",") {
				item = strings.TrimSpace(item)
				if item == "" {
					continue
				}
				if len(item) > 128 {
					return nil, false
				}
				if _, exists := seen[item]; exists {
					continue
				}
				seen[item] = struct{}{}
				result = append(result, item)
				if len(result) > 100 {
					return nil, false
				}
			}
		}
		return result, true
	}
	var result billingAnalyticsDimensionFilters
	var ok bool
	if result.DepartmentIDs, ok = parse("department_ids"); !ok {
		return billingAnalyticsDimensionFilters{}, false
	}
	if result.ProjectIDs, ok = parse("project_ids"); !ok {
		return billingAnalyticsDimensionFilters{}, false
	}
	if result.UserIDs, ok = parse("user_ids"); !ok {
		return billingAnalyticsDimensionFilters{}, false
	}
	if result.ModelIDs, ok = parse("model_ids"); !ok {
		return billingAnalyticsDimensionFilters{}, false
	}
	if result.ProviderIDs, ok = parse("provider_ids"); !ok {
		return billingAnalyticsDimensionFilters{}, false
	}
	if result.AgentTypes, ok = parse("agent_types"); !ok {
		return billingAnalyticsDimensionFilters{}, false
	}
	return result, true
}

func parseBillingAnalyticsRange(r *http.Request) (time.Time, time.Time, bool) {
	defaultStart, defaultEnd := parseUsageRange(r)
	start, end := defaultStart, defaultEnd
	if value := strings.TrimSpace(firstQuery(r, "from", "start_date")); value != "" {
		parsed, ok := parseBillingAnalyticsTime(value, false)
		if !ok {
			return time.Time{}, time.Time{}, false
		}
		start = parsed
	}
	if value := strings.TrimSpace(firstQuery(r, "to", "end_date")); value != "" {
		parsed, ok := parseBillingAnalyticsTime(value, true)
		if !ok {
			return time.Time{}, time.Time{}, false
		}
		end = parsed
	}
	if !end.After(start) || end.Sub(start) > 366*24*time.Hour {
		return time.Time{}, time.Time{}, false
	}
	return start.UTC(), end.UTC(), true
}

func parseBillingAnalyticsTime(value string, inclusiveDateEnd bool) (time.Time, bool) {
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC(), true
	}
	loc, _ := time.LoadLocation("Asia/Shanghai")
	parsed, err := time.ParseInLocation("2006-01-02", value, loc)
	if err != nil {
		return time.Time{}, false
	}
	if inclusiveDateEnd {
		parsed = parsed.AddDate(0, 0, 1)
	}
	return parsed.UTC(), true
}

func GetBillingAnalyticsSummary(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing analytics")
			return
		}
		filter, ok := billingAnalyticsFilter(w, r, deps)
		if !ok {
			return
		}
		result, err := store.GetAnalyticsSummary(r.Context(), filter)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, result)
	}
}

func GetBillingAnalyticsBreakdown(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing analytics")
			return
		}
		filter, ok := billingAnalyticsFilter(w, r, deps)
		if !ok {
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		result, err := store.GetAnalyticsBreakdown(r.Context(), filter, strings.TrimSpace(r.URL.Query().Get("dimension")), limit)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		otherCurrencies, err := store.AnalyticsOtherCurrencies(r.Context(), filter)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": result, "currency": filter.Currency, "other_currencies": otherCurrencies})
	}
}

func GetBillingAnalyticsSeries(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing analytics")
			return
		}
		filter, ok := billingAnalyticsFilter(w, r, deps)
		if !ok {
			return
		}
		granularity := strings.TrimSpace(r.URL.Query().Get("granularity"))
		if granularity == "" {
			granularity = "day"
			if filter.End.Sub(filter.Start) <= 72*time.Hour {
				granularity = "hour"
			}
		}
		result, err := store.GetAnalyticsSeries(r.Context(), filter, granularity)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		otherCurrencies, err := store.AnalyticsOtherCurrencies(r.Context(), filter)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": result, "currency": filter.Currency, "other_currencies": otherCurrencies})
	}
}

func GetBillingAnalyticsTimeProfile(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing analytics")
			return
		}
		filter, ok := billingAnalyticsFilter(w, r, deps)
		if !ok {
			return
		}
		timezone := strings.TrimSpace(r.URL.Query().Get("timezone"))
		if timezone == "" {
			timezone = "Asia/Shanghai"
		}
		interval, _ := strconv.Atoi(r.URL.Query().Get("interval_minutes"))
		if interval == 0 {
			interval = 60
		}
		result, err := store.GetAnalyticsTimeProfile(r.Context(), filter, timezone, interval)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		otherCurrencies, err := store.AnalyticsOtherCurrencies(r.Context(), filter)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": result, "currency": filter.Currency, "other_currencies": otherCurrencies})
	}
}

func GetBillingAnalyticsDepartmentProviderMatrix(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		store, ok := billingStore(deps)
		if !ok {
			portalNotConfigured(w, "billing analytics")
			return
		}
		filter, ok := billingAnalyticsFilter(w, r, deps)
		if !ok {
			return
		}
		result, err := store.GetAnalyticsDepartmentProviderMatrix(r.Context(), filter)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		otherCurrencies, err := store.AnalyticsOtherCurrencies(r.Context(), filter)
		if err != nil {
			billingHTTPError(w, err)
			return
		}
		writeJSON(w, map[string]any{"data": result, "currency": filter.Currency, "other_currencies": otherCurrencies})
	}
}
