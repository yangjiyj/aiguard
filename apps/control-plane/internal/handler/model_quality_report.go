package handler

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
)

func GetModelOperationsSLA(db *pgxpool.Pool) http.HandlerFunc    { return modelOperationsSLA(db, false) }
func ExportModelOperationsSLA(db *pgxpool.Pool) http.HandlerFunc { return modelOperationsSLA(db, true) }

func modelOperationsSLA(db *pgxpool.Pool, export bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := auth.GetUser(r.Context())
		if user == nil || user.TenantID == "" {
			writeUnauthorized(w, "user not found")
			return
		}
		for key, values := range r.URL.Query() {
			if (key != "month" && key != "timezone" && key != "provider_id" && key != "model_id") || len(values) != 1 || len(values[0]) > 128 {
				writeErrorWithStatus(w, http.StatusBadRequest, "invalid_query", "invalid quality report query")
				return
			}
		}
		window, err := repository.ParseModelQualityWindow(r.URL.Query().Get("month"), r.URL.Query().Get("timezone"), time.Now())
		if err != nil {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_query", "invalid month or timezone")
			return
		}
		report, err := repository.NewModelQualityReportRepository(db).Report(r.Context(), user.TenantID, r.URL.Query().Get("provider_id"), r.URL.Query().Get("model_id"), window, time.Now())
		if errors.Is(err, repository.ErrModelQualityScopeNotFound) {
			writeErrorWithStatus(w, http.StatusNotFound, "not_found", "model or provider not found")
			return
		}
		if err != nil {
			writeErrorWithStatus(w, http.StatusServiceUnavailable, "quality_unavailable", "model quality evidence unavailable")
			return
		}
		if !export {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"data": report})
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="model-quality-`+window.Month+`.csv"`)
		writer := csv.NewWriter(w)
		writer.Write([]string{"month", "timezone", "model", "provider", "requests", "eligible_requests", "http_successes", "platform_failures", "client_errors", "availability", "p50_ms", "p95_ms", "first_event_samples"})
		for _, item := range report.Models {
			writer.Write([]string{window.Month, window.Timezone, modelQualityCSVText(item.ModelName), modelQualityCSVText(item.ProviderName), strconv.FormatInt(item.Requests, 10), strconv.FormatInt(item.EligibleRequests, 10), strconv.FormatInt(item.HTTPSuccesses, 10), strconv.FormatInt(item.PlatformFailures, 10), strconv.FormatInt(item.ClientErrors, 10), modelQualityCSVNumber(item.Availability), modelQualityCSVNumber(item.P50MS), modelQualityCSVNumber(item.P95MS), strconv.FormatInt(item.FirstEventSamples, 10)})
		}
		writer.Flush()
	}
}

func modelQualityCSVNumber(value *float64) string {
	if value == nil {
		return ""
	}
	return strconv.FormatFloat(*value, 'f', 4, 64)
}

func modelQualityCSVText(value string) string {
	trimmed := strings.TrimSpace(value)
	if trimmed != "" && strings.ContainsRune("=+-@", rune(trimmed[0])) {
		return "'" + value
	}
	return value
}
