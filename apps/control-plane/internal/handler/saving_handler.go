package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"
)

// rangeDays parses the ?range= query parameter and returns a start date.
// Supported values: "7d", "30d", "90d", "1y". Default: "30d".
func rangeDays(r *http.Request) time.Time {
	s := r.URL.Query().Get("range")
	switch s {
	case "7d":
		return time.Now().UTC().AddDate(0, 0, -7)
	case "90d":
		return time.Now().UTC().AddDate(0, 0, -90)
	case "1y":
		return time.Now().UTC().AddDate(-1, 0, 0)
	default:
		return time.Now().UTC().AddDate(0, 0, -30) // "30d" default
	}
}

// GetSavingsSummary handles GET /savings/summary
//
//	?range=7d|30d|90d|1y   (default: 30d)
//	?scope_type=tenant|team|project|user
//	?scope_id=<id>
//
// Returns aggregated totals and breakdown by source.
func GetSavingsSummary(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// 全局节省汇总口径无法按 team 收窄（scope_id 调用者可控且未校验归属），
		// 故限管理员档；部门主管等非管理员一律拒绝，防读到全公司数字。
		if !callerIsFullTenant(r) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		ctx := r.Context()
		since := rangeDays(r)
		rangeStr := r.URL.Query().Get("range")
		if rangeStr == "" {
			rangeStr = "30d"
		}

		scopeType := r.URL.Query().Get("scope_type")
		scopeID := r.URL.Query().Get("scope_id")

		// Build WHERE clause for optional scope filter.
		// ?include_test=true skips the default filter that excludes E2E test tenants.
		includeTest := r.URL.Query().Get("include_test") == "true"
		excludeTestSQL := ""
		if !includeTest {
			excludeTestSQL = " AND tenant_id NOT IN (SELECT id FROM tenants WHERE is_test=TRUE)"
		}
		whereExtra := ""
		args := []interface{}{since}
		argIdx := 2
		if scopeID != "" {
			switch scopeType {
			case "tenant":
				whereExtra = " AND tenant_id = $" + strconv.Itoa(argIdx)
				args = append(args, scopeID)
				argIdx++
			case "team":
				whereExtra = " AND team_id = $" + strconv.Itoa(argIdx)
				args = append(args, scopeID)
				argIdx++
			case "project":
				whereExtra = " AND project_id = $" + strconv.Itoa(argIdx)
				args = append(args, scopeID)
				argIdx++
			case "user":
				whereExtra = " AND user_id = $" + strconv.Itoa(argIdx)
				args = append(args, scopeID)
				argIdx++
			}
		}
		_ = argIdx // suppress unused warning

		// Query total + per-source breakdown.
		rows, err := deps.SavingDB.Query(ctx, `
			SELECT source,
			       SUM(saving_usd)    AS total_usd,
			       SUM(saving_cny)    AS total_cny,
			       SUM(request_count) AS total_requests
			FROM saving_metrics
			WHERE date >= $1`+whereExtra+excludeTestSQL+`
			GROUP BY source
		`, args...)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		type sourceRow struct {
			SavingUSD    float64 `json:"saving_usd"`
			SavingCNY    float64 `json:"saving_cny"`
			RequestCount int64   `json:"request_count"`
		}
		bySource := map[string]sourceRow{}
		var totalUSD, totalCNY float64
		var totalRequests int64
		for rows.Next() {
			var source string
			var usd, cny float64
			var cnt int64
			if err := rows.Scan(&source, &usd, &cny, &cnt); err != nil {
				continue
			}
			bySource[source] = sourceRow{SavingUSD: usd, SavingCNY: cny, RequestCount: cnt}
			totalUSD += usd
			totalCNY += cny
			totalRequests += cnt
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"total_usd":      totalUSD,
			"total_cny":      totalCNY,
			"total_requests": totalRequests,
			"by_source":      bySource,
			"range":          rangeStr,
		})
	}
}

// GetSavingsTrend handles GET /savings/trend
//
//	?range=7d|30d|90d|1y  (default: 30d)
//	?groupBy=source|team|project|user  (default: source)
//
// Returns a list of daily rows aggregated by the chosen dimension.
func GetSavingsTrend(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !callerIsFullTenant(r) {
			writeErrorWithStatus(w, http.StatusForbidden, "forbidden", "insufficient permissions")
			return
		}
		ctx := r.Context()
		since := rangeDays(r)
		groupBy := r.URL.Query().Get("groupBy")

		type trendRow struct {
			Date         string  `json:"date"`
			Dimension    string  `json:"dimension"`
			SavingUSD    float64 `json:"saving_usd"`
			SavingCNY    float64 `json:"saving_cny"`
			RequestCount int64   `json:"request_count"`
		}

		// Allowed group-by columns (safeguard against injection).
		groupCol := "source"
		switch groupBy {
		case "team":
			groupCol = "team_id"
		case "project":
			groupCol = "project_id"
		case "user":
			groupCol = "user_id"
		default:
			groupCol = "source"
			groupBy = "source"
		}

		// ?include_test=true skips the default filter that excludes E2E test tenants.
		includeTestTrend := r.URL.Query().Get("include_test") == "true"
		excludeTestTrendSQL := ""
		if !includeTestTrend {
			excludeTestTrendSQL = " AND tenant_id NOT IN (SELECT id FROM tenants WHERE is_test=TRUE)"
		}
		rows, err := deps.SavingDB.Query(ctx, `
			SELECT date,
			       COALESCE(`+groupCol+`, '') AS dimension,
			       SUM(saving_usd)            AS saving_usd,
			       SUM(saving_cny)            AS saving_cny,
			       SUM(request_count)         AS request_count
			FROM saving_metrics
			WHERE date >= $1`+excludeTestTrendSQL+`
			GROUP BY date, `+groupCol+`
			ORDER BY date DESC, dimension
		`, since)
		if err != nil {
			http.Error(w, "db error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		result := []trendRow{}
		for rows.Next() {
			var row trendRow
			var d time.Time
			if err := rows.Scan(&d, &row.Dimension, &row.SavingUSD, &row.SavingCNY, &row.RequestCount); err != nil {
				continue
			}
			row.Date = d.Format("2006-01-02")
			result = append(result, row)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"data":     result,
			"group_by": groupBy,
		})
	}
}
