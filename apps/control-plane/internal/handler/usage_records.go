package handler

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type usageRecordsSummaryResponse struct {
	Requests            int   `json:"requests"`
	Users               int   `json:"users"`
	Apps                int   `json:"apps"`
	Keys                int   `json:"keys"`
	InputTokens         int64 `json:"input_tokens"`
	OutputTokens        int64 `json:"output_tokens"`
	TotalTokens         int64 `json:"total_tokens"`
	BillingAmountMicros int64 `json:"billing_amount_micros"`
	SettledRequests     int   `json:"settled_requests"`
	ReservedRequests    int   `json:"reserved_requests"`
	ReleasedRequests    int   `json:"released_requests"`
	ExceptionRequests   int   `json:"exception_requests"`
	NotBilledRequests   int   `json:"not_billed_requests"`
	SuccessRequests     int   `json:"success_requests"`
	FailedRequests      int   `json:"failed_requests"`
}

func parseFlexibleTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC(), nil
	}
	loc, _ := time.LoadLocation("Asia/Shanghai")
	if parsed, err := time.ParseInLocation("2006-01-02", value, loc); err == nil {
		return parsed.UTC(), nil
	}
	return time.Time{}, fmt.Errorf("invalid time %q", value)
}

func parseUsageRecordFilter(r *http.Request, includePagination bool) (repository.UsageRecordFilter, error) {
	// 用 Asia/Shanghai 日界，与 stats / rollup 口径一致
	loc, _ := time.LoadLocation("Asia/Shanghai")
	if loc == nil {
		loc = time.Local
	}
	now := time.Now().In(loc)
	filter := repository.UsageRecordFilter{
		StartDate: now.AddDate(0, 0, -7),
		EndDate:   now,
		Limit:     50,
	}
	if parsed, err := parseFlexibleTime(firstQuery(r, "start", "start_date", "from")); err != nil {
		return filter, err
	} else if !parsed.IsZero() {
		filter.StartDate = parsed
	}
	if parsed, err := parseFlexibleTime(firstQuery(r, "end", "end_date", "to")); err != nil {
		return filter, err
	} else if !parsed.IsZero() {
		filter.EndDate = parsed
	}

	q := r.URL.Query()
	filter.UserID = q.Get("user_id")
	filter.ClientID = q.Get("client_id")
	filter.ProjectID = q.Get("project_id")
	filter.ModelID = q.Get("model_id")
	filter.ProviderID = q.Get("provider_id")
	filter.RequestStatus = q.Get("request_status")
	filter.SourceIP = strings.TrimSpace(q.Get("source_ip"))
	filter.FailureCategory = strings.TrimSpace(q.Get("failure_category"))
	filter.ErrorKeyword = strings.TrimSpace(q.Get("error_keyword"))
	if len(filter.SourceIP) > 64 || len(filter.ErrorKeyword) > 512 || len(filter.FailureCategory) > 64 {
		return filter, fmt.Errorf("invalid troubleshooting filter")
	}
	if v := q.Get("http_status"); v != "" {
		code, err := strconv.Atoi(v)
		if err != nil || code < 100 || code > 599 {
			return filter, fmt.Errorf("invalid http_status")
		}
		filter.HTTPStatus = code
	}
	filter.BillingState = q.Get("billing_state")
	if v := q.Get("fallback"); v == "1" || v == "true" {
		filter.FallbackOnly = true
	}

	if includePagination {
		if l := q.Get("limit"); l != "" {
			parsed, err := strconv.Atoi(l)
			if err != nil || parsed <= 0 {
				return filter, fmt.Errorf("invalid limit")
			}
			if parsed > 200 {
				parsed = 200
			}
			filter.Limit = parsed
		}
		if o := q.Get("offset"); o != "" {
			parsed, err := strconv.Atoi(o)
			if err != nil || parsed < 0 {
				return filter, fmt.Errorf("invalid offset")
			}
			filter.Offset = parsed
		}
		if c := q.Get("cursor"); c != "" {
			ct, cid, err := decodeUsageCursor(c)
			if err != nil {
				return filter, fmt.Errorf("invalid cursor")
			}
			filter.CursorTime = ct
			filter.CursorID = cid
			filter.SkipTotal = true
		}
		if v := q.Get("skip_total"); v == "1" || v == "true" {
			filter.SkipTotal = true
		}
	}
	return filter, nil
}

// keyset 游标编码:created_at(RFC3339Nano)|id 的 base64url,前端原样回传即可翻下一页。
func encodeUsageCursor(t time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + id))
}

func decodeUsageCursor(s string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, "", err
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return time.Time{}, "", fmt.Errorf("bad cursor")
	}
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", err
	}
	return t.UTC(), parts[1], nil
}

func buildUsageSummaryResponse(summary *repository.UsageRecordsSummary) usageRecordsSummaryResponse {
	resp := usageRecordsSummaryResponse{
		Requests:            summary.Requests,
		Users:               summary.Users,
		Apps:                summary.Apps,
		Keys:                summary.Keys,
		InputTokens:         summary.InputTokens,
		OutputTokens:        summary.OutputTokens,
		TotalTokens:         summary.TotalTokens,
		BillingAmountMicros: summary.BillingAmountMicros,
		SettledRequests:     summary.SettledRequests,
		ReservedRequests:    summary.ReservedRequests,
		ReleasedRequests:    summary.ReleasedRequests,
		ExceptionRequests:   summary.ExceptionRequests,
		NotBilledRequests:   summary.NotBilledRequests,
		SuccessRequests:     summary.SuccessRequests,
		FailedRequests:      summary.FailedRequests,
	}
	return resp
}

func GetUsageRecords(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.UsageDailyRepo == nil {
			writeError(w, "internal_error", "usage repository is not configured")
			return
		}
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}
		filter, err := parseUsageRecordFilter(r, true)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		records, total, err := deps.UsageDailyRepo.ListUsageRecords(r.Context(), scope, filter)
		if err != nil {
			writeError(w, "internal_error", "failed to list usage records")
			return
		}
		// 直接返回共用 UsageRecord，包含错误原文、中文解释和供应商错误码。
		resp := map[string]interface{}{"records": records}
		if total >= 0 {
			resp["total"] = total // 仅 offset 路径返回精确总数;游标分页退订 COUNT,不返回
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

func GetUsageRecordsSummary(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps == nil || deps.UsageDailyRepo == nil {
			writeError(w, "internal_error", "usage repository is not configured")
			return
		}
		scope, ok := resolveUsageScope(r, deps)
		if !ok {
			writeUnauthorized(w, "user not found")
			return
		}
		filter, err := parseUsageRecordFilter(r, false)
		if err != nil {
			writeError(w, "invalid_request", err.Error())
			return
		}

		summary, err := deps.UsageDailyRepo.SummarizeUsageRecords(r.Context(), scope, filter)
		if err != nil {
			writeError(w, "internal_error", "failed to summarize usage records")
			return
		}
		writeJSON(w, buildUsageSummaryResponse(summary))
	}
}
