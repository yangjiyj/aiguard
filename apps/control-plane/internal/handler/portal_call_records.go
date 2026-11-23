package handler

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

const (
	defaultPortalCallRecordLimit = 50
	maxPortalCallRecordLimit     = 200
	defaultPortalCallRecordDays  = 30
	maxPortalCallRecordDays      = 90
	maxPortalCallRecordCursorLen = 512
)

var portalCallRecordRequestIDPattern = regexp.MustCompile(`^(?:req_)?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type PortalCallRecordReader interface {
	SummarizePortalCallRecords(context.Context, repository.PortalCallRecordFilter) (repository.PortalCallRecordsSummary, error)
	ListPortalCallRecords(
		context.Context,
		repository.PortalCallRecordFilter,
	) ([]repository.PortalCallRecord, int, error)
}

type portalCallRecordInfo struct {
	RequestID             string `json:"request_id"`
	CreatedAt             string `json:"created_at"`
	Model                 string `json:"model"`
	Status                string `json:"status"`
	InputTokens           int    `json:"input_tokens"`
	CachedInputTokens     int    `json:"cached_input_tokens"`
	CacheWriteInputTokens int    `json:"cache_write_input_tokens"`
	OutputTokens          int    `json:"output_tokens"`
	TotalTokens           int    `json:"total_tokens"`
	LatencyMs             int    `json:"latency_ms"`
	AgentType             string `json:"agent_type"`
	EndpointType          string `json:"endpoint_type"`
	BillingAmountMicros   *int64 `json:"billing_amount_micros"`
	BillingCurrency       string `json:"billing_currency"`
	BillingState          string `json:"billing_state"`
}

type portalCallRecordCursor struct {
	CreatedAt string `json:"created_at"`
	RequestID string `json:"request_id"`
}

func encodePortalCallRecordCursor(record repository.PortalCallRecord) string {
	payload, _ := json.Marshal(portalCallRecordCursor{
		CreatedAt: record.CreatedAt.UTC().Format(time.RFC3339Nano),
		RequestID: record.RequestID,
	})
	return base64.RawURLEncoding.EncodeToString(payload)
}

func decodePortalCallRecordCursor(raw string) (time.Time, string, bool) {
	if raw == "" {
		return time.Time{}, "", true
	}
	if len(raw) > maxPortalCallRecordCursorLen {
		return time.Time{}, "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		return time.Time{}, "", false
	}
	var cursor portalCallRecordCursor
	if err := json.Unmarshal(payload, &cursor); err != nil {
		return time.Time{}, "", false
	}
	requestID := strings.TrimSpace(cursor.RequestID)
	if requestID == "" || requestID != cursor.RequestID || len(requestID) > 128 ||
		strings.IndexFunc(requestID, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return time.Time{}, "", false
	}
	createdAt, err := time.Parse(time.RFC3339Nano, cursor.CreatedAt)
	if err != nil {
		return time.Time{}, "", false
	}
	return createdAt.UTC(), requestID, true
}

func boundedPortalCallRecordParam(raw string, fallback, minimum, maximum int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func nonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func portalCallRecordReader(deps *Dependencies) PortalCallRecordReader {
	if deps == nil {
		return nil
	}
	if deps.PortalCallRecordReader != nil {
		return deps.PortalCallRecordReader
	}
	return deps.RequestLogRepo
}

// ListPortalUserCallRecords exposes a privacy-minimized, billing-enriched
// view of completed model calls for one tenant user.
func ListPortalUserCallRecords(deps *Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, ok := portalTenantID(w, r)
		if !ok {
			return
		}
		userID := strings.TrimSpace(chi.URLParam(r, "id"))
		if userID == "" {
			writeErrorWithStatus(w, http.StatusBadRequest, "user_required", "user id is required")
			return
		}
		reader := portalCallRecordReader(deps)
		if reader == nil {
			portalNotConfigured(w, "request log repository")
			return
		}

		query := r.URL.Query()
		limit := boundedPortalCallRecordParam(
			query.Get("limit"),
			defaultPortalCallRecordLimit,
			1,
			maxPortalCallRecordLimit,
		)
		days := boundedPortalCallRecordParam(
			query.Get("days"),
			defaultPortalCallRecordDays,
			1,
			maxPortalCallRecordDays,
		)
		beforeCreatedAt, beforeRequestID, cursorOK := decodePortalCallRecordCursor(query.Get("cursor"))
		if !cursorOK {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_cursor", "call record cursor is invalid")
			return
		}
		requestID := query.Get("request_id")
		if requestID != "" && !portalCallRecordRequestIDPattern.MatchString(requestID) {
			writeErrorWithStatus(w, http.StatusBadRequest, "invalid_request_id", "call record request id is invalid")
			return
		}
		startTime := time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour)
		records, total, err := reader.ListPortalCallRecords(
			r.Context(),
			repository.PortalCallRecordFilter{
				TenantID:        tenantID,
				UserID:          userID,
				StartTime:       startTime,
				BeforeCreatedAt: beforeCreatedAt,
				BeforeRequestID: beforeRequestID,
				RequestID:       requestID,
				Limit:           limit + 1,
			},
		)
		if err != nil {
			writeErrorWithStatus(
				w,
				http.StatusInternalServerError,
				"internal_error",
				"failed to list call records",
			)
			return
		}

		// 汇总使用同一权限、同一开始时间的完整范围，游标不参与聚合。
		summary, err := reader.SummarizePortalCallRecords(r.Context(), repository.PortalCallRecordFilter{TenantID: tenantID, UserID: userID, StartTime: startTime})
		if err != nil {
			writeErrorWithStatus(w, http.StatusInternalServerError, "internal_error", "failed to summarize call records")
			return
		}
		nextCursor := ""
		if len(records) > limit {
			records = records[:limit]
			nextCursor = encodePortalCallRecordCursor(records[len(records)-1])
		}
		data := make([]portalCallRecordInfo, 0, len(records))
		for _, record := range records {
			inputTokens := nonNegative(record.InputTokens)
			outputTokens := nonNegative(record.OutputTokens)
			data = append(data, portalCallRecordInfo{
				RequestID:             record.RequestID,
				CreatedAt:             record.CreatedAt.UTC().Format(time.RFC3339Nano),
				Model:                 record.Model,
				Status:                record.Status,
				InputTokens:           inputTokens,
				CachedInputTokens:     nonNegative(record.CachedInputTokens),
				CacheWriteInputTokens: nonNegative(record.CacheWriteInputTokens),
				OutputTokens:          outputTokens,
				TotalTokens:           inputTokens + outputTokens,
				LatencyMs:             nonNegative(record.LatencyMs),
				AgentType:             record.AgentType,
				EndpointType:          record.EndpointType,
				BillingAmountMicros:   record.BillingAmountMicros,
				BillingCurrency:       record.BillingCurrency,
				BillingState:          record.BillingState,
			})
		}
		writeJSON(w, map[string]interface{}{
			"data":        data,
			"summary":     summary,
			"total":       total,
			"next_cursor": nextCursor,
		})
	}
}
