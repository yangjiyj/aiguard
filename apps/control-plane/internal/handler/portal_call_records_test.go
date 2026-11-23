package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type portalCallRecordReaderFake struct {
	records       []repository.PortalCallRecord
	total         int
	err           error
	filter        repository.PortalCallRecordFilter
	calls         int
	summaryFilter repository.PortalCallRecordFilter
}

func (f *portalCallRecordReaderFake) ListPortalCallRecords(
	_ context.Context,
	filter repository.PortalCallRecordFilter,
) ([]repository.PortalCallRecord, int, error) {
	f.calls++
	f.filter = filter
	return f.records, f.total, f.err
}

func portalCallRecordRequest(
	t *testing.T,
	reader PortalCallRecordReader,
	target string,
	tenantID string,
) *httptest.ResponseRecorder {
	t.Helper()
	router := chi.NewRouter()
	router.Get(
		"/admin/v1/portal-integration/users/{id}/call-records",
		ListPortalUserCallRecords(&Dependencies{PortalCallRecordReader: reader}),
	)
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if tenantID != "" {
		req.Header.Set(portalIntegrationTenantHeader, tenantID)
	}
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)
	return response
}

func TestPortalCallRecordsRequireTenantAndUser(t *testing.T) {
	reader := &portalCallRecordReaderFake{}
	response := portalCallRecordRequest(
		t,
		reader,
		"/admin/v1/portal-integration/users/user-a/call-records",
		"",
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing tenant: want 400, got %d %s", response.Code, response.Body.String())
	}
	if reader.calls != 0 {
		t.Fatalf("repository must not be called without tenant, got %d calls", reader.calls)
	}

	req := httptest.NewRequest(http.MethodGet, "/call-records", nil)
	req.Header.Set(portalIntegrationTenantHeader, "tenant-a")
	direct := httptest.NewRecorder()
	ListPortalUserCallRecords(&Dependencies{PortalCallRecordReader: reader})(direct, req)
	if direct.Code != http.StatusBadRequest {
		t.Fatalf("missing user: want 400, got %d %s", direct.Code, direct.Body.String())
	}
	if reader.calls != 0 {
		t.Fatalf("repository must not be called without user, got %d calls", reader.calls)
	}
}

func TestPortalCallRecordsUseExactTenantUserAndBoundedWindow(t *testing.T) {
	amount := int64(0)
	reader := &portalCallRecordReaderFake{
		total: 1,
		records: []repository.PortalCallRecord{{
			RequestID:           "req-public-1",
			CreatedAt:           time.Date(2026, 8, 16, 0, 0, 0, 0, time.UTC),
			Model:               "GPT 5.6",
			Status:              "success",
			UpstreamStatus:      200,
			InputTokens:         12,
			OutputTokens:        8,
			LatencyMs:           321,
			AgentType:           "codex",
			EndpointType:        "responses",
			InputAction:         "",
			OutputAction:        "audit",
			SecurityEventCount:  0,
			BillingAmountMicros: &amount,
			BillingCurrency:     "CNY",
			BillingState:        "settled",
		}},
	}
	before := time.Now().UTC().Add(-90 * 24 * time.Hour)
	response := portalCallRecordRequest(
		t,
		reader,
		"/admin/v1/portal-integration/users/user%20a/call-records?limit=500&days=180",
		"tenant-a",
	)
	after := time.Now().UTC().Add(-90 * 24 * time.Hour)

	if response.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", response.Code, response.Body.String())
	}
	if reader.calls != 1 {
		t.Fatalf("want one repository call, got %d", reader.calls)
	}
	if reader.filter.TenantID != "tenant-a" || reader.filter.UserID != "user a" {
		t.Fatalf("wrong tenant/user filter: %+v", reader.filter)
	}
	if reader.filter.Limit != 201 {
		t.Fatalf("pagination must be bounded, got %+v", reader.filter)
	}
	if reader.filter.StartTime.Before(before) || reader.filter.StartTime.After(after) {
		t.Fatalf("days must clamp to 90, got start=%s before=%s after=%s", reader.filter.StartTime, before, after)
	}

	var payload struct {
		Data []struct {
			RequestID           string `json:"request_id"`
			TotalTokens         int    `json:"total_tokens"`
			InputAction         string `json:"input_action"`
			OutputAction        string `json:"output_action"`
			SecurityEvents      int    `json:"security_event_count"`
			BillingAmountMicros *int64 `json:"billing_amount_micros"`
			BillingCurrency     string `json:"billing_currency"`
			BillingState        string `json:"billing_state"`
		} `json:"data"`
		Total int `json:"total"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v body=%s", err, response.Body.String())
	}
	if payload.Total != 1 || len(payload.Data) != 1 {
		t.Fatalf("unexpected payload: %+v", payload)
	}
	if payload.Data[0].RequestID != "req-public-1" || payload.Data[0].TotalTokens != 20 {
		t.Fatalf("wrong overview mapping: %+v", payload.Data[0])
	}
	if payload.Data[0].BillingAmountMicros == nil || *payload.Data[0].BillingAmountMicros != 0 ||
		payload.Data[0].BillingCurrency != "CNY" || payload.Data[0].BillingState != "settled" {
		t.Fatalf("wrong zero-price billing mapping: %+v", payload.Data[0])
	}
	for _, forbidden := range []string{
		"prompt",
		"response_body",
		"content_logs",
		"secret",
		"provider_id",
		"session_id",
		"input_audit_result",
		"output_audit_result",
	} {
		if strings.Contains(response.Body.String(), forbidden) {
			t.Fatalf("response leaked forbidden field %q: %s", forbidden, response.Body.String())
		}
	}
}

func TestPortalCallRecordsReturnEmptyArrayAndSanitizedErrors(t *testing.T) {
	empty := &portalCallRecordReaderFake{}
	response := portalCallRecordRequest(
		t,
		empty,
		"/admin/v1/portal-integration/users/user-a/call-records",
		"tenant-a",
	)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"data":[]`) {
		t.Fatalf("empty list must be [], got %d %s", response.Code, response.Body.String())
	}

	failed := &portalCallRecordReaderFake{err: errors.New("postgres://db.internal/?password=leak-canary")}
	response = portalCallRecordRequest(
		t,
		failed,
		"/admin/v1/portal-integration/users/user-a/call-records",
		"tenant-a",
	)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("repository error: want 500, got %d %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "postgres") || strings.Contains(response.Body.String(), "leak-canary") {
		t.Fatalf("repository error leaked infrastructure details: %s", response.Body.String())
	}
}

func TestPortalCallRecordsReturnOpaqueCursorForNextPage(t *testing.T) {
	reader := &portalCallRecordReaderFake{
		total: 3,
		records: []repository.PortalCallRecord{
			{RequestID: "req-3", CreatedAt: time.Date(2026, 8, 16, 3, 0, 0, 0, time.UTC), Model: "GPT 5.6", Status: "success"},
			{RequestID: "req-2", CreatedAt: time.Date(2026, 8, 16, 2, 0, 0, 0, time.UTC), Model: "GPT 5.6", Status: "success"},
			{RequestID: "req-1", CreatedAt: time.Date(2026, 8, 16, 1, 0, 0, 0, time.UTC), Model: "GPT 5.6", Status: "success"},
		},
	}
	response := portalCallRecordRequest(
		t,
		reader,
		"/admin/v1/portal-integration/users/user-a/call-records?limit=2",
		"tenant-a",
	)

	if response.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", response.Code, response.Body.String())
	}
	if reader.filter.Limit != 3 {
		t.Fatalf("repository must fetch one lookahead row, got limit=%d", reader.filter.Limit)
	}
	var payload struct {
		Data       []portalCallRecordInfo `json:"data"`
		NextCursor string                 `json:"next_cursor"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(payload.Data) != 2 || payload.NextCursor == "" {
		t.Fatalf("expected two visible rows and an opaque next cursor, got %+v", payload)
	}
	if strings.Contains(payload.NextCursor, "req-2") {
		t.Fatalf("cursor must not expose its payload as plain text: %q", payload.NextCursor)
	}
	nextReader := &portalCallRecordReaderFake{}
	nextResponse := portalCallRecordRequest(
		t,
		nextReader,
		"/admin/v1/portal-integration/users/user-a/call-records?limit=2&cursor="+payload.NextCursor,
		"tenant-a",
	)
	if nextResponse.Code != http.StatusOK {
		t.Fatalf("valid cursor: want 200, got %d %s", nextResponse.Code, nextResponse.Body.String())
	}
	if nextReader.filter.BeforeRequestID != "req-2" ||
		!nextReader.filter.BeforeCreatedAt.Equal(time.Date(2026, 8, 16, 2, 0, 0, 0, time.UTC)) {
		t.Fatalf("cursor anchor was not restored exactly: %+v", nextReader.filter)
	}
}

func TestPortalCallRecordsRejectMalformedCursor(t *testing.T) {
	reader := &portalCallRecordReaderFake{}
	response := portalCallRecordRequest(
		t,
		reader,
		"/admin/v1/portal-integration/users/user-a/call-records?cursor=not-a-valid-cursor",
		"tenant-a",
	)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("malformed cursor: want 400, got %d %s", response.Code, response.Body.String())
	}
	if reader.calls != 0 {
		t.Fatalf("repository must not be called for a malformed cursor, got %d calls", reader.calls)
	}
}

func TestPortalCallRecordsCacheTokens(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		read, write, wantRead, wantWrite int
	}{
		{"有缓存", 90086, 118, 90086, 118},
		{"无缓存", 0, 0, 0, 0},
		{"负数归零", -1, -2, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader := &portalCallRecordReaderFake{total: 1, records: []repository.PortalCallRecord{{
				RequestID: "req-cache", InputTokens: 90364, OutputTokens: 4,
				CachedInputTokens: tc.read, CacheWriteInputTokens: tc.write,
			}}}
			response := portalCallRecordRequest(t, reader, "/admin/v1/portal-integration/users/user-a/call-records", "tenant-a")
			var payload struct {
				Data []map[string]interface{} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusOK || len(payload.Data) != 1 {
				t.Fatalf("调用记录响应异常：%s", response.Body.String())
			}
			row := payload.Data[0]
			if row["cached_input_tokens"] != float64(tc.wantRead) || row["cache_write_input_tokens"] != float64(tc.wantWrite) || row["total_tokens"] != float64(90368) {
				t.Fatalf("缓存映射错误或改变了总 Token：%+v", row)
			}
		})
	}
}

func TestPortalCallRecordsTimingPrivacyAndSummary(t *testing.T) {
	reader := &portalCallRecordReaderFake{total: 1, records: []repository.PortalCallRecord{{RequestID: "req", Status: "success", LatencyMs: 300, UpstreamStatus: 200, SecurityEventCount: 3}}}
	response := portalCallRecordRequest(t, reader, "/admin/v1/portal-integration/users/user-a/call-records", "tenant-a")
	for _, field := range []string{"timing", "upstream", "security", "input_action", "output_action"} {
		if strings.Contains(response.Body.String(), field) {
			t.Fatalf("门户泄露内部字段 %s: %s", field, response.Body.String())
		}
	}
	var payload struct {
		Summary repository.PortalCallRecordsSummary `json:"summary"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Summary.Requests != 7 || payload.Summary.AverageLatencyMS == nil || *payload.Summary.AverageLatencyMS != 123 || payload.Summary.SuccessRate == nil || *payload.Summary.SuccessRate != 0.5 {
		t.Fatalf("汇总必须来自完整窗口: %s", response.Body.String())
	}
	if !reader.summaryFilter.BeforeCreatedAt.IsZero() || reader.summaryFilter.Limit != 0 || reader.summaryFilter.TenantID != "tenant-a" || reader.summaryFilter.UserID != "user-a" || !reader.summaryFilter.StartTime.Equal(reader.filter.StartTime) {
		t.Fatalf("汇总范围错误: %+v", reader.summaryFilter)
	}
}

func (f *portalCallRecordReaderFake) SummarizePortalCallRecords(_ context.Context, filter repository.PortalCallRecordFilter) (repository.PortalCallRecordsSummary, error) {
	f.summaryFilter = filter
	average, rate := 123.0, 0.5
	return repository.PortalCallRecordsSummary{Requests: 7, AverageLatencyMS: &average, SuccessRate: &rate}, f.err
}

func TestPortalCallRecordsRequestIDFilterIsScopedToUserAndValidated(t *testing.T) {
	reqID := "req_0123abcd-0123-abcd-0123-0123abcd4567"
	reader := &portalCallRecordReaderFake{}
	response := portalCallRecordRequest(t, reader,
		"/admin/v1/portal-integration/users/user-a/call-records?request_id="+reqID, "tenant-a")
	if response.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", response.Code, response.Body.String())
	}
	if reader.filter.RequestID != reqID || reader.filter.UserID != "user-a" || reader.filter.TenantID != "tenant-a" {
		t.Fatalf("request id must be passed alongside tenant and user: %+v", reader.filter)
	}
	// 他人的编号：仓储按 user_id 过滤后返回空，接口只回空列表。
	var body struct {
		Data []map[string]interface{} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || len(body.Data) != 0 {
		t.Fatalf("other user's request id must yield no rows: %v %s", err, response.Body.String())
	}

	for _, bad := range []string{"req-1", "req_ZZZ", "req_0123abcd-0123-abcd-0123-0123abcd4567%27%20OR%201=1", "x"} {
		bad := bad
		reader := &portalCallRecordReaderFake{}
		resp := portalCallRecordRequest(t, reader,
			"/admin/v1/portal-integration/users/user-a/call-records?request_id="+bad, "tenant-a")
		if resp.Code != http.StatusBadRequest || reader.calls != 0 {
			t.Fatalf("%q: want 400 without repository call, got %d calls=%d", bad, resp.Code, reader.calls)
		}
	}
}
