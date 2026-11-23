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

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 消息中心折叠视图 + 管理员批量已读的 handler 测试。
// 仓储用桩，验证：谁能调、参数怎么校验、什么情况下才会真的写、写之前审计怎么带、错误码是什么。

type inboxFoldStub struct {
	foldedFilter repository.AlertInboxFilter
	foldedTZ     string
	foldedPage   *repository.AlertInboxFoldedPage
	foldedErr    error

	itemsFilter repository.AlertInboxFoldedItemsFilter
	items       []*repository.AlertInboxItem
	itemsTotal  int

	summary []*repository.AlertInboxTypeSummary

	previewCalls  int
	previewTenant string
	previewType   string
	previewFrom   time.Time
	previewTo     time.Time
	previewResult *repository.BulkReadPreview
	previewErr    error

	bulkCalls  int
	bulkParams repository.BulkReadParams
	bulkMarked int
	bulkErr    error

	unread int
}

func (s *inboxFoldStub) CountUnread(context.Context, string) (int, error) { return s.unread, nil }

func (s *inboxFoldStub) ListFolded(_ context.Context, f repository.AlertInboxFilter, tz string) (*repository.AlertInboxFoldedPage, error) {
	s.foldedFilter, s.foldedTZ = f, tz
	return s.foldedPage, s.foldedErr
}

func (s *inboxFoldStub) ListFoldedItems(_ context.Context, f repository.AlertInboxFoldedItemsFilter) ([]*repository.AlertInboxItem, int, error) {
	s.itemsFilter = f
	return s.items, s.itemsTotal, nil
}

func (s *inboxFoldStub) TypeSummary(context.Context, string) ([]*repository.AlertInboxTypeSummary, error) {
	return s.summary, nil
}

func (s *inboxFoldStub) PreviewBulkRead(_ context.Context, tenant, typ string, from, to time.Time) (*repository.BulkReadPreview, error) {
	s.previewCalls++
	s.previewTenant, s.previewType, s.previewFrom, s.previewTo = tenant, typ, from, to
	return s.previewResult, s.previewErr
}

func (s *inboxFoldStub) BulkMarkRead(_ context.Context, p repository.BulkReadParams) (int, error) {
	s.bulkCalls++
	s.bulkParams = p
	return s.bulkMarked, s.bulkErr
}

func foldReq(role, method, target, body string) *http.Request {
	r := contentAuditAuthRequest(role) // 用户 user-a / 租户 tenant-a
	r.Method = method
	u := httptest.NewRequest(method, target, strings.NewReader(body))
	r.URL = u.URL
	r.RequestURI = target
	r.RemoteAddr = "10.0.0.7:5555"
	if body != "" {
		r.Body = u.Body
		r.Header.Set("Content-Type", "application/json")
	} else {
		r.Body = http.NoBody
	}
	return r
}

func errCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var resp struct {
		Error struct {
			Code    string         `json:"code"`
			Details map[string]any `json:"details"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应不是错误 JSON：%q", w.Body.String())
	}
	return resp.Error.Code
}

func foldDeps() *Dependencies { return &Dependencies{} }

func shanghai(*http.Request, string) (*time.Location, string) {
	loc, _ := time.LoadLocation("Asia/Shanghai")
	return loc, "Asia/Shanghai"
}

const bulkBody = `{"type":"alert","from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","expected_count":11944,"confirm":true}`

// ---------- 权限：全部写入/预览路径只有控制台管理员 ----------

func TestBulkReadEndpointsRequireConsoleAdministrator(t *testing.T) {
	for _, role := range []string{"viewer", "auditor", "developer", "chat_user", "dept_manager", "security_officer"} {
		s := &inboxFoldStub{}
		deps := foldDeps()
		w := httptest.NewRecorder()
		bulkReadAlertInboxHandler(deps, s).ServeHTTP(w, foldReq(role, http.MethodPost, "/admin/v1/alerts/inbox/bulk-read", bulkBody))
		if w.Code != http.StatusForbidden || s.bulkCalls != 0 || s.previewCalls != 0 {
			t.Fatalf("role %s 批量已读: status=%d bulk=%d preview=%d", role, w.Code, s.bulkCalls, s.previewCalls)
		}
		w = httptest.NewRecorder()
		previewBulkReadHandler(s, shanghai).ServeHTTP(w, foldReq(role, http.MethodGet,
			"/admin/v1/alerts/inbox/bulk-read/preview?type=alert&from=2026-09-03T16:00:00Z&to=2026-10-13T16:00:00Z", ""))
		if w.Code != http.StatusForbidden || s.previewCalls != 0 {
			t.Fatalf("role %s 预览: status=%d preview=%d", role, w.Code, s.previewCalls)
		}
		w = httptest.NewRecorder()
		alertInboxTypeSummaryHandler(s).ServeHTTP(w, foldReq(role, http.MethodGet, "/admin/v1/alerts/inbox/type-summary", ""))
		if w.Code != http.StatusForbidden {
			t.Fatalf("role %s 类别汇总: status=%d", role, w.Code)
		}
	}
}

// ---------- 参数校验：必须显式、完整、受保护类别拒绝 ----------

func TestBulkReadRejectsIncompleteOrUnsafeRequestsWithoutWriting(t *testing.T) {
	cases := map[string]struct {
		body string
		code string
	}{
		"缺 confirm":     {`{"type":"alert","from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","expected_count":3}`, "invalid_request"},
		"confirm=false": {`{"type":"alert","from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","expected_count":3,"confirm":false}`, "invalid_request"},
		"缺类别":           {`{"from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","expected_count":3,"confirm":true}`, "invalid_request"},
		"空类别":           {`{"type":"","from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","expected_count":3,"confirm":true}`, "invalid_request"},
		"通配类别":          {`{"type":"*","from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","expected_count":3,"confirm":true}`, "type_protected"},
		"安全事件类":         {`{"type":"security_event","from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","expected_count":3,"confirm":true}`, "type_protected"},
		"缺起点":           {`{"type":"alert","to":"2026-10-13T16:00:00Z","expected_count":3,"confirm":true}`, "invalid_request"},
		"缺终点":           {`{"type":"alert","from":"2026-09-03T16:00:00Z","expected_count":3,"confirm":true}`, "invalid_request"},
		"起点晚于终点":        {`{"type":"alert","from":"2026-10-13T16:00:00Z","to":"2026-09-03T16:00:00Z","expected_count":3,"confirm":true}`, "invalid_request"},
		"时间格式错误":        {`{"type":"alert","from":"yesterday","to":"2026-10-13T16:00:00Z","expected_count":3,"confirm":true}`, "invalid_request"},
		"缺预期条数":         {`{"type":"alert","from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","confirm":true}`, "invalid_request"},
		"预期条数为 0":       {`{"type":"alert","from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","expected_count":0,"confirm":true}`, "invalid_request"},
		"预期条数为负":        {`{"type":"alert","from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","expected_count":-1,"confirm":true}`, "invalid_request"},
		"多余字段(试图指定租户)":  {`{"type":"alert","tenant_id":"tenant-b","from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","expected_count":3,"confirm":true}`, "invalid_request"},
		"不是 JSON":       {`not json`, "invalid_request"},
		"空请求体":          {``, "invalid_request"},
	}
	for name, c := range cases {
		s := &inboxFoldStub{bulkMarked: 3}
		deps := foldDeps()
		w := httptest.NewRecorder()
		bulkReadAlertInboxHandler(deps, s).ServeHTTP(w, foldReq("tenant_admin", http.MethodPost, "/admin/v1/alerts/inbox/bulk-read", c.body))
		if w.Code != http.StatusBadRequest || errCode(t, w) != c.code {
			t.Errorf("%s: status=%d body=%s，want 400/%s", name, w.Code, w.Body.String(), c.code)
		}
		if s.bulkCalls != 0 {
			t.Errorf("%s: 被拒绝的请求不得进入写入路径（bulk=%d）", name, s.bulkCalls)
		}
	}
}

// ---------- 正常路径：租户取自会话、审计信息完整、响应带实际条数 ----------

func TestBulkReadPassesSessionTenantAndAuditContextToTheRepository(t *testing.T) {
	for _, role := range []string{"tenant_admin", "platform_admin", "admin", "tenant_owner"} {
		s := &inboxFoldStub{bulkMarked: 11944}
		deps := foldDeps()
		w := httptest.NewRecorder()
		bulkReadAlertInboxHandler(deps, s).ServeHTTP(w, foldReq(role, http.MethodPost, "/admin/v1/alerts/inbox/bulk-read", bulkBody))
		if w.Code != http.StatusOK {
			t.Fatalf("role %s: status=%d body=%s", role, w.Code, w.Body.String())
		}
		p := s.bulkParams
		if p.TenantID != "tenant-a" || p.Type != "alert" || p.ExpectedCount != 11944 {
			t.Fatalf("role %s: 参数不对 %+v", role, p)
		}
		if !p.From.Equal(time.Date(2026, 9, 3, 16, 0, 0, 0, time.UTC)) || !p.To.Equal(time.Date(2026, 10, 13, 16, 0, 0, 0, time.UTC)) {
			t.Fatalf("role %s: 时间范围不对 %v ~ %v", role, p.From, p.To)
		}
		a := p.Audit
		if a == nil || a.ID == "" || a.UserID != "user-a" || a.ActionType != "alert_inbox.bulk_read" ||
			a.TargetType != "alert_inbox" || a.TargetID != "alert" || a.IPAddress == "" {
			t.Fatalf("role %s: 审计信息不完整 %+v", role, a)
		}
		var resp struct {
			OK         bool   `json:"ok"`
			MarkedRead int    `json:"marked_read"`
			Type       string `json:"type"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || !resp.OK || resp.MarkedRead != 11944 || resp.Type != "alert" {
			t.Fatalf("role %s: 响应不对 %s", role, w.Body.String())
		}
	}
}

func TestBulkReadIgnoresTenantSuppliedByTheClient(t *testing.T) {
	s := &inboxFoldStub{bulkMarked: 3}
	deps := foldDeps()
	w := httptest.NewRecorder()
	r := foldReq("tenant_admin", http.MethodPost, "/admin/v1/alerts/inbox/bulk-read?tenant_id=tenant-b",
		`{"type":"alert","from":"2026-09-03T16:00:00Z","to":"2026-10-13T16:00:00Z","expected_count":3,"confirm":true}`)
	r.Header.Set("X-Tenant-ID", "tenant-b")
	bulkReadAlertInboxHandler(deps, s).ServeHTTP(w, r)
	if w.Code != http.StatusOK || s.bulkParams.TenantID != "tenant-a" {
		t.Fatalf("租户必须取自会话：status=%d tenant=%q", w.Code, s.bulkParams.TenantID)
	}
}

// ---------- 错误映射 ----------

func TestBulkReadMapsCountChangedTo409WithCurrentCount(t *testing.T) {
	s := &inboxFoldStub{bulkErr: &repository.BulkReadCountChangedError{Current: 12001}}
	deps := foldDeps()
	w := httptest.NewRecorder()
	bulkReadAlertInboxHandler(deps, s).ServeHTTP(w, foldReq("tenant_admin", http.MethodPost, "/admin/v1/alerts/inbox/bulk-read", bulkBody))
	if w.Code != http.StatusConflict || errCode(t, w) != "count_changed" {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Error struct {
			Details struct {
				CurrentCount int `json:"current_count"`
			} `json:"details"`
		} `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Error.Details.CurrentCount != 12001 {
		t.Fatalf("409 必须带当前条数：%s", w.Body.String())
	}
}

func TestBulkReadMapsProtectedTypeAndRepositoryFailures(t *testing.T) {
	s := &inboxFoldStub{bulkErr: repository.ErrBulkReadTypeProtected}
	deps := foldDeps()
	w := httptest.NewRecorder()
	bulkReadAlertInboxHandler(deps, s).ServeHTTP(w, foldReq("tenant_admin", http.MethodPost, "/admin/v1/alerts/inbox/bulk-read", bulkBody))
	if w.Code != http.StatusBadRequest || errCode(t, w) != "type_protected" {
		t.Fatalf("仓储层拒绝受保护类别应映射为 400/type_protected：%d %s", w.Code, w.Body.String())
	}

	s = &inboxFoldStub{bulkErr: errors.New("write audit operation: connection reset")}
	w = httptest.NewRecorder()
	bulkReadAlertInboxHandler(deps, s).ServeHTTP(w, foldReq("tenant_admin", http.MethodPost, "/admin/v1/alerts/inbox/bulk-read", bulkBody))
	if w.Code != http.StatusInternalServerError || errCode(t, w) != "internal_error" {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "connection reset") {
		t.Fatalf("内部错误细节不得返回给前端：%s", w.Body.String())
	}
}

// ---------- 预览 ----------

func TestPreviewBulkReadEchoesTheExactScopeAndNeverWrites(t *testing.T) {
	first := time.Date(2026, 9, 4, 1, 0, 0, 0, time.UTC)
	last := time.Date(2026, 10, 13, 23, 0, 0, 0, time.UTC)
	s := &inboxFoldStub{previewResult: &repository.BulkReadPreview{Matched: 11944, FirstAt: &first, LastAt: &last,
		SeverityCounts: map[string]int{"warning": 11900, "high": 44}}}
	w := httptest.NewRecorder()
	previewBulkReadHandler(s, shanghai).ServeHTTP(w, foldReq("platform_admin", http.MethodGet,
		"/admin/v1/alerts/inbox/bulk-read/preview?type=alert&from=2026-09-03T16:00:00Z&to=2026-10-13T16:00:00Z", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	if s.previewTenant != "tenant-a" || s.previewType != "alert" || s.bulkCalls != 0 {
		t.Fatalf("预览参数不对：tenant=%q type=%q bulk=%d", s.previewTenant, s.previewType, s.bulkCalls)
	}
	var resp struct {
		Type           string         `json:"type"`
		From           string         `json:"from"`
		To             string         `json:"to"`
		MatchedUnread  int            `json:"matched_unread"`
		SeverityCounts map[string]int `json:"severity_counts"`
		Timezone       string         `json:"timezone"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Type != "alert" || resp.From != "2026-09-03T16:00:00Z" || resp.To != "2026-10-13T16:00:00Z" ||
		resp.MatchedUnread != 11944 || resp.SeverityCounts["high"] != 44 || resp.Timezone == "" {
		t.Fatalf("预览响应不对：%s", w.Body.String())
	}
}

func TestPreviewBulkReadValidatesTheScope(t *testing.T) {
	for name, target := range map[string]string{
		"缺类别":    "/p?from=2026-09-03T16:00:00Z&to=2026-10-13T16:00:00Z",
		"缺起点":    "/p?type=alert&to=2026-10-13T16:00:00Z",
		"缺终点":    "/p?type=alert&from=2026-09-03T16:00:00Z",
		"时间格式错误": "/p?type=alert&from=x&to=2026-10-13T16:00:00Z",
		"起点晚于终点": "/p?type=alert&from=2026-10-13T16:00:00Z&to=2026-09-03T16:00:00Z",
	} {
		s := &inboxFoldStub{}
		w := httptest.NewRecorder()
		previewBulkReadHandler(s, shanghai).ServeHTTP(w, foldReq("tenant_admin", http.MethodGet, target, ""))
		if w.Code != http.StatusBadRequest || errCode(t, w) != "invalid_request" || s.previewCalls != 0 {
			t.Errorf("%s: status=%d code=%s calls=%d", name, w.Code, errCode(t, w), s.previewCalls)
		}
	}
	for _, typ := range []string{"security_event", "runtime_fault", "*", "billing_budget_exhausted"} {
		s := &inboxFoldStub{}
		w := httptest.NewRecorder()
		previewBulkReadHandler(s, shanghai).ServeHTTP(w, foldReq("tenant_admin", http.MethodGet,
			"/p?type="+typ+"&from=2026-09-03T16:00:00Z&to=2026-10-13T16:00:00Z", ""))
		if w.Code != http.StatusBadRequest || errCode(t, w) != "type_protected" || s.previewCalls != 0 {
			t.Errorf("%s: status=%d code=%s calls=%d", typ, w.Code, errCode(t, w), s.previewCalls)
		}
	}
}

// ---------- 折叠视图 ----------

func TestFoldedListUsesSessionTenantFiltersAndTenantTimezone(t *testing.T) {
	sample := &repository.AlertInboxItem{ID: "s1", Type: "alert", Severity: "warning", Title: "governor 事件：alert"}
	s := &inboxFoldStub{foldedPage: &repository.AlertInboxFoldedPage{
		Groups:      []*repository.AlertInboxFoldedGroup{{Key: "k", Type: "alert", Severity: "warning", Day: "2026-10-10", Count: 1221, UnreadCount: 1221, Sample: sample}},
		TotalGroups: 966, TotalItems: 20539,
	}}
	s.unread = 20539
	w := httptest.NewRecorder()
	listAlertInboxFoldedHandler(s, func(*http.Request, string) (*time.Location, string) {
		loc, _ := time.LoadLocation("Asia/Tokyo")
		return loc, "Asia/Tokyo"
	}).ServeHTTP(w, foldReq("viewer", http.MethodGet,
		"/admin/v1/alerts/inbox/folded?unread=true&severity=warning&type=alert&from=2026-10-01&to=2026-10-10&limit=50&offset=100&tenant_id=tenant-b", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	f := s.foldedFilter
	if f.TenantID != "tenant-a" || !f.UnreadOnly || f.Severity != "warning" || f.Type != "alert" || f.Limit != 50 || f.Offset != 100 {
		t.Fatalf("筛选参数不对：%+v", f)
	}
	if f.From.IsZero() || f.To.IsZero() || s.foldedTZ != "Asia/Tokyo" {
		t.Fatalf("时间范围与租户时区没有带上：from=%v to=%v tz=%q", f.From, f.To, s.foldedTZ)
	}
	var resp struct {
		Groups      []map[string]any `json:"groups"`
		TotalGroups int              `json:"total_groups"`
		TotalItems  int              `json:"total_items"`
		UnreadCount int              `json:"unread_count"`
		Timezone    string           `json:"timezone"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Groups) != 1 || resp.TotalGroups != 966 || resp.TotalItems != 20539 || resp.UnreadCount != 20539 || resp.Timezone != "Asia/Tokyo" {
		t.Fatalf("响应不对：%s", w.Body.String())
	}
	if resp.Groups[0]["count"].(float64) != 1221 || resp.Groups[0]["sample"].(map[string]any)["id"] != "s1" {
		t.Fatalf("分组字段不对：%v", resp.Groups[0])
	}
}

func TestFoldedItemsRequiresTheFullGroupIdentity(t *testing.T) {
	for name, target := range map[string]string{
		"缺 key":       "/i?type=alert&severity=warning&day_start=2026-10-09T16:00:00Z&day_end=2026-10-10T16:00:00Z",
		"缺 type":      "/i?key=abc&severity=warning&day_start=2026-10-09T16:00:00Z&day_end=2026-10-10T16:00:00Z",
		"缺 severity":  "/i?key=abc&type=alert&day_start=2026-10-09T16:00:00Z&day_end=2026-10-10T16:00:00Z",
		"缺 day_start": "/i?key=abc&type=alert&severity=warning&day_end=2026-10-10T16:00:00Z",
		"缺 day_end":   "/i?key=abc&type=alert&severity=warning&day_start=2026-10-09T16:00:00Z",
		"窗口超过 26 小时":  "/i?key=abc&type=alert&severity=warning&day_start=2026-10-01T00:00:00Z&day_end=2026-10-30T00:00:00Z",
	} {
		s := &inboxFoldStub{}
		w := httptest.NewRecorder()
		listAlertInboxFoldedItemsHandler(s, func(*http.Request, string) (*time.Location, string) { return time.UTC, "UTC" }).
			ServeHTTP(w, foldReq("viewer", http.MethodGet, target, ""))
		if w.Code != http.StatusBadRequest || errCode(t, w) != "invalid_request" || s.itemsFilter.TenantID != "" {
			t.Errorf("%s: status=%d code=%s filter=%+v", name, w.Code, errCode(t, w), s.itemsFilter)
		}
	}
	s := &inboxFoldStub{items: []*repository.AlertInboxItem{{ID: "a"}, {ID: "b"}}, itemsTotal: 2}
	w := httptest.NewRecorder()
	listAlertInboxFoldedItemsHandler(s, func(*http.Request, string) (*time.Location, string) { return time.UTC, "UTC" }).
		ServeHTTP(w, foldReq("viewer", http.MethodGet,
			"/i?key=abc&type=alert&severity=warning&day_start=2026-10-09T16:00:00Z&day_end=2026-10-10T16:00:00Z&unread=true&limit=20&offset=40&tenant_id=tenant-b", ""))
	if w.Code != http.StatusOK || s.itemsFilter.TenantID != "tenant-a" || s.itemsFilter.Key != "abc" || !s.itemsFilter.UnreadOnly ||
		s.itemsFilter.Limit != 20 || s.itemsFilter.Offset != 40 || s.itemsFilter.TZ != "UTC" {
		t.Fatalf("status=%d filter=%+v", w.Code, s.itemsFilter)
	}
	var resp struct {
		Items []map[string]any `json:"items"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || len(resp.Items) != 2 || resp.Total != 2 {
		t.Fatalf("响应不对：%v %s", err, w.Body.String())
	}
}

func TestTypeSummaryReturnsRepositoryRowsForAdministrators(t *testing.T) {
	s := &inboxFoldStub{summary: []*repository.AlertInboxTypeSummary{
		{Type: "alert", Unread: 11944, Total: 11944, BulkReadAllowed: true},
		{Type: "security_event", Unread: 2155, Total: 2155, BulkReadAllowed: false},
	}}
	w := httptest.NewRecorder()
	alertInboxTypeSummaryHandler(s).ServeHTTP(w, foldReq("tenant_admin", http.MethodGet, "/admin/v1/alerts/inbox/type-summary", ""))
	var resp struct {
		Types []struct {
			Type            string `json:"type"`
			Unread          int    `json:"unread"`
			BulkReadAllowed bool   `json:"bulk_read_allowed"`
		} `json:"types"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &resp) != nil || len(resp.Types) != 2 ||
		!resp.Types[0].BulkReadAllowed || resp.Types[1].BulkReadAllowed || resp.Types[0].Unread != 11944 {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
}

// 前端的日期范围控件传的是 YYYY-MM-DD（按租户时区，结束日含当天）。预览要把它归一化成精确的 RFC3339 时刻回显，
// 之后确认请求必须原样带回这两个时刻，这样“看到的范围”和“实际作用的范围”不会有时区歧义。
func TestPreviewBulkReadNormalizesDateOnlyInputsInTheTenantTimezone(t *testing.T) {
	s := &inboxFoldStub{previewResult: &repository.BulkReadPreview{Matched: 5, SeverityCounts: map[string]int{}}}
	w := httptest.NewRecorder()
	previewBulkReadHandler(s, shanghai).ServeHTTP(w, foldReq("tenant_admin", http.MethodGet,
		"/p?type=alert&from=2026-09-04&to=2026-10-13", ""))
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d %s", w.Code, w.Body.String())
	}
	if !s.previewFrom.Equal(time.Date(2026, 9, 3, 16, 0, 0, 0, time.UTC)) || !s.previewTo.Equal(time.Date(2026, 10, 13, 16, 0, 0, 0, time.UTC)) {
		t.Fatalf("上海时区 09-04 00:00 ~ 10-13 24:00 应对应 09-03T16:00Z ~ 10-13T16:00Z，实际 %v ~ %v", s.previewFrom, s.previewTo)
	}
	var resp struct{ From, To string }
	_ = json.Unmarshal([]byte(strings.NewReplacer(`"from"`, `"From"`, `"to"`, `"To"`).Replace(w.Body.String())), &resp)
	if resp.From != "2026-09-03T16:00:00Z" || resp.To != "2026-10-13T16:00:00Z" {
		t.Fatalf("预览必须回显归一化后的精确时刻：%s", w.Body.String())
	}
}

// 确认请求只接受精确时刻：日期形式有歧义，不允许在“写”这一步出现。
func TestBulkReadRejectsDateOnlyBounds(t *testing.T) {
	s := &inboxFoldStub{bulkMarked: 3}
	w := httptest.NewRecorder()
	bulkReadAlertInboxHandler(foldDeps(), s).ServeHTTP(w, foldReq("tenant_admin", http.MethodPost, "/admin/v1/alerts/inbox/bulk-read",
		`{"type":"alert","from":"2026-09-04","to":"2026-10-13","expected_count":3,"confirm":true}`))
	if w.Code != http.StatusBadRequest || s.bulkCalls != 0 {
		t.Fatalf("status=%d calls=%d", w.Code, s.bulkCalls)
	}
}
