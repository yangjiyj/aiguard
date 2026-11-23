package handler

// W8 真库测试：每条都对应一个 W8 修复项，在基线上会失败。
// 需要 WS8_TEST_DATABASE_URL（缺省回退 RULES_TEST_DATABASE_URL）。

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func setupWS8TestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("WS8_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("RULES_TEST_DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("WS8_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	schema := fmt.Sprintf("ws8_%d", time.Now().UnixNano())
	ident := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+ident); err != nil {
		admin.Close()
		t.Fatalf("create schema: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+ident+" CASCADE")
		admin.Close()
	})
	for _, stmt := range []string{
		`CREATE TABLE tenants (id VARCHAR(64) PRIMARY KEY, config_json JSONB DEFAULT '{}')`,
		`CREATE TABLE users (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), username VARCHAR(255))`,
		`CREATE TABLE usage_rollup_hourly (tenant_id VARCHAR(64), bucket_start TIMESTAMPTZ, project_id VARCHAR(64) DEFAULT '',
			user_id VARCHAR(64) DEFAULT '', model_id VARCHAR(64) DEFAULT '', request_count INT DEFAULT 0,
			input_tokens BIGINT DEFAULT 0, output_tokens BIGINT DEFAULT 0, total_cost DECIMAL(18,6) DEFAULT 0)`,
		`CREATE TABLE security_events (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), project_id VARCHAR(64), user_id VARCHAR(64),
			action_taken VARCHAR(32), created_at TIMESTAMPTZ DEFAULT NOW())`,
		`CREATE TABLE audit_operations (id VARCHAR(64) PRIMARY KEY, user_id VARCHAR(64), tenant_id VARCHAR(64), action_type VARCHAR(64),
			action_detail JSONB DEFAULT '{}', target_type VARCHAR(64), target_id VARCHAR(64), ip_address VARCHAR(64),
			created_at TIMESTAMPTZ DEFAULT NOW())`,
		`CREATE TABLE alert_inbox (id VARCHAR(64) PRIMARY KEY, tenant_id VARCHAR(64), severity VARCHAR(16), type VARCHAR(64),
			title TEXT, body_json JSONB DEFAULT '{}', target_url TEXT, read_at TIMESTAMPTZ, created_at TIMESTAMPTZ DEFAULT NOW())`,
		`INSERT INTO tenants VALUES ('t1', '{"timezone":"Asia/Tokyo"}'), ('t2', '{}')`,
		`INSERT INTO users VALUES ('u1','t1','alice'), ('u2','t1','bob'), ('u9','t2','mallory')`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("fixture %q: %v", stmt[:30], err)
		}
	}
	return pool
}

func ws8Request(method, target, tenant, role string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	user := &repository.User{ID: "u1", TenantID: tenant, Role: role, Status: "active"}
	return req.WithContext(context.WithValue(req.Context(), auth.UserKey, user))
}

// 8.1：占比分母必须与所选窗口一致；基线只返回裸数组，前端只能拿全历史/近 30 天当分母。
func TestWS8UserStatsTotalsMatchSelectedWindow(t *testing.T) {
	pool := setupWS8TestDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Hour)
	old := now.AddDate(0, 0, -60)
	for _, row := range []struct {
		at      time.Time
		user    string
		req     int
		in, out int64
	}{
		{now.Add(-2 * time.Hour), "u1", 3, 100, 50},
		{now.Add(-3 * time.Hour), "u2", 1, 30, 20},
		{old, "u1", 90, 9000, 1000},          // 窗口外，不能进分母
		{now.Add(-time.Hour), "", 7, 700, 0}, // 未归属用户，不进用户占比分母
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO usage_rollup_hourly (tenant_id,bucket_start,user_id,request_count,input_tokens,output_tokens) VALUES ('t1',$1,$2,$3,$4,$5)`,
			row.at, row.user, row.req, row.in, row.out); err != nil {
			t.Fatal(err)
		}
	}
	deps := &Dependencies{UsageDailyRepo: repository.NewUsageDailyRepository(pool)}
	start := now.AddDate(0, 0, -7).Format(time.RFC3339)
	end := now.Add(time.Hour).Format(time.RFC3339)
	rr := httptest.NewRecorder()
	GetUserStats(deps)(rr, ws8Request(http.MethodGet, "/admin/v1/stats/users?by=tokens&with_totals=true&start="+start+"&end="+end, "t1", "tenant_owner"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data   []repository.UserStats     `json:"data"`
		Totals repository.UserUsageTotals `json:"totals"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode %s: %v", rr.Body.String(), err)
	}
	if resp.Totals.TotalTokens != 200 || resp.Totals.TotalRequests != 4 {
		t.Fatalf("totals = %+v, want tokens 200 requests 4 (window-scoped, attributed users only)", resp.Totals)
	}
	if len(resp.Data) != 2 || resp.Data[0].TotalTokens != 150 {
		t.Fatalf("ranking = %+v", resp.Data)
	}
}

// 8.3/8.5/8.9：概览下发租户时区、最早数据日与执行模式。
func TestWS8OverviewCarriesTimezoneDataStartAndMode(t *testing.T) {
	pool := setupWS8TestDB(t)
	ctx := context.Background()
	first := time.Date(2026, 3, 4, 20, 0, 0, 0, time.UTC) // 东京时间 3 月 5 日 05:00
	if _, err := pool.Exec(ctx, `INSERT INTO usage_rollup_hourly (tenant_id,bucket_start,user_id,request_count) VALUES ('t1',$1,'u1',1), ('t1',$2,'u1',1)`,
		first, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	deps := &Dependencies{UsageDailyRepo: repository.NewUsageDailyRepository(pool), SystemRepo: &agentGuardAuditSystemRepo{}}
	rr := httptest.NewRecorder()
	GetStatsOverview(deps)(rr, ws8Request(http.MethodGet, "/admin/v1/stats/overview", "t1", "tenant_owner"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp["timezone"] != "Asia/Tokyo" {
		t.Fatalf("timezone = %v, want tenant timezone Asia/Tokyo", resp["timezone"])
	}
	if resp["data_start"] != "2026-03-05" {
		t.Fatalf("data_start = %v, want 2026-03-05 in tenant timezone", resp["data_start"])
	}
	mode, _ := resp["execution_mode"].(map[string]any)
	if mode == nil || (mode["effective_mode"] != "record" && mode["effective_mode"] != "protect") {
		t.Fatalf("execution_mode = %v", resp["execution_mode"])
	}
	if _, ok := resp["today_requests"]; !ok {
		t.Fatalf("legacy overview fields missing: %v", resp)
	}
}

func seedWS8AuditOps(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	rows := []struct {
		id, user, tenant, action string
		at                       time.Time
	}{
		{"op1", "u1", "t1", "create_user", base},
		{"op2", "u2", "", "delete_key", base.Add(24 * time.Hour)}, // tenant_id 为空，靠操作人归属到 t1
		{"op3", "u1", "t1", "delete_key", base.Add(48 * time.Hour)},
		{"op4", "u9", "t2", "delete_key", base.Add(48 * time.Hour)}, // 其他租户
	}
	for _, row := range rows {
		var tenant any
		if row.tenant != "" {
			tenant = row.tenant
		}
		if _, err := pool.Exec(ctx, `INSERT INTO audit_operations (id,user_id,tenant_id,action_type,action_detail,target_type,target_id,ip_address,created_at)
			VALUES ($1,$2,$3,$4,'{"k":"=cmd"}','key','k1','10.0.0.1',$5)`, row.id, row.user, tenant, row.action, row.at); err != nil {
			t.Fatal(err)
		}
	}
}

// 8.7：操作审计按租户隔离，并支持时间/动作筛选；基线不按租户过滤、忽略 from/to/action_type。
func TestWS8OperationAuditFiltersAndTenantScope(t *testing.T) {
	pool := setupWS8TestDB(t)
	seedWS8AuditOps(t, pool)
	deps := &Dependencies{UsageDailyRepo: repository.NewUsageDailyRepository(pool), SystemRepo: repository.NewSystemRepository(pool)}
	rr := httptest.NewRecorder()
	ListAuditOperationsW8(deps)(rr, ws8Request(http.MethodGet, "/admin/v1/system/audit-operations?action_type=delete_key&from=2026-09-02T00:00:00Z&to=2026-09-10T00:00:00Z", "t1", "tenant_admin"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Data  []map[string]any `json:"data"`
		Total int              `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Total != 2 || len(resp.Data) != 2 {
		t.Fatalf("got %d/%d rows, want op2+op3 only: %s", len(resp.Data), resp.Total, rr.Body.String())
	}
	for _, row := range resp.Data {
		if row["id"] == "op4" || row["id"] == "op1" {
			t.Fatalf("unexpected row %v", row["id"])
		}
	}
}

// 8.7：服务端全量导出 CSV，时间按租户时区，公式注入被中和，导出本身写审计。
func TestWS8OperationAuditExportCSVIsFullAndAudited(t *testing.T) {
	pool := setupWS8TestDB(t)
	seedWS8AuditOps(t, pool)
	deps := &Dependencies{UsageDailyRepo: repository.NewUsageDailyRepository(pool), SystemRepo: repository.NewSystemRepository(pool)}
	rr := httptest.NewRecorder()
	ExportAuditOperations(deps)(rr, ws8Request(http.MethodGet, "/admin/v1/system/audit-operations/export?format=csv", "t1", "auditor"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.Bytes()
	if !bytes.HasPrefix(body, []byte("\ufeff")) {
		t.Fatalf("csv must start with UTF-8 BOM")
	}
	records, err := csv.NewReader(bytes.NewReader(bytes.TrimPrefix(body, []byte("\ufeff")))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 4 { // header + op1..op3
		t.Fatalf("rows = %d, want header + 3 tenant rows: %v", len(records), records)
	}
	if !strings.Contains(records[0][0], "Asia/Tokyo") {
		t.Fatalf("header must name tenant timezone: %v", records[0])
	}
	if records[3][0] != "2026-09-01 09:00:00" {
		t.Fatalf("oldest row time = %q, want tenant-local 2026-09-01 09:00:00", records[3][0])
	}
	var audited int
	if err := pool.QueryRow(context.Background(), `SELECT COUNT(*) FROM audit_operations WHERE action_type='export_operation_audit' AND action_detail->>'rows'='3' AND action_detail->>'format'='csv'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if audited != 1 {
		t.Fatalf("export must leave exactly one audit record, got %d", audited)
	}
}

// 8.7：XLSX 是合法 OOXML 包，工作表内容为全量数据。
func TestWS8AlertInboxExportXLSXAndFilters(t *testing.T) {
	pool := setupWS8TestDB(t)
	ctx := context.Background()
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 30; i++ { // 超过旧接口默认 limit 20
		sev := "info"
		if i%3 == 0 {
			sev = "high"
		}
		if _, err := pool.Exec(ctx, `INSERT INTO alert_inbox (id,tenant_id,severity,type,title,created_at) VALUES ($1,'t1',$2,'budget',$3,$4)`,
			fmt.Sprintf("a%02d", i), sev, fmt.Sprintf("title <%d> & more", i), base.Add(time.Duration(i)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO alert_inbox (id,tenant_id,severity,type,title) VALUES ('x1','t2','high','budget','other tenant')`); err != nil {
		t.Fatal(err)
	}
	deps := &Dependencies{UsageDailyRepo: repository.NewUsageDailyRepository(pool), AlertInboxRepo: repository.NewAlertInboxRepository(pool), SystemRepo: repository.NewSystemRepository(pool)}

	rr := httptest.NewRecorder()
	ListAlertInboxW8(deps)(rr, ws8Request(http.MethodGet, "/admin/v1/alerts/inbox?severity=high&limit=5", "t1", "tenant_owner"))
	var list struct {
		Items []repository.AlertInboxItem `json:"items"`
		Total int                         `json:"total"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if list.Total != 10 || len(list.Items) != 5 {
		t.Fatalf("severity filter: total=%d items=%d, want 10/5", list.Total, len(list.Items))
	}

	rr = httptest.NewRecorder()
	ExportAlertInbox(deps)(rr, ws8Request(http.MethodGet, "/admin/v1/alerts/inbox/export?format=xlsx", "t1", "tenant_owner"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rr.Code, rr.Body.String())
	}
	zr, err := zip.NewReader(bytes.NewReader(rr.Body.Bytes()), int64(rr.Body.Len()))
	if err != nil {
		t.Fatalf("xlsx is not a zip: %v", err)
	}
	var sheet string
	for _, f := range zr.File {
		if f.Name == "xl/worksheets/sheet1.xml" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			sheet = string(b)
		}
	}
	if got := strings.Count(sheet, "<row "); got != 31 {
		t.Fatalf("xlsx rows = %d, want header + 30 (full export, tenant scoped)", got)
	}
	if strings.Contains(sheet, "other tenant") || !strings.Contains(sheet, "title &lt;7&gt; &amp; more") {
		t.Fatalf("sheet content not scoped/escaped")
	}
	var audited int
	_ = pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_operations WHERE action_type='export_alert_inbox'`).Scan(&audited)
	if audited != 1 {
		t.Fatalf("alert export audit rows = %d, want 1", audited)
	}
}

func TestWS8ExportRejectsUnknownFormat(t *testing.T) {
	rr := httptest.NewRecorder()
	ExportAlertInbox(&Dependencies{})(rr, ws8Request(http.MethodGet, "/admin/v1/alerts/inbox/export?format=pdf", "t1", "tenant_owner"))
	if rr.Code == http.StatusOK {
		t.Fatalf("unknown format must be rejected")
	}
}

func TestWS8CSVNeutralisesFormulaCells(t *testing.T) {
	out, err := encodeCSV(reportTable{Headers: []string{"a"}, Rows: [][]string{{"=HYPERLINK(1)"}, {"normal"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "'=HYPERLINK(1)") || strings.Contains(string(out), "\n=HYPERLINK") {
		t.Fatalf("formula cell not neutralised: %q", out)
	}
}
