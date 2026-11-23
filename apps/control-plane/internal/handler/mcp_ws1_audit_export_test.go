package handler

// W1 1.13：MCP 调用审计服务端全量导出（CSV/XLSX）+ 导出留痕。

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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func TestWS1MCPAuditExportCellSanitize(t *testing.T) {
	cases := map[string]string{
		"=1+1":      "'=1+1",
		"+cmd":      "'+cmd",
		"-2":        "'-2",
		"@SUM(A1)":  "'@SUM(A1)",
		"\tx":       "'\tx",
		"plain":     "plain",
		"":          "",
		"a=b":       "a=b",
		"fs__write": "fs__write",
	}
	for in, want := range cases {
		if got := mcpAuditExportSafeCell(in); got != want {
			t.Fatalf("sanitize %q: got %q want %q", in, got, want)
		}
	}
}

func ws1AuditExportRequest(path, tenant, userID string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	ctx := context.WithValue(req.Context(), auth.SessionKey, &repository.Session{ID: "s-" + userID, UserID: userID, Role: "tenant_admin", TenantID: tenant})
	ctx = context.WithValue(ctx, auth.UserKey, &repository.User{ID: userID, TenantID: tenant, Role: "tenant_admin"})
	return req.WithContext(ctx)
}

func ws1XLSXRowCount(t *testing.T, body []byte) (int, string) {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("xlsx is not a zip: %v", err)
	}
	need := map[string]bool{"[Content_Types].xml": false, "_rels/.rels": false, "xl/workbook.xml": false, "xl/_rels/workbook.xml.rels": false, "xl/worksheets/sheet1.xml": false}
	var sheet string
	for _, f := range zr.File {
		if _, ok := need[f.Name]; ok {
			need[f.Name] = true
		}
		if f.Name == "xl/worksheets/sheet1.xml" {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(rc)
			rc.Close()
			sheet = string(b)
		}
	}
	for name, ok := range need {
		if !ok {
			t.Fatalf("xlsx missing part %s", name)
		}
	}
	return strings.Count(sheet, "<row "), sheet
}

func TestWS1MCPAuditExportOnRealPostgres(t *testing.T) {
	dsn := os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	tenant := fmt.Sprintf("ws1ax%d", time.Now().UnixNano()%1_000_000_000)
	other := tenant + "o"
	userID := tenant + "-u"
	for _, id := range []string{tenant, other} {
		if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, id); err != nil {
			t.Fatalf("tenant: %v", err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role) VALUES ($1,$2,$1,'tenant_admin')`, userID, tenant); err != nil {
		t.Fatalf("user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM audit_operations WHERE user_id = $1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM tool_call_logs WHERE tenant_id IN ($1,$2)`, tenant, other)
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id IN ($1,$2)`, tenant, other)
	})

	insert := func(tid, reqID, toolName, toolType, effective string, ago int) {
		t.Helper()
		if _, err := pool.Exec(ctx, `INSERT INTO tool_call_logs(request_id,tenant_id,tool_name,tool_type,risk_level,status,raw_decision,effective_decision,mode,created_at)
VALUES ($1,$2,$3,$4,'high','success',$5,$5,'enforce', now() - make_interval(secs => $6))`, reqID, tid, toolName, toolType, effective, ago); err != nil {
			t.Fatalf("insert tool_call_log: %v", err)
		}
	}
	// 130 条 MCP（跨过单页 100 上限），其中 10 条 block，1 条工具名带公式前缀。
	for i := 0; i < 130; i++ {
		decision := "allow"
		if i%13 == 0 {
			decision = "block"
		}
		name := fmt.Sprintf("fs__read_%03d", i)
		if i == 7 {
			name = "evil__=cmd"
		}
		insert(tenant, fmt.Sprintf("%s-r%03d", tenant, i), name, "mcp", decision, i+1)
	}
	for i := 0; i < 5; i++ {
		insert(tenant, fmt.Sprintf("%s-f%d", tenant, i), "web_search", "function", "allow", i+1)
	}
	for i := 0; i < 3; i++ {
		insert(other, fmt.Sprintf("%s-o%d", other, i), "fs__read", "mcp", "allow", i+1)
	}

	deps := &Dependencies{
		ToolCallLogRepo: repository.NewToolCallLogRepository(pool),
		SystemRepo:      repository.NewSystemRepository(pool),
	}
	h := ExportMCPAuditLogs(deps)
	base := "/admin/v1/mcp-audit/export?from=" + time.Now().Add(-2*time.Hour).UTC().Format(time.RFC3339)

	// 未登录
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, base+"&format=csv", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated must be 401, got %d", rec.Code)
	}
	// 非法格式
	rec = httptest.NewRecorder()
	h(rec, ws1AuditExportRequest(base+"&format=pdf", tenant, userID))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad format must be 400, got %d", rec.Code)
	}

	// CSV 全量：即便调用方传 tool_type=function 也强制只导出 MCP，且不串租户。
	rec = httptest.NewRecorder()
	h(rec, ws1AuditExportRequest(base+"&format=csv&tool_type=function", tenant, userID))
	if rec.Code != http.StatusOK {
		t.Fatalf("csv export: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("csv content-type: %q", ct)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") || !strings.Contains(cd, ".csv") {
		t.Fatalf("csv content-disposition: %q", cd)
	}
	body := rec.Body.Bytes()
	if !bytes.HasPrefix(body, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatalf("csv must start with UTF-8 BOM")
	}
	records, err := csv.NewReader(bytes.NewReader(body[3:])).ReadAll()
	if err != nil {
		t.Fatalf("csv parse: %v", err)
	}
	if len(records) != 131 {
		t.Fatalf("csv must contain header + 130 mcp rows, got %d", len(records))
	}
	if rec.Header().Get("X-Export-Row-Count") != "130" || rec.Header().Get("X-Export-Truncated") != "false" {
		t.Fatalf("row headers: count=%q truncated=%q", rec.Header().Get("X-Export-Row-Count"), rec.Header().Get("X-Export-Truncated"))
	}
	joined := string(body)
	if strings.Contains(joined, "web_search") || strings.Contains(joined, other+"-o") {
		t.Fatalf("export leaked non-mcp or cross-tenant rows")
	}
	if !strings.Contains(joined, "'=cmd") || strings.Contains(joined, ",=cmd") {
		t.Fatalf("formula-leading cell must be neutralized")
	}
	seen := map[string]bool{}
	for _, row := range records[1:] {
		for _, cell := range row {
			if strings.HasPrefix(cell, tenant+"-r") {
				seen[cell] = true
			}
		}
	}
	if len(seen) != 130 {
		t.Fatalf("paged export must contain 130 distinct request ids, got %d", len(seen))
	}

	// 过滤条件透传
	rec = httptest.NewRecorder()
	h(rec, ws1AuditExportRequest(base+"&format=csv&effective_decision=block", tenant, userID))
	records, err = csv.NewReader(bytes.NewReader(rec.Body.Bytes()[3:])).ReadAll()
	if err != nil || len(records) != 11 {
		t.Fatalf("filtered export must be header + 10, got %d (%v)", len(records), err)
	}

	// XLSX
	rec = httptest.NewRecorder()
	h(rec, ws1AuditExportRequest(base+"&format=xlsx", tenant, userID))
	if rec.Code != http.StatusOK {
		t.Fatalf("xlsx export: %d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" {
		t.Fatalf("xlsx content-type: %q", ct)
	}
	rows, sheet := ws1XLSXRowCount(t, rec.Body.Bytes())
	if rows != 131 {
		t.Fatalf("xlsx must contain 131 rows, got %d", rows)
	}
	if !strings.Contains(sheet, "&#39;=cmd") && !strings.Contains(sheet, "&apos;=cmd") && !strings.Contains(sheet, "'=cmd") {
		t.Fatalf("xlsx formula-leading cell must be neutralized")
	}

	// 截断上限
	prev := mcpAuditExportMaxRows
	mcpAuditExportMaxRows = 50
	rec = httptest.NewRecorder()
	h(rec, ws1AuditExportRequest(base+"&format=csv", tenant, userID))
	mcpAuditExportMaxRows = prev
	records, _ = csv.NewReader(bytes.NewReader(rec.Body.Bytes()[3:])).ReadAll()
	if len(records) != 51 || rec.Header().Get("X-Export-Truncated") != "true" {
		t.Fatalf("capped export: rows=%d truncated=%q", len(records), rec.Header().Get("X-Export-Truncated"))
	}

	// 留痕：每次成功导出一条 mcp_audit.export，记录格式、行数、是否截断、过滤条件。
	type opRow struct {
		Detail map[string]interface{}
	}
	rs, err := pool.Query(ctx, `SELECT action_detail FROM audit_operations WHERE user_id = $1 AND action_type = 'mcp_audit.export' ORDER BY created_at`, userID)
	if err != nil {
		t.Fatal(err)
	}
	var ops []opRow
	for rs.Next() {
		var raw []byte
		if err := rs.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var d map[string]interface{}
		_ = json.Unmarshal(raw, &d)
		ops = append(ops, opRow{Detail: d})
	}
	rs.Close()
	if len(ops) != 4 {
		t.Fatalf("expected 4 export audit records, got %d", len(ops))
	}
	first := ops[0].Detail
	if first["format"] != "csv" || first["rows"] != float64(130) || first["truncated"] != false {
		t.Fatalf("first audit detail: %v", first)
	}
	if ops[1].Detail["filters"].(map[string]interface{})["effective_decision"] != "block" {
		t.Fatalf("filters must be recorded: %v", ops[1].Detail)
	}
	if ops[2].Detail["format"] != "xlsx" || ops[3].Detail["truncated"] != true {
		t.Fatalf("xlsx/truncated audit detail: %v / %v", ops[2].Detail, ops[3].Detail)
	}
}
