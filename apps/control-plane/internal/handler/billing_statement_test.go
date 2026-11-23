package handler

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func sampleStatement() *billing.MonthlyStatement {
	line := func(model string, req, tokens, billed, unpriced, unknown int64) billing.StatementLine {
		return billing.StatementLine{ModelName: model, Requests: req, TotalTokens: tokens, BilledMicros: billed, BilledRequests: req - unpriced - unknown,
			UnbilledRequests: unpriced + unknown, UnpricedRequests: unpriced, UsageUnknownRequests: unknown}
	}
	sum := func(lines ...billing.StatementLine) billing.StatementLine {
		var s billing.StatementLine
		for _, l := range lines {
			s.Requests += l.Requests
			s.TotalTokens += l.TotalTokens
			s.BilledMicros += l.BilledMicros
			s.BilledRequests += l.BilledRequests
			s.UnbilledRequests += l.UnbilledRequests
			s.UnpricedRequests += l.UnpricedRequests
			s.UsageUnknownRequests += l.UsageUnknownRequests
		}
		return s
	}
	employee := func(id, name string, models ...billing.StatementLine) billing.StatementEmployee {
		return billing.StatementEmployee{UserID: id, UserName: name, StatementLine: sum(models...), Models: models}
	}
	department := func(id, name string, employees ...billing.StatementEmployee) billing.StatementDepartment {
		lines := make([]billing.StatementLine, 0, len(employees))
		for _, e := range employees {
			lines = append(lines, e.StatementLine)
		}
		return billing.StatementDepartment{DepartmentID: id, DepartmentName: name, StatementLine: sum(lines...), Employees: employees}
	}
	rd := department("d1", "研发部",
		employee("u1", "=alice", line("gpt-6-luna", 3, 1500, 1_234_567, 0, 0), line("chatgpt", 2, 0, 0, 0, 2)),
		employee("u2", "李娜（测试数据）", line("claude-sonnet-5", 233, 1_120_400, 268_900_000, 0, 0), line("deepseek-v4", 51, 210_330, 0, 51, 0)))
	mkt := department("d2", "市场部", employee("u3", "王芳（测试数据）", line("gpt-6-luna", 120, 512_000, 108_200_000, 0, 0)))
	return &billing.MonthlyStatement{Month: "2026-10", Timezone: "Asia/Shanghai", Currency: "CNY",
		PeriodStart: time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC), PeriodEnd: time.Date(2026, 10, 31, 16, 0, 0, 0, time.UTC),
		Total: sum(rd.StatementLine, mkt.StatementLine), Departments: []billing.StatementDepartment{rd, mkt}}
}

func unzipParts(t *testing.T, data []byte) map[string]string {
	t.Helper()
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("not a valid xlsx zip: %v", err)
	}
	parts := map[string]string{}
	for _, file := range reader.File {
		rc, _ := file.Open()
		body, _ := io.ReadAll(rc)
		rc.Close()
		parts[file.Name] = string(body)
	}
	return parts
}

// 月度分账单 Excel：三张工作表（部门汇总 / 员工明细 / 计费口径说明），表头全中文，
// 金额两位小数，未计费单列，文本永远是字符串单元格（不能被当成公式）。
func TestMonthlyStatementXLSX(t *testing.T) {
	content, err := renderMonthlyStatementXLSX(sampleStatement())
	if err != nil {
		t.Fatal(err)
	}
	parts := unzipParts(t, content)
	workbook := parts["xl/workbook.xml"]
	for _, name := range []string{"部门汇总", "员工明细", "计费口径说明"} {
		if !strings.Contains(workbook, `name="`+name+`"`) {
			t.Fatalf("missing sheet %s: %s", name, workbook)
		}
	}
	summary, detail, notes := parts["xl/worksheets/sheet1.xml"], parts["xl/worksheets/sheet2.xml"], parts["xl/worksheets/sheet3.xml"]
	for _, header := range []string{"部门", "调用次数", "Token 数", "已计费金额（元）", "未计费调用次数", "其中未定价", "其中用量未知"} {
		if !strings.Contains(summary, ">"+header+"<") {
			t.Fatalf("summary header %q missing", header)
		}
	}
	for _, header := range []string{"部门", "员工", "模型", "调用次数", "Token 数", "金额（元）", "未计费调用次数"} {
		if !strings.Contains(detail, ">"+header+"<") {
			t.Fatalf("detail header %q missing", header)
		}
	}
	if !strings.Contains(summary, "<v>270.13</v>") || strings.Contains(summary, "270.134567") {
		t.Fatalf("amount must be rounded to two decimals: %s", summary)
	}
	if !strings.Contains(detail, ">=alice<") || strings.Contains(detail, "<f>") {
		t.Fatal("employee names must be inline strings, never formulas")
	}
	// 用量未知的行金额显示“未计费”，而不是 0.00
	if !strings.Contains(detail, ">未计费<") {
		t.Fatalf("unbilled model line must say 未计费: %s", detail)
	}
	for _, phrase := range []string{"计费口径说明", "未定价", "用量未知", "Asia/Shanghai", "四舍五入"} {
		if !strings.Contains(notes, phrase) {
			t.Fatalf("notes must mention %q", phrase)
		}
	}
	if strings.Contains(notes, "0001-01-01") {
		t.Fatal("export time must never be the zero time")
	}
	for _, english := range []string{"billing_usage_facts", "unpriced", "usage_unknown", "settled"} {
		for name, body := range parts {
			if strings.HasPrefix(name, "xl/worksheets/") && strings.Contains(body, english) {
				t.Fatalf("%s leaks technical term %q", name, english)
			}
		}
	}
}

func TestStatementCents(t *testing.T) {
	for micros, want := range map[int64]string{0: "0.00", 1_234_567: "1.23", 1_235_000: "1.24", 4_800: "0.00", 5_000: "0.01", 999_999_999_999: "1000000.00"} {
		if got := formatBillingCents(billing.Micros(micros)); got != want {
			t.Fatalf("%d -> %s want %s", micros, got, want)
		}
	}
}

// 接口：仅平台管理员；月份非法 400；format=xlsx 返回 Excel。
func TestMonthlyStatementEndpointRolesAndFormats(t *testing.T) {
	databaseURL := os.Getenv("BILLING_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("BILLING_TEST_DATABASE_URL not set")
	}
	db, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	tenant := billingHandlerTestTenant(t, "stmt")
	if _, err := db.Exec(context.Background(), `INSERT INTO tenants(id,name,edition,status) VALUES($1,$1,'enterprise','active')`, tenant); err != nil {
		t.Fatal(err)
	}
	deps := &Dependencies{BillingStore: billing.NewStore(db)}
	call := func(role, query string) *httptest.ResponseRecorder {
		req := billingHandlerAdminRequest(httptest.NewRequest(http.MethodGet, "/x?tenant_id="+tenant+"&"+query, nil), "admin", tenant, role)
		rec := httptest.NewRecorder()
		GetBillingMonthlyStatement(deps)(rec, req)
		return rec
	}
	for _, role := range []string{"tenant_admin", "dept_manager", "auditor"} {
		if rec := call(role, "month=2026-10"); rec.Code != http.StatusForbidden {
			t.Fatalf("%s got %d", role, rec.Code)
		}
	}
	if rec := call("platform_admin", "month=2026-13"); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid month got %d", rec.Code)
	}
	if rec := call("platform_admin", "month=2026-10"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"departments":[]`) {
		t.Fatalf("json status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec := call("platform_admin", "month=2026-10&format=xlsx")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "spreadsheetml") || !strings.Contains(rec.Header().Get("Content-Disposition"), "statement-2026-10.xlsx") {
		t.Fatalf("xlsx status=%d headers=%v", rec.Code, rec.Header())
	}
	unzipParts(t, rec.Body.Bytes())
}

// 生成截图用的示例 Excel（测试数据）：设置 STATEMENT_XLSX_SAMPLE_OUT 时才写文件。
func TestWriteSampleMonthlyStatementXLSX(t *testing.T) {
	path := os.Getenv("STATEMENT_XLSX_SAMPLE_OUT")
	if path == "" {
		t.Skip("STATEMENT_XLSX_SAMPLE_OUT not set")
	}
	content, err := renderMonthlyStatementXLSX(sampleStatement())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatal(err)
	}
}
