package repository

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 留存的报表读查询在事务内 SET LOCAL jit = off：现场留存页大部分时间花在 JIT 编译上。
// 设置只在本次只读事务里生效，不影响连接池里其他查询。
func TestRetentionReadsRunWithoutJIT(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewRequestLogRepository(db)
	var jit string
	if err := repo.retentionRead().QueryRow(ctx, "SELECT current_setting('jit')").Scan(&jit); err != nil || jit != "off" {
		t.Fatalf("QueryRow jit=%q err=%v", jit, err)
	}
	rows, err := repo.retentionRead().Query(ctx, "SELECT current_setting('jit') FROM generate_series(1, 3)")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for rows.Next() {
		if err := rows.Scan(&jit); err != nil || jit != "off" {
			t.Fatalf("Query jit=%q err=%v", jit, err)
		}
		n++
	}
	rows.Close()
	if rows.Err() != nil || n != 3 {
		t.Fatalf("rows=%d err=%v", n, rows.Err())
	}
	var poolDefault, after string
	if err := db.QueryRow(ctx, "SELECT current_setting('jit')").Scan(&poolDefault); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ { // 同一池里反复取连接，确认 SET LOCAL 没有留到别的查询上
		if err := db.QueryRow(ctx, "SELECT current_setting('jit')").Scan(&after); err != nil || after != poolDefault {
			t.Fatalf("jit leaked to the pool: %q -> %q (%v)", poolDefault, after, err)
		}
	}
}

// 守门：留存仓储的读查询都经过 retentionRead，不直接用连接池查询。
func TestRetentionRepositoriesReadThroughJITOffHelper(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	dir := filepath.Dir(file)
	for _, name := range []string{"forward_proxy_access.go", "forward_proxy_access_overview.go", "evidence_runs.go", "evidence_timeline.go", "retention_request_states.go"} {
		source, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"r.db.Query(", "r.db.QueryRow("} {
			if strings.Contains(string(source), forbidden) {
				t.Fatalf("%s reads with %s; use r.retentionRead() so the query runs with jit=off", name, forbidden)
			}
		}
	}
}

// 留存完整汇总的风险原因、请求/响应正文有无改读 request_logs 上的预算列；列为空时回退原表达式。
// 预算前后整份汇总（含风险类别分面、证据完整性计数）必须一致，列值也必须等于原表达式。
func TestRetentionSummaryPrecomputedColumnsMatchLiveExpressions(t *testing.T) {
	db, ctx, tenantID, _, projectID := setupAuditStatsRegressionFixture(t)
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `DELETE FROM access_content_logs WHERE tenant_id = $1`, tenantID)
	})
	suffix := time.Now().UnixNano()
	now := time.Now().UTC()
	id := func(name string) string { return fmt.Sprintf("%s_%d", name, suffix) }
	insertRequest := func(name, mode, input, output string) {
		t.Helper()
		var proxyMode any
		if mode != "" {
			proxyMode = mode
		}
		var in, out any
		if input != "" {
			in = input
		}
		if output != "" {
			out = output
		}
		if _, err := db.Exec(ctx, `INSERT INTO request_logs (id, request_id, tenant_id, project_id, endpoint_type, request_status,
			proxy_mode, proxy_target_host, proxy_access_type, proxy_access_type_resolved, proxy_provider, environment_scope,
			input_audit_result, output_audit_result, created_at)
			VALUES ($1, $1, $2, $3, 'proxy', 'success', $4, 'chat.example.test', 'llm', 'llm', 'example', 'customer', $5::jsonb, $6::jsonb, $7)`,
			id(name), tenantID, projectID, proxyMode, in, out, now.Add(-time.Minute)); err != nil {
			t.Fatalf("insert %s: %v", name, err)
		}
	}
	finding := func(category string) string {
		return fmt.Sprintf(`{"action_taken":"audit","findings":[{"type":"pii","category":%q,"severity":"high","rule_id":"r_%s","action":"audit","redacted_evidence":"a***b","matched_location":"content[1:4]"}]}`, category, category)
	}
	insertRequest("reverse_full", "", finding("email"), "")
	insertRequest("reverse_empty", "", "", "")
	insertRequest("forward_a", "forward", "", finding("phone_cn"))
	insertRequest("forward_b", "forward", finding("id_card_cn"), "")
	for i, role := range []string{"user", "assistant"} {
		if _, err := db.Exec(ctx, `INSERT INTO content_logs (id, request_id, tenant_id, session_id, role, content, tokens, environment_scope, created_at)
			VALUES ($1, $2, $3, 's', $4, $5, 1, 'customer', $6)`, fmt.Sprintf("%s_%d", id("reverse_full"), i), id("reverse_full"), tenantID, role, "正文 "+role, now.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO content_logs (id, request_id, tenant_id, session_id, role, content, tokens, environment_scope, created_at)
		VALUES ($1, $2, $3, 's', 'user', '   ', 1, 'customer', $4)`, id("reverse_empty")+"_0", id("reverse_empty"), tenantID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	for _, row := range [][3]string{{"forward_a", "请求正文", ""}, {"forward_b", "", "响应正文"}} {
		if _, err := db.Exec(ctx, `INSERT INTO access_content_logs (request_id, tenant_id, conversation_id, section_id, request_content_redacted, response_content_redacted, environment_scope, created_at)
			VALUES ($1, $2, $3, $1, NULLIF($4, ''), NULLIF($5, ''), 'customer', $6)`, id(row[0]), tenantID, id("conversation"), row[1], row[2], now.Add(-time.Minute)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO security_events (id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, created_at)
		VALUES ($1, $2, $3, $4, 'security_check', 'high', 'flag', '{"findings":[{"type":"secret","category":"api_key","severity":"high","rule_id":"r_key","action":"audit","redacted_evidence":"sk-***"}]}', $5)`,
		id("event"), id("reverse_empty"), tenantID, projectID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}

	repo := NewRequestLogRepository(db)
	for {
		n, err := repo.BackfillRiskColumns(ctx, 5000)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
	}
	var mismatched int
	if err := db.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM request_logs rl WHERE rl.tenant_id = $1 AND (
		rl.risk_reasons IS DISTINCT FROM (%s) OR rl.request_body_exists IS DISTINCT FROM (%s) OR rl.response_body_exists IS DISTINCT FROM (%s))`,
		forwardProxyRiskReasonsExpr(), forwardProxyRequestBodyExistsExpr(), forwardProxyResponseBodyExistsExpr()), tenantID).Scan(&mismatched); err != nil {
		t.Fatal(err)
	}
	if mismatched != 0 {
		t.Fatalf("%d rows have precomputed values that differ from the live expressions", mismatched)
	}
	var reasons string
	if err := db.QueryRow(ctx, `SELECT risk_reasons::text FROM request_logs WHERE id = $1`, id("reverse_empty")).Scan(&reasons); err != nil || reasons == "[]" {
		t.Fatalf("security event reason not precomputed: %s %v", reasons, err)
	}

	filters := []ForwardProxyAccessFilter{
		{AccessType: "all", StartTime: now.Add(-time.Hour), EndTime: now.Add(time.Hour), EnvironmentScope: "customer"},
		{AccessType: "all", Direction: "forward", StartTime: now.Add(-time.Hour), EndTime: now.Add(time.Hour), EnvironmentScope: "customer"},
	}
	precomputed := make([]ForwardProxyAccessSummary, len(filters))
	for i, f := range filters {
		summary, err := repo.GetForwardProxyAccessSummary(ctx, tenantID, f)
		if err != nil {
			t.Fatal(err)
		}
		precomputed[i] = summary
	}
	if precomputed[0].Total == 0 || precomputed[0].EvidenceQuality.CompleteCount == 0 || len(precomputed[0].TopRiskCategories) == 0 {
		t.Fatalf("fixture did not exercise reasons and evidence quality: %+v", precomputed[0])
	}
	if _, err := db.Exec(ctx, `UPDATE request_logs SET risk_reasons = NULL, request_body_exists = NULL, response_body_exists = NULL WHERE tenant_id = $1`, tenantID); err != nil {
		t.Fatal(err)
	}
	for i, f := range filters {
		live, err := repo.GetForwardProxyAccessSummary(ctx, tenantID, f)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(live, precomputed[i]) {
			t.Fatalf("filter %d: summary from precomputed columns differs from live expressions\nprecomputed=%+v\nlive=%+v", i, precomputed[i], live)
		}
	}

	// 晚到的安全事件：最近窗口刷新后预算列跟上。
	if _, err := repo.BackfillRiskColumns(ctx, 5000); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO security_events (id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, created_at)
		VALUES ($1, $2, $3, $4, 'security_check', 'high', 'flag', '{"findings":[{"type":"pii","category":"bank_card_cn","severity":"high","rule_id":"r_bank","action":"audit","redacted_evidence":"6222***"}]}', $5)`,
		id("late"), id("forward_a"), tenantID, projectID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.RefreshRecentRiskColumns(ctx, 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM request_logs rl WHERE rl.tenant_id = $1 AND rl.risk_reasons IS DISTINCT FROM (%s)`, forwardProxyRiskReasonsExpr()), tenantID).Scan(&mismatched); err != nil || mismatched != 0 {
		t.Fatalf("refresh did not catch up with the late event: %d %v", mismatched, err)
	}
}
