package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 常见词先按时间倒序取够一页（keyword_recent），凑不够再回到完整匹配：两条路的结果必须和完整匹配逐条一致。
func TestRetentionKeywordRecentFirstMatchesFullSearch(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	suffix := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant_kwrecent_%d", suffix)
	projectID := fmt.Sprintf("project_kwrecent_%d", suffix)
	userID := fmt.Sprintf("user_kwrecent_%d", suffix)
	t.Cleanup(func() {
		for _, statement := range []string{
			"DELETE FROM content_logs WHERE tenant_id = $1",
			"DELETE FROM content_logs_legacy WHERE tenant_id = $1",
			"DELETE FROM access_content_logs WHERE tenant_id = $1",
			"DELETE FROM request_logs WHERE tenant_id = $1",
			"DELETE FROM content_log_bodies WHERE tenant_id = $1",
			"DELETE FROM users WHERE tenant_id = $1",
			"DELETE FROM projects WHERE tenant_id = $1",
			"DELETE FROM tenants WHERE id = $1",
		} {
			if _, cleanupErr := db.Exec(context.Background(), statement, tenantID); cleanupErr != nil {
				t.Logf("cleanup %q: %v", statement, cleanupErr)
			}
		}
		db.Close()
	})
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
	}
	exec(`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`, tenantID)
	exec(`INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $1)`, projectID, tenantID)
	exec(`INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, '常见词用户', 'auditor', 'active')`, userID, tenantID)

	base := time.Now().UTC().Add(-2 * time.Hour).Truncate(time.Second)
	at := func(minute int) time.Time { return base.Add(time.Duration(minute) * time.Minute) }
	internal := func(i int) string { return fmt.Sprintf("rl_kwr_%d_%d", i, suffix) }
	external := func(i int) string { return fmt.Sprintf("req_kwr_%d_%d", i, suffix) }
	for i := 0; i < 40; i++ {
		exec(`INSERT INTO request_logs (
				id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status,
				proxy_mode, proxy_target_host, proxy_target_path, proxy_method,
				proxy_access_type, proxy_access_type_resolved, proxy_provider, proxy_product,
				proxy_tls_inspected, proxy_content_retained, proxy_retention_level,
				proxy_endpoint_kind, risk_state, has_retained_content, environment_scope, created_at
			) VALUES ($1, $2, $3, $4, $5, 'proxy', 'success', 'chat_completion', 'api.deepseek.com', '/v1/chat/completions', 'POST',
				'llm', 'llm', 'deepseek', 'deepseek_api', TRUE, TRUE, 'content', 'chat', 'normal', TRUE, 'customer', $6)`,
			internal(i), external(i), tenantID, projectID, userID, at(i))
		content := func(id, role, text string) {
			exec(`INSERT INTO content_logs (id, request_id, tenant_id, user_id, role, content, environment_scope, created_at)
				VALUES ($1, $2, $3, $4, $5, $6, 'customer', $7)`, id, internal(i), tenantID, userID, role, text, at(i))
		}
		switch {
		case i%3 == 0: // 常见词：同一份正文被很多请求引用（历史上下文）
			content(fmt.Sprintf("cl_u_%d_%d", i, suffix), "user", "历史上下文正文 marker 共享")
			content(fmt.Sprintf("cl_a_%d_%d", i, suffix), "assistant", fmt.Sprintf("回答 %d", i))
		case i%7 == 1: // 只在输出里出现
			content(fmt.Sprintf("cl_u_%d_%d", i, suffix), "user", fmt.Sprintf("问题 %d", i))
			content(fmt.Sprintf("cl_a_%d_%d", i, suffix), "assistant", fmt.Sprintf("输出里有历史上下文正文 %d", i))
		case i%11 == 2: // 系统、工具消息和非客户正文不算
			content(fmt.Sprintf("cl_s_%d_%d", i, suffix), "system", "历史上下文正文 system")
			content(fmt.Sprintf("cl_t_%d_%d", i, suffix), "tool", "历史上下文正文 tool")
			content(fmt.Sprintf("cl_r_%d_%d", i, suffix), "user", "<system-reminder>历史上下文正文</system-reminder>")
		default:
			content(fmt.Sprintf("cl_u_%d_%d", i, suffix), "user", fmt.Sprintf("无关 %d", i))
		}
	}
	// 旧表里的正文和访问留存里的命中也要算上。
	exec(`INSERT INTO content_logs_legacy (id, request_id, tenant_id, user_id, role, content, environment_scope, created_at)
		VALUES ($1, $2, $3, $4, 'user', '旧表 历史上下文正文', 'customer', $5)`, fmt.Sprintf("cl_legacy_%d", suffix), internal(38), tenantID, userID, at(38))
	exec(`INSERT INTO access_content_logs (id, request_id, tenant_id, request_content_redacted, response_content_redacted, file_metadata_json, environment_scope, created_at)
		VALUES ($1, $2, $3, '访问留存 历史上下文正文', '', '[]'::jsonb, 'customer', $4)`, fmt.Sprintf("acl_kwr_%d", suffix), external(37), tenantID, at(37))

	repo := NewRequestLogRepository(db)
	search := func(filter ForwardProxyAccessFilter) []string {
		t.Helper()
		records, _, err := repo.ListForwardProxyAccess(ctx, tenantID, filter)
		if err != nil {
			t.Fatalf("search %+v: %v", filter, err)
		}
		ids := make([]string, 0, len(records))
		for _, record := range records {
			ids = append(ids, record.RequestID)
		}
		return ids
	}
	restore := func(entries, scan int) func() {
		old := retentionKeywordRecentDefaults
		retentionKeywordRecentDefaults = keywordRecentThresholds{denseEntries: entries, recentScan: scan}
		return func() { retentionKeywordRecentDefaults = old }
	}
	window := ForwardProxyAccessFilter{AccessType: "all", EnvironmentScope: "customer", StartTime: base.Add(-time.Minute), EndTime: time.Now().UTC()}
	filters := []ForwardProxyAccessFilter{}
	for _, keyword := range []string{"历史上下文正文", "MARKER", "历史上", "上下"} {
		for _, scope := range []string{"", "request", "response"} {
			for _, page := range []struct {
				limit, offset int
				probe         bool
			}{{5, 0, true}, {5, 5, true}, {20, 0, false}, {3, 9, true}} {
				f := window
				f.Keyword, f.KeywordScope, f.Limit, f.Offset, f.ProbeHasMore = keyword, scope, page.limit, page.offset, page.probe
				filters = append(filters, f)
			}
		}
	}
	full := map[int][]string{}
	func() {
		defer restore(1<<30, 400)()
		for i, f := range filters {
			full[i] = search(f)
		}
	}()
	if got := full[0]; len(got) != 6 || got[0] != external(39) {
		t.Fatalf("full search first page = %v", got)
	}
	for _, mode := range []struct {
		name          string
		entries, scan int
	}{{"按时间倒序取够一页", 1, 400}, {"倒序凑不够回到完整匹配", 1, 2}} {
		func() {
			defer restore(mode.entries, mode.scan)()
			for i, f := range filters {
				if got := search(f); strings.Join(got, ",") != strings.Join(full[i], ",") {
					t.Fatalf("%s：keyword=%q scope=%q limit=%d offset=%d got %v want %v", mode.name, f.Keyword, f.KeywordScope, f.Limit, f.Offset, got, full[i])
				}
			}
		}()
	}

	// 倒序路径真的生效：来源 SQL 只交出一页所需的正文请求，不再把全部命中都物化出来。
	func() {
		defer restore(1, 400)()
		filter := normalizeForwardProxyFilter(filters[0])
		where, args := buildForwardProxyWhere(tenantID, ForwardProxyAccessFilter{AccessType: filter.AccessType, EnvironmentScope: filter.EnvironmentScope, StartTime: filter.StartTime, EndTime: filter.EndTime, SkipTotal: true})
		where = append(where, forwardProxyInternalTitlePredicate())
		matchWhere, args := buildForwardProxyKeywordMatchWhere(filter, args)
		contentWhere := []string{}
		for _, predicate := range matchWhere {
			contentWhere = append(contentWhere, strings.ReplaceAll(predicate, "keyword_match.", "keyword_content."))
		}
		args = append(args, "%"+escapePostgresLikeLiteral(filter.Keyword)+"%")
		canonical := []string{}
		for _, predicate := range where {
			canonical = append(canonical, strings.ReplaceAll(predicate, "rl.", "keyword_canonical."))
		}
		source := retentionKeywordIndexPolicy(forwardProxyKeywordMatchSQL(matchWhere, contentWhere, len(args), &keywordRecentContent{canonicalWhere: canonical, needed: 6, thresholds: retentionKeywordRecentDefaults}), filter.Keyword, len(args))
		var rows int
		if err := db.QueryRow(ctx, "SELECT COUNT(*) FROM ("+source+") keyword_source", args...).Scan(&rows); err != nil {
			t.Fatalf("run recent-first source: %v\n%s", err, source)
		}
		if rows != 6+1 { // 一页正文请求 + 访问留存里的一条
			t.Fatalf("recent-first source returned %d rows, want 7", rows)
		}
	}()
}

// 关键字里没有分大小写的字符（中文、数字、符号）时 ILIKE 与 LIKE 结果相同，改用 LIKE 省掉整段正文转小写。
func TestRetentionKeywordUsesLikeWhenKeywordHasNoCase(t *testing.T) {
	source := forwardProxyKeywordMatchSourceSQL([]string{"keyword_match.tenant_id = $1"}, []string{"keyword_content.tenant_id = $1"}, 2)
	for _, keyword := range []string{"历史上下文正文", "合同 2026-11", "密钥库"} {
		got := retentionKeywordIndexPolicy(source, keyword, 2)
		if strings.Contains(got, " ILIKE $2") || !strings.Contains(got, "keyword_body.content LIKE $2") {
			t.Fatalf("keyword %q should use LIKE:\n%s", keyword, got)
		}
	}
	for _, keyword := range []string{"Secret", "abc", "密钥ab", "ß"} {
		got := retentionKeywordIndexPolicy(source, keyword, 2)
		if strings.Contains(got, " LIKE $2") && !strings.Contains(got, " ILIKE $2") {
			t.Fatalf("keyword %q has case and must keep ILIKE:\n%s", keyword, got)
		}
	}
}
