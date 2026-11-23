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

func TestContentSessionAlertOnlyFiltersBeforePagingAndExcludesAgentBehaviorPollution(t *testing.T) {
	for _, skipTotal := range []bool{false, true} {
		query := buildContentSessionListQueryScopedWithAlertOnly(skipTotal, "", true)
		if !strings.Contains(query, "se.alert_group_id IS NOT NULL") {
			t.Fatalf("skip_total=%v alert-only query must filter promoted events before paging", skipTotal)
		}
		if !strings.Contains(query, "agent_detect") || !strings.Contains(query, "agent_canary") {
			t.Fatalf("skip_total=%v alert-only query must exclude ordinary agent behavior but preserve canaries", skipTotal)
		}
		alertPos := strings.Index(query, "se.alert_group_id IS NOT NULL")
		pagePos := strings.Index(query, "page AS")
		if alertPos < 0 || pagePos < 0 || alertPos > pagePos {
			t.Fatalf("skip_total=%v alert filtering must happen before page selection", skipTotal)
		}
	}
}

func TestAlertOnlySessionListAlwaysUsesFastPath(t *testing.T) {
	filter := ContentSessionListFilter{AlertOnly: true, SkipTotal: false}
	useFastPath := filter.SkipTotal || filter.AlertOnly
	if !useFastPath {
		t.Fatal("alert-only session list must not use the full exact-total query")
	}
	query := buildContentSessionListQueryScopedWithAlertOnly(useFastPath, "", true)
	if !strings.Contains(query, "WITH recent_risk_events AS MATERIALIZED") {
		t.Fatal("alert-only session list must use the indexed security-event fast path")
	}
	if !strings.Contains(query, "0::bigint as total_count") {
		t.Fatal("fast path must not synchronously compute the full session total")
	}
}

func TestContentSessionQueryCountsOnlyPromotedAlertsAsActionable(t *testing.T) {
	for _, skipTotal := range []bool{false, true} {
		query := buildContentSessionListQuery(skipTotal)
		if !strings.Contains(query, "FILTER (WHERE se.alert_group_id IS NOT NULL") {
			t.Fatalf("skip_total=%v query must count only promoted alerts", skipTotal)
		}
		if !strings.Contains(query, "agent_detect") || !strings.Contains(query, "agent_canary") {
			t.Fatalf("skip_total=%v actionable count must exclude ordinary agent behavior pollution", skipTotal)
		}
	}
}

func TestScopedContentSessionQueryUsesScopeAndHalfOpenBoundary(t *testing.T) {
	for _, skipTotal := range []bool{false, true} {
		query := buildContentSessionListQueryScoped(skipTotal, "customer")
		if !strings.Contains(query, "environment_scope = ANY($6)") {
			t.Fatalf("skip_total=%v query missing explicit scope predicate", skipTotal)
		}
		if strings.Contains(query, "created_at <= $3") {
			t.Fatalf("skip_total=%v query uses a closed end boundary", skipTotal)
		}
		if !strings.Contains(query, "created_at < $3") {
			t.Fatalf("skip_total=%v query missing half-open end boundary", skipTotal)
		}
		if !strings.Contains(query, "se_scope_rl.environment_scope = ANY($6)") {
			t.Fatalf("skip_total=%v query missing security-event scope join", skipTotal)
		}
		if strings.Contains(query, "se.tenant_id = $1 AND se.request_id") {
			t.Fatalf("skip_total=%v query leaves security events outside the scope window", skipTotal)
		}
	}
}

func TestContentSessionProjectScopeFiltersEventsAndEveryContentMemberBeforePaging(t *testing.T) {
	query := scopeContentSessionProjectQuery(
		buildContentSessionListQueryScopedWithAlertOnly(true, "customer", true),
		7,
	)
	pagePos := strings.Index(query, "page AS")
	projectPos := strings.Index(query, "se.project_id = ANY($7)")
	if projectPos < 0 || pagePos < 0 || projectPos > pagePos {
		t.Fatalf("project authorization must filter event candidates before paging: %s", query)
	}
	if !strings.Contains(query, "content_scope_rl.project_id = ANY($7)") {
		t.Fatalf("every content member must be project scoped for mixed sessions: %s", query)
	}
}

func TestContentSessionCombinedFiltersRunBeforePagingAndSearchBothContentStores(t *testing.T) {
	query := buildContentSessionListQueryScopedWithAlertOnly(true, "customer", true)
	args := []interface{}{"tenant-a", time.Now().Add(-time.Hour), time.Now(), 21, 0, []string{"customer"}}
	query = scopeContentSessionAlertFilters(query, ContentSessionListFilter{
		UserID: "user-a", Keyword: "越权", Categories: []string{"prompt_injection", "secret_leak"},
		Severities: []string{"high", "critical"}, Dispositions: []string{"open", "escalated"},
	}, 6, &args)
	pagePos := strings.Index(query, "page AS")
	for _, required := range []string{
		"se.user_id =", "finding_filter->>'category'", "se.severity, '')) = ANY(",
		"audit_dispositions disposition_event", "FROM content_logs keyword_content",
		"FROM access_content_logs keyword_access",
	} {
		pos := strings.Index(query, required)
		if pos < 0 || pos > pagePos {
			t.Fatalf("combined filter %q must run before paging: %s", required, query)
		}
	}
	if strings.Contains(query, "LIMIT GREATEST(($4::bigint + $5::bigint)") {
		t.Fatal("silent candidate truncation must not masquerade as complete pagination")
	}
}

func TestContentSessionUserAndCategoryFiltersUseEffectiveEvidence(t *testing.T) {
	query := buildContentSessionListQueryScopedWithAlertOnly(true, "customer", true)
	args := []interface{}{"tenant-a", time.Now().Add(-time.Hour), time.Now(), 21, 0, []string{"customer"}}
	query = scopeContentSessionAlertFilters(query, ContentSessionListFilter{
		UserID: "user-a", Keyword: "needle", Categories: []string{"prompt_injection"},
	}, 6, &args)
	for _, required := range []string{
		"LEFT(user_filter_request.client_id, 7) = 'caller_'",
		"COALESCE(finding_filter->>'counts_as_security_finding', 'true') <> 'false'",
		"keyword_content.role IN ('user', 'assistant')",
		"jjdguard_customer_content_text(keyword_content.content)",
		"jjdguard_customer_content_text(keyword_access.request_content_redacted)",
		"jjdguard_customer_content_text(keyword_access.response_content_redacted)",
		"visible_file->>'file_name'",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("combined filter missing %q: %s", required, query)
		}
	}
	if strings.Contains(query, "file_metadata_json::text") {
		t.Fatalf("keyword filter must not search raw file metadata JSON: %s", query)
	}
}

func TestFastContentSessionQueryFallsBackOnlyWhenContentSessionIsMissing(t *testing.T) {
	query := buildFastContentSessionListQueryWithAlertOnly(true)
	for _, required := range []string{
		"LEFT JOIN LATERAL",
		"CASE WHEN pick.session_id IS NULL THEN rc.request_key ELSE pick.session_id END AS session_id",
		"CASE WHEN pick.session_id IS NULL THEN NULL ELSE rc.client_session_id END AS client_session_id",
		"CASE WHEN pc.session_id IS NULL THEN 'access_retention' ELSE 'content_logs' END AS _source",
		"CASE WHEN pc.session_id IS NULL THEN p.request_key ELSE '' END AS request_id",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("ACL-only fallback missing %q: %s", required, query)
		}
	}
}

func TestContentSessionQueryProjectsDispositionAndActualAction(t *testing.T) {
	query := addContentSessionDispositionProjection(buildContentSessionListQueryScopedWithAlertOnly(true, "customer", true))
	for _, required := range []string{"disposition_status", "action_rank"} {
		if !strings.Contains(query, required) {
			t.Fatalf("query missing %s projection: %s", required, query)
		}
	}
}

func TestListSessionsCollapsesRequestSnapshots(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}

	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}

	suffix := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant_content_%d", suffix)
	userID := fmt.Sprintf("user_content_%d", suffix)
	projectID := fmt.Sprintf("project_content_%d", suffix)
	keyID := fmt.Sprintf("key_content_%d", suffix)
	keyName := "Claude Code 安全测试"
	keyPrefix := "na_test1"
	requestA := fmt.Sprintf("req_content_a_%d", suffix)
	requestB := fmt.Sprintf("req_content_b_%d", suffix)
	ruleSetID := fmt.Sprintf("ruleset_content_%d", suffix)
	ruleID := fmt.Sprintf("rule_content_%d", suffix)
	summaryRuleID := "code_config_file"
	sessionA := fmt.Sprintf("session_content_a_%d", suffix)
	sessionB := fmt.Sprintf("session_content_b_%d", suffix)
	start := time.Date(2026, 5, 10, 5, 37, 0, 0, time.UTC)

	// db.Close() 放 t.Cleanup 末尾：defer 会先于 t.Cleanup 执行，先关池会让 DELETE 静默失败。
	t.Cleanup(func() {
		type cleanupStmt struct {
			sql string
			arg string
		}
		for _, stmt := range []cleanupStmt{
			{"DELETE FROM content_logs WHERE tenant_id = $1", tenantID},
			{"DELETE FROM security_events WHERE tenant_id = $1", tenantID},
			{"DELETE FROM request_logs WHERE tenant_id = $1", tenantID},
			{"DELETE FROM internal_keys WHERE tenant_id = $1", tenantID},
			{"DELETE FROM rules WHERE rule_set_id = $1", ruleSetID},
			{"DELETE FROM rule_sets WHERE id = $1", ruleSetID},
			{"DELETE FROM projects WHERE tenant_id = $1", tenantID},
			{"DELETE FROM users WHERE tenant_id = $1", tenantID},
			{"DELETE FROM tenants WHERE id = $1", tenantID},
		} {
			if _, err := db.Exec(ctx, stmt.sql, stmt.arg); err != nil {
				t.Logf("cleanup %s (%q): %v", stmt.arg, stmt.sql, err)
			}
		}
		db.Close()
	})

	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`, tenantID, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $3, 'developer', 'active')`, userID, tenantID, userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1, $2, $3, $4, 'active')`, projectID, tenantID, projectID, userID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, name, status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'active')
	`, keyID, tenantID, projectID, userID, strings.Repeat("a", 64), keyPrefix, keyName); err != nil {
		t.Fatalf("insert internal key: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO rule_sets (id, tenant_id, name, version, source_type, published, created_by) VALUES ($1, $2, '测试规则集', '1.0', 'test', true, $3)`, ruleSetID, tenantID, userID); err != nil {
		t.Fatalf("insert rule set: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO rules (id, rule_set_id, rule_type, name, priority, severity, action, enabled) VALUES ($1, $2, 'prompt_injection', 'Prompt 注入检测基线', 100, 'high', 'audit', true)`, ruleID, ruleSetID); err != nil {
		t.Fatalf("insert rule: %v", err)
	}
	insertRequest := func(id string, inputTokens, outputTokens int, createdAt time.Time) {
		t.Helper()
		_, err := db.Exec(ctx, `
			INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, client_id, session_id, endpoint_type, request_status, input_tokens, output_tokens, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, NULL, 'anthropic_messages', 'success', $7, $8, $9)
		`, id, id, tenantID, projectID, userID, keyID, inputTokens, outputTokens, createdAt)
		if err != nil {
			t.Fatalf("insert request %s: %v", id, err)
		}
	}
	insertContent := func(id, requestID, sessionID, role, content string, tokens int, createdAt time.Time) {
		t.Helper()
		_, err := db.Exec(ctx, `
			INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`, id, requestID, tenantID, userID, sessionID, role, content, tokens, createdAt)
		if err != nil {
			t.Fatalf("insert content %s: %v", id, err)
		}
	}

	insertRequest(requestA, 1000, 50, start)
	insertContent("cl_a_system_"+fmt.Sprint(suffix), requestA, sessionA, "system", "You are Claude Code", 0, start)
	insertContent("cl_a_user_"+fmt.Sprint(suffix), requestA, sessionA, "user", "不是，我看了，是你这边没有能连wifi", 20, start.Add(time.Second))
	insertContent("cl_a_assistant_"+fmt.Sprint(suffix), requestA, sessionA, "assistant", "我来查系统日志", 30, start.Add(2*time.Second))

	insertRequest(requestB, 2000, 110, start.Add(4*time.Minute))
	insertContent("cl_b_system_"+fmt.Sprint(suffix), requestB, sessionB, "system", "You are Claude Code", 0, start.Add(4*time.Minute))
	insertContent("cl_b_user_"+fmt.Sprint(suffix), requestB, sessionB, "user", "不是，我看了，是你这边没有能连wifi", 20, start.Add(4*time.Minute+time.Second))
	insertContent("cl_b_assistant_"+fmt.Sprint(suffix), requestB, sessionB, "assistant", "我来查系统日志", 30, start.Add(4*time.Minute+2*time.Second))
	insertContent("cl_b_user2_"+fmt.Sprint(suffix), requestB, sessionB, "user", "这个时间段是我处理的时间段，你再往前倒腾看看", 25, start.Add(4*time.Minute+3*time.Second))
	insertContent("cl_b_assistant2_"+fmt.Sprint(suffix), requestB, sessionB, "assistant", "我再往前查", 35, start.Add(4*time.Minute+4*time.Second))
	if _, err := db.Exec(ctx, `
		INSERT INTO security_events (id, request_id, tenant_id, project_id, user_id, event_type, severity, rule_id, action_taken, matched_summary, created_at)
		VALUES ($1, $2, $3, $4, $5, 'security_check', 'high', $6, 'security_audit_only', '{"category":"prompt_injection"}'::jsonb, $7)
	`, "evt_content_"+fmt.Sprint(suffix), requestB, tenantID, projectID, userID, ruleID, start.Add(4*time.Minute+5*time.Second)); err != nil {
		t.Fatalf("insert security event: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO security_events (id, request_id, tenant_id, project_id, user_id, event_type, severity, rule_id, action_taken, matched_summary, created_at)
		VALUES ($1, $2, $3, $4, $5, 'security_check', 'medium', NULL, 'security_audit_only', $6::jsonb, $7)
	`, "evt_content_summary_"+fmt.Sprint(suffix), requestB, tenantID, projectID, userID,
		fmt.Sprintf(`{"category":"config_file","findings":[{"type":"code_config","rule_id":"%s","category":"config_file","severity":"medium"}]}`, summaryRuleID),
		start.Add(4*time.Minute+6*time.Second)); err != nil {
		t.Fatalf("insert summary security event: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO security_events (id, request_id, tenant_id, project_id, user_id, event_type, severity, rule_id, action_taken, matched_summary, created_at)
		VALUES ($1, $2, $3, $4, $5, 'semantic_telemetry', 'medium', NULL, 'security_audit_only', $6::jsonb, $7)
	`, "evt_content_observation_"+fmt.Sprint(suffix), requestB, tenantID, projectID, userID,
		`{"category":"semantic_jailbreak","findings":[{"type":"semantic_attack","category":"semantic_jailbreak","severity":"medium","counts_as_security_finding":false}]}`,
		start.Add(4*time.Minute+7*time.Second)); err != nil {
		t.Fatalf("insert observation event: %v", err)
	}

	repo := NewContentLogRepository(db)
	sessions, total, err := repo.ListSessions(ctx, tenantID, start.Add(-time.Minute), start.Add(10*time.Minute), 10, 0)
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}

	if total != 1 {
		t.Fatalf("expected one conversation, got total=%d sessions=%v", total, sessions)
	}
	if len(sessions) != 1 {
		t.Fatalf("expected one listed conversation, got %d", len(sessions))
	}
	if sessions[0]["session_id"] != sessionB {
		t.Fatalf("expected latest request snapshot %s, got %v", sessionB, sessions[0]["session_id"])
	}
	if sessions[0]["turn_count"] != 2 {
		t.Fatalf("expected latest snapshot to show 2 user turns, got %v", sessions[0]["turn_count"])
	}
	if sessions[0]["message_count"] != 5 {
		t.Fatalf("expected latest snapshot to show 5 raw messages, got %v", sessions[0]["message_count"])
	}
	if sessions[0]["total_tokens"] != 3160 {
		t.Fatalf("expected aggregated request token usage to include input and output tokens, got %v", sessions[0]["total_tokens"])
	}
	if sessions[0]["security_event_count"] != 2 {
		t.Fatalf("expected security event count, got %v", sessions[0]["security_event_count"])
	}
	if sessions[0]["actionable_alert_count"] != 0 {
		t.Fatalf("expected retained events without alert groups to stay non-actionable, got %v", sessions[0]["actionable_alert_count"])
	}
	if sessions[0]["matched_rule_count"] != 2 {
		t.Fatalf("expected matched rule count, got %v", sessions[0]["matched_rule_count"])
	}
	if sessions[0]["highest_severity"] != "high" {
		t.Fatalf("expected high severity, got %v", sessions[0]["highest_severity"])
	}
	if sessions[0]["username"] != userID || sessions[0]["client_name"] != keyName || sessions[0]["credential_type"] != "api_key" {
		t.Fatalf("expected user and API key identity, got username=%v client_name=%v", sessions[0]["username"], sessions[0]["client_name"])
	}
	fastSessions, _, err := repo.ListSessionsFiltered(ctx, ContentSessionListFilter{
		TenantID:  tenantID,
		StartTime: start.Add(-time.Minute),
		EndTime:   start.Add(10 * time.Minute),
		Limit:     10,
		SkipTotal: true,
	})
	if err != nil {
		t.Fatalf("list sessions through fast path: %v", err)
	}
	if len(fastSessions) != 1 {
		t.Fatalf("expected one fast-path session, got %d", len(fastSessions))
	}
	if fastSessions[0]["username"] != userID || fastSessions[0]["client_name"] != keyName || fastSessions[0]["credential_type"] != "api_key" {
		t.Fatalf("expected fast-path user and API key identity, got username=%v client_name=%v",
			fastSessions[0]["username"], fastSessions[0]["client_name"])
	}
	categories, ok := sessions[0]["risk_categories"].([]string)
	if !ok || !containsString(categories, "prompt_injection") || !containsString(categories, "config_file") {
		t.Fatalf("expected prompt injection and config file risk categories, got %#v", sessions[0]["risk_categories"])
	}

	events, err := NewSecurityEventRepository(db).ListByContentSession(ctx, tenantID, sessionB)
	if err != nil {
		t.Fatalf("list session security events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected two session security events, got %d", len(events))
	}
	if events[0].MatchedSummary == nil || events[1].MatchedSummary == nil {
		t.Fatalf("expected matched summary to be loaded, got %#v", events)
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestBuildContentSessionListQueryPagesBeforeExpensiveAggregates(t *testing.T) {
	query := buildContentSessionListQuery(true)

	riskPos := strings.Index(query, "risk_request_keys AS")
	pagePos := strings.Index(query, "page AS")
	contentPos := strings.Index(query, "page_content AS")
	if riskPos < 0 {
		t.Fatalf("session list query should start from deduplicated risk request keys, got %s", query)
	}
	if strings.Contains(query, "session_request_stats AS") || strings.Contains(query, "WHERE has_risk") {
		t.Fatalf("session list query must not aggregate all content before checking risk, got %s", query)
	}
	if !strings.Contains(query, "JOIN LATERAL") || !strings.Contains(query, "LIMIT 1") {
		t.Fatalf("session list query should resolve one candidate session row per risky request, got %s", query)
	}
	if pagePos < riskPos || contentPos < pagePos {
		t.Fatalf("session list query should page candidates before content enrichment, got %s", query)
	}
	if !strings.Contains(query, "page_group_totals AS") || !strings.Contains(query, "page_security AS") {
		t.Fatalf("session list query should enrich only paged sessions, got %s", query)
	}
}

func TestBuildContentSessionListQueryEnrichesAPIKeyIdentityAfterPaging(t *testing.T) {
	for _, skipTotal := range []bool{false, true} {
		query := buildContentSessionListQuery(skipTotal)
		pagePos := strings.Index(query, "page AS")
		keyJoinPos := strings.LastIndex(query, "JOIN internal_keys")
		if pagePos < 0 || keyJoinPos < pagePos {
			t.Fatalf("identity lookup must happen after paging, skipTotal=%v", skipTotal)
		}
		for _, field := range []string{"username", "client_name"} {
			if !strings.Contains(query, field) {
				t.Fatalf("session query missing %s identity projection, skipTotal=%v", field, skipTotal)
			}
		}
	}
}

func TestBuildContentSessionListQueryExcludesObservationOnlyEvents(t *testing.T) {
	for _, skipTotal := range []bool{false, true} {
		query := buildContentSessionListQuery(skipTotal)
		if !strings.Contains(query, "counts_as_security_finding") {
			t.Fatalf("session risk query must exclude observation-only findings, skipTotal=%v", skipTotal)
		}
	}
}

func TestBuildContentSessionListQuerySkipsTotalCountWhenRequested(t *testing.T) {
	query := buildContentSessionListQuery(true)

	if strings.Contains(query, "SELECT COUNT(*) FROM ranked_sessions WHERE row_num = 1") {
		t.Fatalf("skip-total session query should not count all ranked sessions, got %s", query)
	}
	if !strings.Contains(query, "0::bigint as total_count") {
		t.Fatalf("skip-total session query should return a zero total marker, got %s", query)
	}
}

func TestAlertOnlyExistingDatasetFitsRequestBudget(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	tenantID := os.Getenv("CONTENT_LOGS_TEST_EXISTING_TENANT")
	if databaseURL == "" || tenantID == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL and CONTENT_LOGS_TEST_EXISTING_TENANT are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	defer db.Close()

	repo := NewContentLogRepository(db)
	sessions, total, err := repo.ListSessionsFiltered(ctx, ContentSessionListFilter{
		TenantID: tenantID, StartTime: time.Now().AddDate(0, 0, -90), EndTime: time.Now(),
		Limit: 21, AlertOnly: true,
	})
	if err != nil {
		t.Fatalf("list actionable alert sessions within request budget: %v", err)
	}
	t.Logf("actionable alert sessions returned=%d total_marker=%d", len(sessions), total)
	if len(sessions) == 0 {
		t.Fatal("expected actionable alert first page from existing dataset")
	}
}

func TestListSessionsExistingDatasetFitsRequestBudget(t *testing.T) {
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	tenantID := os.Getenv("CONTENT_LOGS_TEST_EXISTING_TENANT")
	if databaseURL == "" || tenantID == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL and CONTENT_LOGS_TEST_EXISTING_TENANT are required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	defer db.Close()

	repo := NewContentLogRepository(db)
	sessions, total, err := repo.ListSessionsFiltered(ctx, ContentSessionListFilter{
		TenantID: tenantID, StartTime: time.Now().AddDate(0, 0, -7), EndTime: time.Now(),
		Limit: 50, SkipTotal: true,
	})
	if err != nil {
		t.Fatalf("list existing dataset sessions within request budget: %v", err)
	}
	t.Logf("content risk sessions returned=%d total_marker=%d", len(sessions), total)
	if total > 0 && len(sessions) == 0 {
		t.Fatalf("expected first page when total=%d", total)
	}
}
