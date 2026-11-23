package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setupAuditStatsRegressionFixture(t *testing.T) (*pgxpool.Pool, context.Context, string, string, string) {
	t.Helper()

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
	tenantID := fmt.Sprintf("tenant_audit_stats_%d", suffix)
	userID := fmt.Sprintf("user_audit_stats_%d", suffix)
	projectID := fmt.Sprintf("project_audit_stats_%d", suffix)

	t.Cleanup(func() {
		// 删除顺序按外键依赖：引用 tenants 的子表全部先删，漏一张都会让
		// DELETE FROM tenants 因 FK 失败、测试租户残留生产库。
		cleanups := []string{
			"DELETE FROM content_logs WHERE tenant_id = $1",
			"DELETE FROM security_events WHERE tenant_id = $1",
			"DELETE FROM request_logs WHERE tenant_id = $1",
			"DELETE FROM quota_policies WHERE tenant_id = $1",
			"DELETE FROM usage_rollup_hourly WHERE tenant_id = $1",
			"DELETE FROM access_rollup_hourly WHERE tenant_id = $1",
			"DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1)",
			"DELETE FROM providers WHERE tenant_id = $1",
			"DELETE FROM projects WHERE tenant_id = $1",
			"DELETE FROM users WHERE tenant_id = $1",
			"DELETE FROM tenants WHERE id = $1",
		}
		for _, stmt := range cleanups {
			if _, err := db.Exec(ctx, stmt, tenantID); err != nil {
				t.Logf("fixture cleanup %s (%q): %v", tenantID, stmt, err)
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

	return db, ctx, tenantID, userID, projectID
}

func TestRequestLogListHandlesNullOptionalFields(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	requestID := fmt.Sprintf("req_audit_null_%d", time.Now().UnixNano())

	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, created_at)
		VALUES ($1, $2, $3, $4, $5, 'anthropic_messages', 'success', $6)
	`, requestID, requestID, tenantID, projectID, userID, time.Now().UTC())
	if err != nil {
		t.Fatalf("insert request log: %v", err)
	}

	logs, total, err := NewRequestLogRepository(db).List(ctx, tenantID, 10, 0)
	if err != nil {
		t.Fatalf("list request logs with null optional fields: %v", err)
	}
	if total != 1 || len(logs) != 1 {
		t.Fatalf("expected one request log, got total=%d len=%d", total, len(logs))
	}
	if logs[0].StatusCode != 0 || logs[0].LatencyMs != 0 || logs[0].ClientID != "" {
		t.Fatalf("expected null optional fields to be normalized, got %+v", logs[0])
	}
}

func TestRequestLogListHandlesForwardProxyWithoutProject(t *testing.T) {
	db, ctx, tenantID, _, _ := setupAuditStatsRegressionFixture(t)
	requestID := fmt.Sprintf("req_forward_audit_null_project_%d", time.Now().UnixNano())

	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, endpoint_type, request_status,
			proxy_mode, proxy_target_host, proxy_target_path, proxy_method, created_at
		)
		VALUES ($1, $2, $3, 'proxy', 'success', 'forward', 'www.baidu.com', '/', 'GET', $4)
	`, requestID, requestID, tenantID, time.Now().UTC())
	if err != nil {
		t.Fatalf("insert forward proxy request log: %v", err)
	}

	logs, total, err := NewRequestLogRepository(db).List(ctx, tenantID, 10, 0)
	if err != nil {
		t.Fatalf("list request logs with forward proxy null project: %v", err)
	}
	if total != 1 || len(logs) != 1 {
		t.Fatalf("expected one request log, got total=%d len=%d", total, len(logs))
	}
	if logs[0].ProjectID != "" {
		t.Fatalf("expected null project_id to be normalized, got %+v", logs[0])
	}
}

func TestRequestLogListReturnsCustomerReadableModelName(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	providerID := fmt.Sprintf("prov_audit_model_%d", time.Now().UnixNano())
	modelID := fmt.Sprintf("model_audit_model_%d", time.Now().UnixNano())
	requestID := fmt.Sprintf("req_audit_model_%d", time.Now().UnixNano())

	if _, err := db.Exec(ctx, `
		INSERT INTO providers (id, tenant_id, name, provider_type, status)
		VALUES ($1, $2, '测试供应商', 'openai', 'active')
	`, providerID, tenantID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO models (id, provider_id, model_name, model_label, status)
		VALUES ($1, $2, 'qwen3.6-plus', 'qwen3.6-plus', 'active')
	`, modelID, providerID); err != nil {
		t.Fatalf("insert model: %v", err)
	}
	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, provider_id, model_id, endpoint_type, request_status, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'anthropic_messages', 'success', $8)
	`, requestID, requestID, tenantID, projectID, userID, providerID, modelID, time.Now().UTC())
	if err != nil {
		t.Fatalf("insert request log: %v", err)
	}

	logs, _, err := NewRequestLogRepository(db).List(ctx, tenantID, 10, 0)
	if err != nil {
		t.Fatalf("list request logs: %v", err)
	}
	if len(logs) != 1 || logs[0].ModelName != "qwen3.6-plus" {
		t.Fatalf("expected customer-readable model name, got %+v", logs)
	}
}

func TestAgentStatsInfersClaudeCodeFromContentLogs(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	requestID := fmt.Sprintf("req_agent_infer_%d", time.Now().UnixNano())
	now := time.Now().UTC()

	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at)
		VALUES ($1, $2, $3, $4, $5, 'anthropic_messages', 'success', 100, 20, 0.012, $6)
	`, requestID, requestID, tenantID, projectID, userID, now)
	if err != nil {
		t.Fatalf("insert request log: %v", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO content_logs (id, request_id, tenant_id, user_id, session_id, role, content, tokens, created_at)
		VALUES ($1, $2, $3, $4, $5, 'system', 'You are Claude Code, Anthropic''s official CLI for Claude.', 0, $6)
	`, "cl_agent_infer_"+fmt.Sprint(time.Now().UnixNano()), requestID, tenantID, userID, "", now)
	if err != nil {
		t.Fatalf("insert content log: %v", err)
	}

	repo := NewStatsRepository(db)
	stats, err := repo.GetAgentStats(ctx, tenantID)
	if err != nil {
		t.Fatalf("get agent stats: %v", err)
	}
	if len(stats) != 1 || stats[0].AgentType != "claude-code" || stats[0].RequestCount != 1 || stats[0].SessionCount != 1 {
		t.Fatalf("expected inferred claude-code stats, got %+v", stats)
	}
	if stats[0].ContentRequestCount != 1 || stats[0].ToolBackedRequestCount != 0 {
		t.Fatalf("expected claude-code content drill-down counts to match retained content only, got %+v", stats[0])
	}

	distribution, err := repo.GetAgentTypeDistribution(ctx, tenantID)
	if err != nil {
		t.Fatalf("get agent distribution: %v", err)
	}
	if len(distribution) != 1 || distribution[0].AgentType != "claude-code" || distribution[0].Count != 1 {
		t.Fatalf("expected inferred claude-code distribution, got %+v", distribution)
	}

	detail, err := repo.GetUserAgentDetail(ctx, tenantID, userID)
	if err != nil {
		t.Fatalf("get user agent detail: %v", err)
	}
	if len(detail) != 1 || detail[0].AgentType != "claude-code" || detail[0].TotalTokens != 120 {
		t.Fatalf("expected inferred user detail token usage, got %+v", detail)
	}

	sessions, total, err := repo.ListAgentSessionsByType(ctx, tenantID, "claude-code", "", 10, 0)
	if err != nil {
		t.Fatalf("list agent sessions: %v", err)
	}
	if total != 1 || len(sessions) != 1 || sessions[0].SessionID != requestID {
		t.Fatalf("expected one inferred agent session, total=%d sessions=%+v", total, sessions)
	}
}

func TestAgentStatsExposesDrilldownCountHints(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	registerToolCallLogCleanup(t, db, ctx, tenantID)
	now := time.Now().UTC()
	inferredRequestID := fmt.Sprintf("req_agent_tool_hint_%d", now.UnixNano())
	explicitRequestID := fmt.Sprintf("req_agent_tool_hint_explicit_%d", now.UnixNano())

	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, created_at)
		VALUES ($1, $1, $2, $3, $4, 'anthropic_messages', 'success', $5)
	`, inferredRequestID, tenantID, projectID, userID, now)
	if err != nil {
		t.Fatalf("insert inferred tool-backed request log: %v", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status,
			agent_type, proxy_mode, proxy_access_type_resolved, proxy_retention_level,
			proxy_content_retained, proxy_target_host, proxy_target_path, created_at
		) VALUES ($1, $1, $2, $3, $4, 'proxy', 'success', 'workbuddy', 'forward', 'ai_ide', 'content', true, 'copilot.tencent.com', '/v2/chat/completions', $5)
	`, explicitRequestID, tenantID, projectID, userID, now)
	if err != nil {
		t.Fatalf("insert explicit tool-backed request log: %v", err)
	}
	insertToolCallFixture(t, db, ctx, tenantID, inferredRequestID, "sess-tool-hint", userID, "read_file", "medium", "audit", "", "", now)
	insertToolCallFixture(t, db, ctx, tenantID, explicitRequestID, "sess-tool-hint-explicit", userID, "read_file", "medium", "audit", "", "", now)

	stats, err := NewStatsRepository(db).GetAgentStats(ctx, tenantID)
	if err != nil {
		t.Fatalf("get agent stats: %v", err)
	}
	byAgent := map[string]AgentStats{}
	for _, stat := range stats {
		byAgent[stat.AgentType] = stat
	}
	if byAgent["agent-tool-call"].RequestCount != 1 {
		t.Fatalf("expected inferred agent-tool-call stats, got %+v", stats)
	}
	if byAgent["agent-tool-call"].ContentRequestCount != 0 || byAgent["agent-tool-call"].ToolBackedRequestCount != 1 {
		t.Fatalf("expected inferred tool-backed count hint without content drill-down, got %+v", byAgent["agent-tool-call"])
	}
	if byAgent["workbuddy"].RequestCount != 1 || byAgent["workbuddy"].ContentRequestCount != 1 || byAgent["workbuddy"].ToolBackedRequestCount != 1 {
		t.Fatalf("expected explicit agent tool-backed and content count hints, got %+v", byAgent["workbuddy"])
	}
}

func TestAgentStatsScopedBetweenHonorsTimeWindow(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	now := time.Now().UTC()
	oldID := fmt.Sprintf("req_agent_old_%d", now.UnixNano())
	currentID := fmt.Sprintf("req_agent_current_%d", now.UnixNano())

	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status,
			agent_type, proxy_mode, proxy_access_type_resolved, proxy_retention_level,
			proxy_content_retained, proxy_target_host, proxy_target_path, created_at
		) VALUES
			($1, $1, $2, $3, $4, 'proxy', 'success', 'workbuddy', 'forward', 'ai_ide', 'content', true, 'copilot.tencent.com', '/v2/chat/completions', $5),
			($6, $6, $2, $3, $4, 'proxy', 'success', 'workbuddy', 'forward', 'ai_ide', 'content', true, 'copilot.tencent.com', '/v2/chat/completions', $7)
	`, oldID, tenantID, projectID, userID, now.Add(-10*24*time.Hour), currentID, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("insert workbuddy request logs: %v", err)
	}

	repo := NewStatsRepository(db)
	allStats, err := repo.GetAgentStats(ctx, tenantID)
	if err != nil {
		t.Fatalf("get all agent stats: %v", err)
	}
	if len(allStats) != 1 || allStats[0].RequestCount != 2 {
		t.Fatalf("expected all-time stats to include both requests, got %+v", allStats)
	}

	rangedStats, err := repo.GetAgentStatsScopedBetween(ctx, UsageScope{TenantID: tenantID, FullTenant: true}, now.Add(-7*24*time.Hour), now)
	if err != nil {
		t.Fatalf("get ranged agent stats: %v", err)
	}
	if len(rangedStats) != 1 || rangedStats[0].AgentType != "workbuddy" || rangedStats[0].RequestCount != 1 {
		t.Fatalf("expected ranged stats to include one current workbuddy request, got %+v", rangedStats)
	}
	if rangedStats[0].ContentRequestCount != 1 || rangedStats[0].ToolBackedRequestCount != 0 {
		t.Fatalf("expected ranged workbuddy content drill-down count to match request count, got %+v", rangedStats[0])
	}
}

func TestAgentStatsExcludesForwardProxySummaryAgentHeartbeats(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	now := time.Now().UTC()
	heartbeatID := fmt.Sprintf("req_agent_summary_heartbeat_%d", time.Now().UnixNano())
	contentID := fmt.Sprintf("req_agent_content_%d", time.Now().UnixNano())

	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status,
			agent_type, proxy_mode, proxy_access_type_resolved, proxy_retention_level,
			proxy_content_retained, proxy_target_host, proxy_target_path, created_at
		) VALUES
			($1, $1, $2, $3, $4, 'proxy', 'success', 'workbuddy', 'forward', 'ai_ide', 'summary', false, 'copilot.tencent.com', '/v2/activity/growth/buddy/info', $5),
			($6, $6, $2, $3, $4, 'proxy', 'success', 'workbuddy', 'forward', 'ai_ide', 'content', true, 'copilot.tencent.com', '/v2/chat/completions', $5)
	`, heartbeatID, tenantID, projectID, userID, now, contentID)
	if err != nil {
		t.Fatalf("insert workbuddy request logs: %v", err)
	}

	repo := NewStatsRepository(db)
	stats, err := repo.GetAgentStats(ctx, tenantID)
	if err != nil {
		t.Fatalf("get agent stats: %v", err)
	}
	if len(stats) != 1 || stats[0].AgentType != "workbuddy" || stats[0].RequestCount != 1 || stats[0].SessionCount != 1 {
		t.Fatalf("expected only content-retained workbuddy request to count, got %+v", stats)
	}
	if stats[0].ContentRequestCount != 1 || stats[0].ToolBackedRequestCount != 0 {
		t.Fatalf("expected workbuddy content drill-down count to match request count, got %+v", stats[0])
	}

	distribution, err := repo.GetAgentTypeDistribution(ctx, tenantID)
	if err != nil {
		t.Fatalf("get agent distribution: %v", err)
	}
	if len(distribution) != 1 || distribution[0].AgentType != "workbuddy" || distribution[0].Count != 1 {
		t.Fatalf("expected only content-retained workbuddy distribution, got %+v", distribution)
	}

	sessions, total, err := repo.ListAgentSessionsByType(ctx, tenantID, "workbuddy", "", 10, 0)
	if err != nil {
		t.Fatalf("list agent sessions: %v", err)
	}
	if total != 1 || len(sessions) != 1 || sessions[0].SessionID != contentID {
		t.Fatalf("expected only content-retained workbuddy session, total=%d sessions=%+v", total, sessions)
	}
}

func TestUsageSummaryFallsBackToRequestLogs(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	requestID := fmt.Sprintf("req_usage_%d", time.Now().UnixNano())
	now := time.Now().UTC()

	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at)
		VALUES ($1, $2, $3, $4, $5, 'anthropic_messages', 'success', 100, 20, 0.012, $6)
	`, requestID, requestID, tenantID, projectID, userID, now)
	if err != nil {
		t.Fatalf("insert request log: %v", err)
	}

	summary, err := NewUsageDailyRepository(db).GetSummary(ctx, tenantID, now.Add(-time.Hour), now.Add(time.Hour))
	if err != nil {
		t.Fatalf("get usage summary: %v", err)
	}
	if summary.Requests != 1 || summary.InputTokens != 100 || summary.OutputTokens != 20 || summary.TotalCost != 0.012 {
		t.Fatalf("expected request log backed usage summary, got %+v", summary)
	}
}

func TestStatsRepositoryScopedRankingsExcludeOtherProjects(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	otherUserID := "user_other_stats_" + fmt.Sprint(time.Now().UnixNano())
	otherProjectID := "project_other_stats_" + fmt.Sprint(time.Now().UnixNano())
	now := time.Now().UTC()

	if _, err := db.Exec(ctx, `INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, $3, 'developer', 'active')`, otherUserID, tenantID, otherUserID); err != nil {
		t.Fatalf("insert other user: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1, $2, $3, $4, 'active')`, otherProjectID, tenantID, otherProjectID, otherUserID); err != nil {
		t.Fatalf("insert other project: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at) VALUES
			('req_scope_allowed', 'req_scope_allowed', $1, $2, $3, 'chat', 'success', 10, 5, 0.1, $4),
			('req_scope_denied', 'req_scope_denied', $1, $5, $6, 'chat', 'success', 900, 100, 9, $4)
	`, tenantID, projectID, userID, now, otherProjectID, otherUserID); err != nil {
		t.Fatalf("insert request logs: %v", err)
	}

	// 排行榜/总览读侧已迁到 usage_rollup_hourly 读模型，生产由 worker 周期刷新；
	// 夹具按同口径刷出本租户 rollup 行，否则读侧只会看到空集。
	rollupWin := RollupRefreshWindow{TenantID: tenantID, From: now.Truncate(time.Hour), To: now.Truncate(time.Hour).Add(time.Hour)}
	if err := NewRollupReadModelRepository(db).RefreshUsageHourly(ctx, rollupWin); err != nil {
		t.Fatalf("refresh usage rollup: %v", err)
	}

	scope := UsageScope{TenantID: tenantID, UserID: userID, ProjectIDs: []string{projectID}}
	repo := NewStatsRepository(db)
	users, err := repo.GetUserTokenRankingScoped(ctx, scope, 10)
	if err != nil {
		t.Fatalf("user ranking: %v", err)
	}
	if len(users) != 1 || users[0].UserID != userID || users[0].TotalTokens != 15 {
		t.Fatalf("unexpected scoped users: %+v", users)
	}

	apps, err := repo.GetAppStatsScoped(ctx, scope, 10)
	if err != nil {
		t.Fatalf("app stats: %v", err)
	}
	if len(apps) != 1 || apps[0].ProjectID != projectID {
		t.Fatalf("unexpected scoped apps: %+v", apps)
	}

	overview, err := repo.GetSystemOverviewScoped(ctx, scope)
	if err != nil {
		t.Fatalf("system overview: %v", err)
	}
	if overview.TotalRequests != 1 || overview.TotalTokens != 15 || overview.TotalCost != 0.1 {
		t.Fatalf("unexpected scoped overview: %+v", overview)
	}
}

func TestStatsRepositoryRankingsRespectTimeWindow(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	suffix := time.Now().UnixNano()
	providerID := fmt.Sprintf("prov_stats_range_%d", suffix)
	modelID := fmt.Sprintf("model_stats_range_%d", suffix)
	now := time.Now().UTC().Truncate(time.Hour)
	oldBucket := now.Add(-60 * 24 * time.Hour)
	recentBucket := now.Add(-2 * 24 * time.Hour)

	if _, err := db.Exec(ctx, `
		INSERT INTO providers (id, tenant_id, name, provider_type, status)
		VALUES ($1, $2, '时间范围供应商', 'openai', 'active')
	`, providerID, tenantID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO models (id, provider_id, model_name, model_label, status)
		VALUES ($1, $2, 'range-model', 'range-model', 'active')
	`, modelID, providerID); err != nil {
		t.Fatalf("insert model: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO usage_rollup_hourly (
			tenant_id, bucket_start, project_id, user_id, provider_id, model_id,
			request_count, success_count, ai_request_count, ai_success_count,
			input_tokens, output_tokens, total_cost
		) VALUES
			($1, $2, $3, $4, $5, $6, 90, 90, 90, 90, 900, 90, 9),
			($1, $7, $3, $4, $5, $6, 4, 4, 4, 4, 30, 3, 0.3)
	`, tenantID, oldBucket, projectID, userID, providerID, modelID, recentBucket); err != nil {
		t.Fatalf("insert ranged rollups: %v", err)
	}

	scope := UsageScope{TenantID: tenantID, FullTenant: true}
	start, end := now.Add(-7*24*time.Hour), now.Add(time.Hour)
	repo := NewStatsRepository(db)
	users, err := repo.GetUserTokenRankingScopedBetween(ctx, scope, 10, start, end)
	if err != nil {
		t.Fatalf("get ranged user stats: %v", err)
	}
	if len(users) != 1 || users[0].RequestCount != 4 || users[0].TotalTokens != 33 {
		t.Fatalf("ranged user stats included out-of-window usage: %+v", users)
	}

	models, err := repo.GetModelStatsScopedBetween(ctx, scope, 10, start, end)
	if err != nil {
		t.Fatalf("get ranged model stats: %v", err)
	}
	if len(models) != 1 || models[0].RequestCount != 4 || models[0].InputTokens != 30 || models[0].OutputTokens != 3 {
		t.Fatalf("ranged model stats included out-of-window usage: %+v", models)
	}
}

func TestCurrentStatsHideDeletedProjectsAndDeletedKeys(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	now := time.Now().UTC().Truncate(time.Hour)
	keyID := fmt.Sprintf("key_audit_stats_%d", time.Now().UnixNano())
	keyPrefix := "na_current"

	if _, err := db.Exec(ctx, `
		INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, scopes_json, status)
		VALUES ($1, $2, $3, $4, $5, $6, '[]'::jsonb, 'active')
	`, keyID, tenantID, projectID, userID, "hash_"+keyID, keyPrefix); err != nil {
		t.Fatalf("insert key: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO usage_rollup_hourly (
			tenant_id, bucket_start, project_id, user_id, client_id,
			request_count, success_count, ai_request_count, ai_success_count, input_tokens, output_tokens, total_cost
		) VALUES ($1, $2, $3, $4, $5, 7, 7, 7, 7, 70, 14, 0)
	`, tenantID, now, projectID, userID, keyID); err != nil {
		t.Fatalf("insert rollup: %v", err)
	}

	scope := UsageScope{TenantID: tenantID, FullTenant: true}
	apps, err := NewStatsRepository(db).GetAppStatsScoped(ctx, scope, 10)
	if err != nil || len(apps) != 1 || apps[0].ProjectID != projectID {
		t.Fatalf("active app stats = %+v err=%v", apps, err)
	}
	keys, err := NewUsageDailyRepository(db).GetByKey(ctx, scope, now, now.Add(time.Hour))
	if err != nil || len(keys) != 1 || keys[0].ID != keyID {
		t.Fatalf("active key stats = %+v err=%v", keys, err)
	}

	if _, err := db.Exec(ctx, `UPDATE projects SET status='deleted' WHERE id=$1`, projectID); err != nil {
		t.Fatalf("mark project deleted: %v", err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM internal_keys WHERE id=$1`, keyID); err != nil {
		t.Fatalf("delete key: %v", err)
	}

	apps, err = NewStatsRepository(db).GetAppStatsScoped(ctx, scope, 10)
	if err != nil || len(apps) != 0 {
		t.Fatalf("deleted project must disappear from current stats: %+v err=%v", apps, err)
	}
	keys, err = NewUsageDailyRepository(db).GetByKey(ctx, scope, now, now.Add(time.Hour))
	if err != nil || len(keys) != 0 {
		t.Fatalf("deleted key must disappear from current stats: %+v err=%v", keys, err)
	}
}

func seedDeletedModelUsage(t *testing.T, db *pgxpool.Pool, ctx context.Context, tenantID, projectID, userID, modelName string) (string, time.Time) {
	t.Helper()
	suffix := time.Now().UnixNano()
	providerID := fmt.Sprintf("prov_deleted_model_%d", suffix)
	modelID := fmt.Sprintf("model_deleted_model_%d", suffix)
	bucket := time.Now().UTC().Truncate(time.Hour)

	if _, err := db.Exec(ctx, `
		INSERT INTO providers (id, tenant_id, name, provider_type, status)
		VALUES ($1, $2, '历史模型供应商', 'openai', 'active')
	`, providerID, tenantID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO models (id, provider_id, model_name, model_label, status)
		VALUES ($1, $2, $3, $3, 'active')
	`, modelID, providerID, modelName); err != nil {
		t.Fatalf("insert model: %v", err)
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO usage_rollup_hourly (
			tenant_id, bucket_start, project_id, user_id, provider_id, model_id,
			request_count, success_count, ai_request_count, ai_success_count,
			input_tokens, output_tokens, total_cost
		) VALUES ($1, $2, $3, $4, $5, $6, 7, 7, 7, 7, 70, 14, 0)
	`, tenantID, bucket, projectID, userID, providerID, modelID); err != nil {
		t.Fatalf("insert model rollup: %v", err)
	}
	if _, err := db.Exec(ctx, `DELETE FROM models WHERE id=$1`, modelID); err != nil {
		t.Fatalf("delete model: %v", err)
	}

	return modelID, bucket
}

func TestModelStatsKeepsCustomerReadableNameAfterModelDeletion(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	modelName := "customer-readable-history-model"
	modelID, _ := seedDeletedModelUsage(t, db, ctx, tenantID, projectID, userID, modelName)

	stats, err := NewStatsRepository(db).GetModelStatsScoped(ctx, UsageScope{TenantID: tenantID, FullTenant: true}, 10)
	if err != nil {
		t.Fatalf("get model stats: %v", err)
	}
	if len(stats) != 1 || stats[0].ModelName != modelName {
		t.Fatalf("deleted model must keep customer-readable name, internal_id=%q stats=%+v", modelID, stats)
	}
}

func TestUsageByModelKeepsCustomerReadableNameAfterModelDeletion(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	modelName := "customer-readable-usage-model"
	modelID, bucket := seedDeletedModelUsage(t, db, ctx, tenantID, projectID, userID, modelName)

	items, err := NewUsageDailyRepository(db).GetByModel(
		ctx,
		UsageScope{TenantID: tenantID, FullTenant: true},
		bucket,
		bucket.Add(time.Hour),
	)
	if err != nil {
		t.Fatalf("get usage by model: %v", err)
	}
	if len(items) != 1 || items[0].Name != modelName {
		t.Fatalf("deleted model usage must keep customer-readable name, internal_id=%q items=%+v", modelID, items)
	}
}

func TestUsageSummaryUsesExclusiveEndDate(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	start := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC)
	rows := []struct {
		id   string
		when time.Time
	}{
		{"req_in_range", start.Add(12 * time.Hour)},
		{"req_out_range", end},
	}

	for _, row := range rows {
		_, err := db.Exec(ctx, `
			INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at)
			VALUES ($1, $1, $2, $3, $4, 'chat', 'success', 100, 20, 0.012, $5)
		`, row.id, tenantID, projectID, userID, row.when)
		if err != nil {
			t.Fatalf("insert request log: %v", err)
		}
	}

	summary, err := NewUsageDailyRepository(db).GetSummary(ctx, tenantID, start, end)
	if err != nil {
		t.Fatalf("get summary: %v", err)
	}
	if summary.Requests != 1 {
		t.Fatalf("requests = %d, want 1", summary.Requests)
	}
}

func TestCostRecommendationsDetectBudgetRiskAndUnpricedModels(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	now := time.Date(2026, 5, 20, 10, 0, 0, 0, time.UTC)

	_, err := db.Exec(ctx, `
		INSERT INTO quota_policies (id, tenant_id, project_id, scope_type, monthly_budget_limit, status)
		VALUES ($1, $2, $3, 'project', 10, 'active')
	`, "qpol_rec_"+fmt.Sprint(time.Now().UnixNano()), tenantID, projectID)
	if err != nil {
		t.Fatalf("insert quota policy: %v", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at)
		VALUES
		('req_rec_cost', 'req_rec_cost', $1, $2, $3, 'chat', 'success', 1000, 100, 9, $4),
		('req_rec_unpriced', 'req_rec_unpriced', $1, $2, $3, 'chat', 'success', 2000, 100, NULL, $4)
	`, tenantID, projectID, userID, now)
	if err != nil {
		t.Fatalf("insert request logs: %v", err)
	}

	scope := UsageScope{TenantID: tenantID, FullTenant: true}
	recs, err := NewUsageDailyRepository(db).GetCostRecommendations(ctx, scope, now.AddDate(0, 0, -1), now.AddDate(0, 0, 1))
	if err != nil {
		t.Fatalf("get recommendations: %v", err)
	}
	var hasBudget, hasUnpriced bool
	for _, rec := range recs {
		if rec.ID == "budget_near_limit" {
			hasBudget = true
		}
		if rec.ID == "unpriced_model_usage" {
			hasUnpriced = true
		}
	}
	if !hasBudget || !hasUnpriced {
		t.Fatalf("expected budget and unpriced recommendations, got %+v", recs)
	}
}

func TestSystemOverviewIncludesTokenTotalsAndSecurityEvents(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	requestID := fmt.Sprintf("req_overview_%d", time.Now().UnixNano())
	eventID := fmt.Sprintf("evt_overview_%d", time.Now().UnixNano())
	now := time.Now().UTC()

	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at)
		VALUES ($1, $2, $3, $4, $5, 'anthropic_messages', 'success', 100, 20, 0.012, $6)
	`, requestID, requestID, tenantID, projectID, userID, now)
	if err != nil {
		t.Fatalf("insert request log: %v", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO security_events (id, request_id, tenant_id, project_id, user_id, event_type, severity, action_taken, matched_summary, created_at)
		VALUES ($1, $2, $3, $4, $5, 'security_check', 'medium', 'security_audit_only', '{}'::jsonb, $6)
	`, eventID, requestID, tenantID, projectID, userID, now)
	if err != nil {
		t.Fatalf("insert security event: %v", err)
	}

	// 总览的请求/token/费用已迁到 usage_rollup_hourly 读模型(安全事件仍直读原表)，
	// 夹具按生产 worker 同口径刷出本租户 rollup 行。
	rollupWin := RollupRefreshWindow{TenantID: tenantID, From: now.Truncate(time.Hour), To: now.Truncate(time.Hour).Add(time.Hour)}
	if err := NewRollupReadModelRepository(db).RefreshUsageHourly(ctx, rollupWin); err != nil {
		t.Fatalf("refresh usage rollup: %v", err)
	}

	overview, err := NewStatsRepository(db).GetSystemOverview(ctx, tenantID)
	if err != nil {
		t.Fatalf("get system overview: %v", err)
	}
	if overview.TotalRequests != 1 || overview.TotalTokens != 120 || overview.TodayTokens != 120 || overview.SecurityEvents != 1 {
		t.Fatalf("expected overview to include request-log backed totals and security events, got %+v", overview)
	}
}

func TestSecurityEventListHandlesNullOptionalFields(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	requestID := fmt.Sprintf("req_security_null_%d", time.Now().UnixNano())
	eventID := fmt.Sprintf("evt_security_null_%d", time.Now().UnixNano())
	now := time.Now().UTC()

	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, created_at)
		VALUES ($1, $2, $3, $4, $5, 'anthropic_messages', 'success', $6)
	`, requestID, requestID, tenantID, projectID, userID, now)
	if err != nil {
		t.Fatalf("insert request log: %v", err)
	}
	_, err = db.Exec(ctx, `
		INSERT INTO security_events (id, request_id, tenant_id, project_id, user_id, event_type, severity, action_taken, matched_summary, created_at)
		VALUES ($1, $2, $3, $4, $5, 'content_policy', 'low', 'allow', '{"summary":"audit only"}'::jsonb, $6)
	`, eventID, requestID, tenantID, projectID, userID, now)
	if err != nil {
		t.Fatalf("insert security event: %v", err)
	}

	repo := NewSecurityEventRepository(db)
	events, total, err := repo.List(ctx, tenantID, 10, 0)
	if err != nil {
		t.Fatalf("list security events with null optional fields: %v", err)
	}
	if total != 1 || len(events) != 1 {
		t.Fatalf("expected one security event, got total=%d len=%d", total, len(events))
	}
	if events[0].RuleID != "" || events[0].EvidenceRef != "" {
		t.Fatalf("expected null optional fields to be normalized, got %+v", events[0])
	}

	byRequest, err := repo.ListByRequest(ctx, tenantID, requestID)
	if err != nil {
		t.Fatalf("list security events by request with null optional fields: %v", err)
	}
	if len(byRequest) != 1 || byRequest[0].MatchedSummary["summary"] != "audit only" {
		t.Fatalf("expected parsed matched summary, got %+v", byRequest)
	}
}

func TestSecurityEventUpsertDeduplicatesEvalFindings(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "DELETE FROM security_events WHERE tenant_id = $1", tenantID)
	})
	requestID := fmt.Sprintf("req_eval_event_%d", time.Now().UnixNano())

	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status, created_at)
		VALUES ($1, $1, $2, $3, $4, 'anthropic_messages', 'success', $5)
	`, requestID, tenantID, projectID, userID, time.Now().UTC())
	if err != nil {
		t.Fatalf("insert request log: %v", err)
	}

	repo := NewSecurityEventRepository(db)
	event := SecurityEventUpsert{
		ID:          "se_lse_test_dedupe",
		RequestID:   requestID,
		TenantID:    tenantID,
		ProjectID:   projectID,
		UserID:      userID,
		EventType:   "eval_content_safety",
		Severity:    "high",
		ActionTaken: "alert",
		MatchedSummary: map[string]interface{}{
			"source":      "llm_safety_eval",
			"risk_domain": "应拒答失败/有害能力风险",
		},
		EvidenceRef: "lse://eval-1/task-1/sample-1",
	}
	if err := repo.Upsert(ctx, event); err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	event.Severity = "critical"
	if err := repo.Upsert(ctx, event); err != nil {
		t.Fatalf("second upsert: %v", err)
	}

	events, err := repo.ListByRequest(ctx, tenantID, requestID)
	if err != nil {
		t.Fatalf("list by request: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected one deduplicated security event, got %d", len(events))
	}
	if events[0].Severity != "critical" || events[0].EventType != "eval_content_safety" || events[0].ActionTaken != "alert" {
		t.Fatalf("unexpected upserted event: %+v", events[0])
	}
	if events[0].MatchedSummary["source"] != "llm_safety_eval" {
		t.Fatalf("missing eval source summary: %#v", events[0].MatchedSummary)
	}
}

func TestUsageByModelExcludesUnattributedTraffic(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	_, bucket := seedDeletedModelUsage(t, db, ctx, tenantID, projectID, userID, "history-model")
	// A missing model ID is common for proxy/IDE/public requests, not proof of deletion.
	_, err := db.Exec(ctx, `INSERT INTO usage_rollup_hourly
 (tenant_id,bucket_start,project_id,user_id,model_id,request_count,success_count,input_tokens,total_cost)
 VALUES ($1,$2,$3,$4,'',87000,87000,2087,100)`, tenantID, bucket, projectID, userID)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []UsageScope{{TenantID: tenantID, FullTenant: true}, {TenantID: tenantID, ProjectIDs: []string{projectID}}, {TenantID: tenantID, UserID: userID}} {
		items, err := NewUsageDailyRepository(db).GetByModel(ctx, scope, bucket, bucket.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if len(items) != 1 || items[0].Name != "history-model" || items[0].Requests != 7 {
			t.Fatalf("unattributed traffic leaked into model share: %+v", items)
		}
	}
	items, err := NewUsageDailyRepository(db).GetByModel(ctx, UsageScope{TenantID: tenantID, ProjectIDs: []string{"unrelated-project"}}, bucket, bucket.Add(time.Hour))
	if err != nil || len(items) != 0 {
		t.Fatalf("project scope leaked: %+v %v", items, err)
	}
}
