package repository

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestToolCallFilterWhereBindsRequestIDAfterTenant(t *testing.T) {
	where, args, err := toolCallFilterWhere(ToolCallFilter{
		TenantID: "tenant-a", RequestID: "req-a",
	})
	if err != nil {
		t.Fatalf("filter where: %v", err)
	}
	if !strings.Contains(where, "tcl.tenant_id = $1") ||
		!strings.Contains(where, "tcl.request_id = $2") {
		t.Fatalf("where=%q", where)
	}
	if len(args) != 2 || args[0] != "tenant-a" || args[1] != "req-a" {
		t.Fatalf("args=%#v", args)
	}
}

func registerToolCallLogCleanup(t *testing.T, db *pgxpool.Pool, ctx context.Context, tenantID string) {
	t.Helper()
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "DELETE FROM agentguard_confirmations WHERE tenant_id = $1", tenantID)
		_, _ = db.Exec(ctx, "DELETE FROM tool_call_logs WHERE tenant_id = $1", tenantID)
	})
}

func insertToolCallFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, tenantID, requestID, sessionID, userID, toolName, riskLevel, mode, policyID, policyName string, createdAt time.Time) {
	t.Helper()
	_, err := db.Exec(ctx, `
		INSERT INTO tool_call_logs (
			id, request_id, session_id, tenant_id, user_id, tool_name, tool_type, risk_level,
			parameters, result, status, matched_policy_id, matched_policy_name, mode, created_at
		) VALUES (
			$1, $2, $3, $4, $5, $6, 'system', $7,
			'{}'::jsonb, '', 'success', NULLIF($8, ''), NULLIF($9, ''), NULLIF($10, ''), $11
		)
	`, fmt.Sprintf("tc_filter_%d", time.Now().UnixNano()), requestID, sessionID, tenantID, userID, toolName, riskLevel, policyID, policyName, mode, createdAt)
	if err != nil {
		t.Fatalf("insert tool call log: %v", err)
	}
}

func insertToolRequestLogFixture(t *testing.T, db *pgxpool.Pool, ctx context.Context, tenantID, requestID, userID, projectID, keyID string, createdAt time.Time) {
	t.Helper()
	insertToolRequestLogFixtureWithAgent(t, db, ctx, tenantID, requestID, userID, projectID, keyID, "", createdAt)
}

func insertToolRequestLogFixtureWithAgent(t *testing.T, db *pgxpool.Pool, ctx context.Context, tenantID, requestID, userID, projectID, keyID, agentType string, createdAt time.Time) {
	t.Helper()
	_, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, project_id, user_id, client_id,
			endpoint_type, request_status, agent_type, created_at
		) VALUES ($1, $1, $2, $3, $4, $5, 'agent-tool-call', 'success', NULLIF($6, ''), $7)
	`, requestID, tenantID, projectID, userID, keyID, agentType, createdAt)
	if err != nil {
		t.Fatalf("insert request log: %v", err)
	}
}

func TestListFilteredSupportsMultiDimensionalFilters(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	registerUsageRecordCleanup(t, db, ctx, tenantID)
	registerToolCallLogCleanup(t, db, ctx, tenantID)
	_, _, keyID, _, _, _ := seedUsageDimensions(t, db, ctx, tenantID, userID, projectID)

	now := time.Now().UTC()
	matchingReq := fmt.Sprintf("req_tool_filter_match_%d", now.UnixNano())
	allowedReq := fmt.Sprintf("req_tool_filter_allow_%d", now.UnixNano())
	insertToolRequestLogFixture(t, db, ctx, tenantID, matchingReq, userID, projectID, keyID, now.Add(-3*time.Minute))
	insertToolRequestLogFixture(t, db, ctx, tenantID, allowedReq, userID, projectID, keyID, now.Add(-2*time.Minute))
	insertToolCallFixture(t, db, ctx, tenantID, matchingReq, "sess-filter-1", userID, "bash.exec", "high", "block", "pol_block", "阻断策略", now.Add(-3*time.Minute))
	insertToolCallFixture(t, db, ctx, tenantID, allowedReq, "sess-filter-2", userID, "bash.exec", "low", "allow", "", "", now.Add(-2*time.Minute))

	otherTenantID := tenantID + "_other"
	registerToolCallLogCleanup(t, db, ctx, otherTenantID)
	insertToolCallFixture(t, db, ctx, otherTenantID, matchingReq, "sess-filter-3", userID, "bash.exec", "high", "block", "pol_block", "阻断策略", now.Add(-time.Minute))

	repo := NewToolCallLogRepository(db)
	logs, total, err := repo.ListFiltered(ctx, ToolCallFilter{
		TenantID:  tenantID,
		StartDate: now.Add(-time.Hour),
		EndDate:   now.Add(time.Hour),
		ClientID:  keyID,
		ProjectID: projectID,
		Mode:      "block",
		RiskLevel: "high",
		ToolName:  "bash.exec",
		PolicyID:  "pol_block",
		SessionID: "sess-filter-1",
		Limit:     50,
		RequestID: matchingReq,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list filtered tool calls: %v", err)
	}
	if total != 1 || len(logs) != 1 {
		t.Fatalf("expected exactly one filtered log, got total=%d len=%d", total, len(logs))
	}
	if logs[0].TenantID != tenantID || logs[0].RequestID != matchingReq {
		t.Fatalf("unexpected filtered log: %+v", logs[0])
	}
	if logs[0].MatchedPolicyID != "pol_block" || logs[0].Mode != "block" {
		t.Fatalf("policy/mode did not round trip: %+v", logs[0])
	}
}

func TestListFilteredSupportsAgentTypeFilter(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	registerUsageRecordCleanup(t, db, ctx, tenantID)
	registerToolCallLogCleanup(t, db, ctx, tenantID)
	_, _, keyID, _, _, _ := seedUsageDimensions(t, db, ctx, tenantID, userID, projectID)

	now := time.Now().UTC()
	workbuddyReq := fmt.Sprintf("req_tool_agent_workbuddy_%d", now.UnixNano())
	vscodeReq := fmt.Sprintf("req_tool_agent_vscode_%d", now.UnixNano())
	insertToolRequestLogFixtureWithAgent(t, db, ctx, tenantID, workbuddyReq, userID, projectID, keyID, "workbuddy", now.Add(-2*time.Minute))
	insertToolRequestLogFixtureWithAgent(t, db, ctx, tenantID, vscodeReq, userID, projectID, keyID, "vscode", now.Add(-time.Minute))
	insertToolCallFixture(t, db, ctx, tenantID, workbuddyReq, "sess-agent-workbuddy", userID, "read_file", "medium", "audit", "", "", now.Add(-2*time.Minute))
	insertToolCallFixture(t, db, ctx, tenantID, vscodeReq, "sess-agent-vscode", userID, "read_file", "medium", "audit", "", "", now.Add(-time.Minute))

	repo := NewToolCallLogRepository(db)
	logs, total, err := repo.ListFiltered(ctx, ToolCallFilter{
		TenantID:  tenantID,
		StartDate: now.Add(-time.Hour),
		EndDate:   now.Add(time.Hour),
		AgentType: "workbuddy",
		ToolName:  "read_file",
		Limit:     50,
		Offset:    0,
	})
	if err != nil {
		t.Fatalf("list filtered tool calls by agent_type: %v", err)
	}
	if total != 1 || len(logs) != 1 || logs[0].RequestID != workbuddyReq {
		t.Fatalf("expected one workbuddy tool call, total=%d logs=%+v", total, logs)
	}
}
func TestBuildToolCallListQuerySupportsSkipTotalCallerSemantics(t *testing.T) {
	start := time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC)
	filter := ToolCallFilter{
		TenantID:  "tenant-1",
		StartDate: start,
		EndDate:   start.Add(time.Hour),
		RiskLevel: "high+",
		Limit:     25,
		Offset:    50,
		SkipTotal: true,
	}
	where, args, err := toolCallFilterWhere(filter)
	if err != nil {
		t.Fatalf("build where: %v", err)
	}

	query, listArgs, countQuery, countArgs := buildToolCallListQuery(where, args, filter)

	if !strings.Contains(query, "ORDER BY tcl.created_at DESC") || !strings.Contains(query, "LIMIT $4 OFFSET $5") {
		t.Fatalf("tool call list query should include stable pagination, got %s", query)
	}
	if !strings.Contains(countQuery, "SELECT COUNT(*)::int") || !strings.Contains(countQuery, "FROM tool_call_logs tcl") {
		t.Fatalf("count query should remain available for non-skip callers, got %s", countQuery)
	}
	if len(listArgs) != 5 || listArgs[0] != "tenant-1" || listArgs[1] != start || listArgs[3] != 25 || listArgs[4] != 50 {
		t.Fatalf("unexpected list args: %#v", listArgs)
	}
	if !strings.Contains(where, "command_shell_metacharacter") {
		t.Fatalf("high+ drill-down must suppress legacy shell-syntax-only false positives, got %s", where)
	}
	if len(countArgs) != 3 {
		t.Fatalf("unexpected count args: %#v", countArgs)
	}
}

func TestBuildToolCallAuditPageQueryFiltersBeforePaginationAndOmitsSensitivePayload(t *testing.T) {
	filter := ToolCallFilter{
		TenantID: "tenant-a", UserID: "user-a", ClientID: "client-a", ProjectID: "project-a",
		SessionID: "session-a", RequestID: "request-a", Mode: "audit", RiskLevel: "high",
		ToolName: "filesystem__read", ToolType: "mcp", AgentType: "workbuddy", PolicyID: "policy-a",
		RawDecision: "confirm", EffectiveDecision: "audit", Server: "filesystem",
		DispositionStatus: "accepted", Keyword: "异常", Limit: 20, Offset: 40,
	}
	where, args, err := toolCallFilterWhere(filter)
	if err != nil {
		t.Fatalf("build where: %v", err)
	}
	for _, clause := range []string{
		"tcl.tenant_id", "tcl.user_id", "rl.client_id", "rl.project_id", "tcl.session_id",
		"tcl.request_id", "tcl.risk_level", "tcl.tool_name", "tcl.tool_type", "rl.agent_type",
		"tcl.matched_policy_id", "tcl.raw_decision", "tcl.effective_decision", "split_part(tcl.tool_name",
		"ad.status", "tcl.tool_name ILIKE", "tcl.matched_policy_name", "tcl.match_reason",
	} {
		if !strings.Contains(where, clause) {
			t.Fatalf("combined filter clause %q missing from %s", clause, where)
		}
	}

	query, listArgs, countQuery, _ := buildToolCallAuditPageQuery(where, args, filter)
	if !strings.Contains(query, "LEFT JOIN audit_dispositions ad") ||
		!strings.Contains(query, "ad.tenant_id = tcl.tenant_id") ||
		!strings.Contains(query, "ad.subject_type = 'tool_call'") {
		t.Fatalf("disposition projection is not tenant-scoped: %s", query)
	}
	if strings.Contains(query, "tcl.parameters") || strings.Contains(query, "tcl.result") ||
		strings.Contains(query, "tcl.evidence_json") || strings.Contains(query, "tcl.tainted_arguments") {
		t.Fatalf("list query must not select sensitive detail payloads: %s", query)
	}
	if strings.Contains(where, "tcl.parameters") || strings.Contains(where, "tcl.result") ||
		strings.Contains(where, "tcl.evidence_json") || strings.Contains(where, "tcl.normalized_target") {
		t.Fatalf("keyword filter must stay on bounded summary fields: %s", where)
	}
	if !strings.Contains(query, "ORDER BY tcl.created_at DESC, tcl.id DESC") {
		t.Fatalf("list query needs stable ordering: %s", query)
	}
	if got := listArgs[len(listArgs)-2]; got != 21 {
		t.Fatalf("query limit = %#v, want requested limit+1", got)
	}
	if !strings.Contains(countQuery, "LEFT JOIN audit_dispositions ad") {
		t.Fatalf("count must apply the same disposition filter: %s", countQuery)
	}
}

func TestListAuditPageKeepsDispositionCorrectBeyondFirstThousandRows(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	if _, err := db.Exec(ctx, `
CREATE TABLE audit_dispositions (
id bigserial PRIMARY KEY,
tenant_id varchar(128) NOT NULL,
subject_type varchar(64) NOT NULL,
subject_id varchar(128) NOT NULL,
status varchar(32) NOT NULL,
note text,
UNIQUE (tenant_id, subject_type, subject_id)
)
`); err != nil {
		t.Fatalf("create dispositions: %v", err)
	}
	const tenantID = "tenant-page-a"
	if _, err := db.Exec(ctx, `
INSERT INTO tool_call_logs (
			id, request_id, session_id, tenant_id, user_id, tool_name, tool_type, risk_level,
			parameters, result, status, raw_decision, effective_decision, mode, event_kind,
			execution_observed, result_observed, created_at
)
SELECT
'tc-page-' || i, 'req-page-' || i, 'sess-page', $1, 'user-page',
'filesystem__read', 'mcp', 'high', jsonb_build_object('secret', i), 'sensitive-result-' || i,
			'audited', 'confirm', 'audit', 'audit', 'invocation_proposed', FALSE, FALSE,
TIMESTAMPTZ '2026-09-01 00:00:00+00' + i * INTERVAL '1 second'
FROM generate_series(1, 1001) AS i
`, tenantID); err != nil {
		t.Fatalf("insert paged tool calls: %v", err)
	}
	if _, err := db.Exec(ctx, `
INSERT INTO audit_dispositions (tenant_id, subject_type, subject_id, status, note) VALUES
($1, 'tool_call', 'tc-page-1', 'accepted', 'tenant note'),
('tenant-page-b', 'tool_call', 'tc-page-1', 'false_positive', 'other tenant note')
`, tenantID); err != nil {
		t.Fatalf("insert dispositions: %v", err)
	}

	repo := NewToolCallLogRepository(db)
	first, err := repo.ListAuditPage(ctx, ToolCallFilter{TenantID: tenantID, Limit: 100, SkipTotal: true})
	if err != nil {
		t.Fatalf("list first page: %v", err)
	}
	if len(first.Data) != 100 || !first.HasMore || first.TotalKnown {
		t.Fatalf("unexpected first page metadata: len=%d has_more=%v total_known=%v", len(first.Data), first.HasMore, first.TotalKnown)
	}

	last, err := repo.ListAuditPage(ctx, ToolCallFilter{TenantID: tenantID, Limit: 1, Offset: 1000})
	if err != nil {
		t.Fatalf("list 1001st row: %v", err)
	}
	if len(last.Data) != 1 || last.Data[0].ID != "tc-page-1" ||
		last.Data[0].DispositionStatus != "accepted" || last.Data[0].DispositionNote != "tenant note" {
		t.Fatalf("1001st disposition projection is wrong: %#v", last.Data)
	}
	if last.Total != 1001 || !last.TotalKnown || last.HasMore {
		t.Fatalf("unexpected last page metadata: %#v", last)
	}

	statusPage, err := repo.ListAuditPage(ctx, ToolCallFilter{
		TenantID: tenantID, DispositionStatus: "accepted", Limit: 20,
	})
	if err != nil {
		t.Fatalf("filter accepted disposition: %v", err)
	}
	if statusPage.Total != 1 || len(statusPage.Data) != 1 || statusPage.Data[0].ID != "tc-page-1" {
		t.Fatalf("disposition filter must run before pagination: %#v", statusPage)
	}

	sessionDetails, err := repo.ListBySessionLimited(ctx, tenantID, "sess-page", 50)
	if err != nil {
		t.Fatalf("list bounded session details: %v", err)
	}
	if len(sessionDetails) != 50 {
		t.Fatalf("session details length = %d, want 50", len(sessionDetails))
	}
	if sessionDetails[0].ID != "tc-page-952" || sessionDetails[49].ID != "tc-page-1001" {
		t.Fatalf("session details are not bounded to the newest 50 in timeline order: first=%q last=%q len=%d",
			sessionDetails[0].ID, sessionDetails[len(sessionDetails)-1].ID, len(sessionDetails))
	}
}
func TestGetRiskOverviewAggregatesAgentGuardDecisions(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	registerUsageRecordCleanup(t, db, ctx, tenantID)
	registerToolCallLogCleanup(t, db, ctx, tenantID)
	_, _, keyID, _, _, _ := seedUsageDimensions(t, db, ctx, tenantID, userID, projectID)

	now := time.Now().UTC()
	rows := []struct {
		requestID  string
		sessionID  string
		toolName   string
		riskLevel  string
		mode       string
		policyID   string
		policyName string
	}{
		{"block", "sess-overview-1", "bash.exec", "high", "block", "pol_", "高危阻断"},
		{"audit", "sess-overview-1", "http.fetch", "medium", "audit", "pol_audit", "审计策略"},
		{"confirm", "sess-overview-2", "db.query", "high", "confirm", "pol_confirm", "人工确认策略"},
		{"allow", "sess-overview-3", "file.read", "low", "allow", "", ""},
		{"unclassified", "sess-overview-4", "Skill", "medium", "", "", ""},
		{"legacy-shell", "sess-overview-legacy", "Bash", "critical", "audit", "", ""},
	}
	for i, row := range rows {
		requestID := fmt.Sprintf("req_tool_overview_%s_%d", row.requestID, now.UnixNano())
		createdAt := now.Add(time.Duration(i-5) * time.Minute)
		insertToolRequestLogFixture(t, db, ctx, tenantID, requestID, userID, projectID, keyID, createdAt)
		insertToolCallFixture(t, db, ctx, tenantID, requestID, row.sessionID, userID, row.toolName, row.riskLevel, row.mode, row.policyID, row.policyName, createdAt)
		if row.requestID == "legacy-shell" {
			if _, err := db.Exec(ctx, `UPDATE tool_call_logs SET evidence_json = '[{"rule_id":"command_shell_metacharacter"}]'::jsonb WHERE tenant_id = $1 AND request_id = $2`, tenantID, requestID); err != nil {
				t.Fatalf("mark legacy shell-only signal: %v", err)
			}
		}
	}
	if _, err := db.Exec(ctx, `
		INSERT INTO agentguard_confirmations (
			id,tenant_id,request_id,trace_id,tool_name,raw_decision,effective_decision,
			status,expires_at,created_at,tool_call_id,replay_status,replay_tool_log_id,source
		) VALUES (
			$1,$2,$3,$4,'db.query','confirm','confirm',
			'pending',$5,$6,$7,'pending','',''
		)
	`, "cf-overview-"+fmt.Sprint(now.UnixNano()), tenantID, "req-confirm-overview", "trace-confirm-overview", now.Add(time.Hour), now, "call-confirm-overview"); err != nil {
		t.Fatalf("insert pending confirmation fixture: %v", err)
	}
	otherTenantID := tenantID + "_other"
	registerToolCallLogCleanup(t, db, ctx, otherTenantID)
	insertToolCallFixture(t, db, ctx, otherTenantID, "req_tool_overview_other", "sess-other", userID, "bash.exec", "high", "block", "pol_", "高危阻断", now)

	overview, err := NewToolCallLogRepository(db).GetRiskOverview(ctx, tenantID, now.Add(-time.Hour), now.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("get risk overview: %v", err)
	}
	if overview.TotalToolCalls != 5 {
		t.Fatalf("classified tool calls = %d, want 5; unclassified inventory must stay out of risk operations", overview.TotalToolCalls)
	}
	if overview.HighRiskCalls != 2 || overview.BlockedCalls != 1 || overview.AuditCalls != 2 || overview.ConfirmCalls != 1 {
		t.Fatalf("unexpected decision counters: %+v", overview)
	}
	if overview.PendingConfirm != 1 {
		t.Fatalf("unexpected /confirm counters: %+v", overview)
	}
	if countByRiskLevel(overview.ByRiskLevel, "high") != 2 || countByRiskLevel(overview.ByRiskLevel, "medium") != 1 || countByRiskLevel(overview.ByRiskLevel, "low") != 2 {
		t.Fatalf("unexpected risk buckets: %+v", overview.ByRiskLevel)
	}
	if countByPolicy(overview.ByPolicy, "pol_", "block") != 1 || countByPolicy(overview.ByPolicy, "pol_confirm", "confirm") != 1 {
		t.Fatalf("unexpected policy buckets: %+v", overview.ByPolicy)
	}
	if countByObject(overview.TopApps, projectID) != 5 || countByObject(overview.TopKeys, keyID) != 5 ||
		countByObject(overview.TopUsers, userID) != 2 {
		t.Fatalf("unexpected object buckets: apps=%+v keys=%+v users=%+v", overview.TopApps, overview.TopKeys, overview.TopUsers)
	}
	if countByObject(overview.TopSessions, "sess-overview-1") != 2 {
		t.Fatalf("unexpected session buckets: %+v", overview.TopSessions)
	}
}

func TestGetRiskOverviewIncludesTopAgentsScopedByTenant(t *testing.T) {
	db, ctx, tenantID, userID, projectID := setupAuditStatsRegressionFixture(t)
	registerUsageRecordCleanup(t, db, ctx, tenantID)
	registerToolCallLogCleanup(t, db, ctx, tenantID)
	_, _, keyID, _, _, _ := seedUsageDimensions(t, db, ctx, tenantID, userID, projectID)

	now := time.Now().UTC()
	rows := []struct {
		suffix    string
		agentType string
		riskLevel string
		mode      string
	}{
		{"a1", "workbuddy", "high", "block"},
		{"a2", "workbuddy", "high", "audit"},
		{"a3", "cursor", "critical", "block"},
		{"a4", "", "high", "block"},         // non-agent traffic must be excluded
		{"a5", "workbuddy", "low", "allow"}, // normal activity must not make an agent look risky
	}
	for i, row := range rows {
		requestID := fmt.Sprintf("req_tool_agent_%s_%d", row.suffix, now.UnixNano())
		createdAt := now.Add(time.Duration(i-5) * time.Minute)
		insertToolRequestLogFixtureWithAgent(t, db, ctx, tenantID, requestID, userID, projectID, keyID, row.agentType, createdAt)
		insertToolCallFixture(t, db, ctx, tenantID, requestID, "sess-agent-"+row.suffix, userID, "bash.exec", row.riskLevel, row.mode, "pol_x", "策略", createdAt)
	}

	// Cross-tenant leakage guard: another tenant's workbuddy decision must not surface.
	otherTenantID := tenantID + "_other"
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`, otherTenantID, otherTenantID); err != nil {
		t.Fatalf("insert other tenant: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(ctx, "DELETE FROM request_logs WHERE tenant_id = $1", otherTenantID)
		_, _ = db.Exec(ctx, "DELETE FROM tenants WHERE id = $1", otherTenantID)
	})
	registerToolCallLogCleanup(t, db, ctx, otherTenantID)
	otherReq := fmt.Sprintf("req_tool_agent_other_%d", now.UnixNano())
	insertToolRequestLogFixtureWithAgent(t, db, ctx, otherTenantID, otherReq, userID, projectID, keyID, "workbuddy", now)
	insertToolCallFixture(t, db, ctx, otherTenantID, otherReq, "sess-agent-other", userID, "bash.exec", "high", "block", "pol_x", "策略", now)

	overview, err := NewToolCallLogRepository(db).GetRiskOverview(ctx, tenantID, now.Add(-time.Hour), now.Add(time.Hour), "")
	if err != nil {
		t.Fatalf("get risk overview: %v", err)
	}
	if countByObject(overview.TopAgents, "workbuddy") != 2 {
		t.Fatalf("expected workbuddy=2 in top agents, got %+v", overview.TopAgents)
	}
	if countByObject(overview.TopAgents, "cursor") != 1 {
		t.Fatalf("expected cursor=1 in top agents, got %+v", overview.TopAgents)
	}
	if countByObject(overview.TopAgents, "") != 0 {
		t.Fatalf("empty agent_type must be excluded from top agents, got %+v", overview.TopAgents)
	}
	if nameByObject(overview.TopAgents, "workbuddy") != "WorkBuddy" {
		t.Fatalf("expected human-readable label WorkBuddy for workbuddy, got %+v", overview.TopAgents)
	}
}

func countByRiskLevel(items []RiskLevelCount, riskLevel string) int {
	for _, item := range items {
		if item.RiskLevel == riskLevel {
			return item.Count
		}
	}
	return 0
}

func countByPolicy(items []PolicyCount, policyID, mode string) int {
	for _, item := range items {
		if item.PolicyID == policyID && item.Mode == mode {
			return item.Count
		}
	}
	return 0
}

func countByObject(items []ObjectCount, id string) int {
	for _, item := range items {
		if item.ID == id {
			return item.Count
		}
	}
	return 0
}

func nameByObject(items []ObjectCount, id string) string {
	for _, item := range items {
		if item.ID == id {
			return item.Name
		}
	}
	return ""
}

func TestListFilteredRequestIDRemainsTenantScopedInPostgres(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	now := time.Now().UTC()
	_, err := db.Exec(ctx, `
		INSERT INTO tool_call_logs (
			id, request_id, tenant_id, session_id, user_id, tool_name, tool_type, risk_level, parameters, result, status,
			event_kind, execution_observed, result_observed, tool_call_id, created_at
		) VALUES
			('tc-request-a', 'req-shared', 'tenant-a', 'sess-a', 'user-a', 'demo__write', 'mcp', 'high', '{}', '', 'audited',
			 'invocation_proposed', FALSE, FALSE, 'number:9', $1),
			('tc-request-b', 'req-shared', 'tenant-b', 'sess-b', 'user-b', 'demo__write', 'mcp', 'high', '{}', '', 'audited',
			 'invocation_proposed', FALSE, FALSE, 'number:9', $1),
			('tc-other-request', 'req-other', 'tenant-a', 'sess-c', 'user-a', 'demo__write', 'mcp', 'high', '{}', '', 'audited',
			 'invocation_proposed', FALSE, FALSE, 'number:10', $1)
	`, now)
	if err != nil {
		t.Fatalf("insert request filter facts: %v", err)
	}
	logs, total, err := NewToolCallLogRepository(db).ListFiltered(ctx, ToolCallFilter{
		TenantID: "tenant-a", RequestID: "req-shared", RiskLevel: "high", Limit: 50,
	})
	if err != nil {
		t.Fatalf("list request-scoped evidence: %v", err)
	}
	if total != 1 || len(logs) != 1 || logs[0].ID != "tc-request-a" {
		t.Fatalf("request filter crossed tenant/request boundary: total=%d logs=%#v", total, logs)
	}
}
