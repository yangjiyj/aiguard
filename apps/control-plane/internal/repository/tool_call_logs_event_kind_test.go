package repository

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func setupRuntimeTruthTestDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	databaseURL := os.Getenv("TOOL_CALL_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("TOOL_CALL_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect test database: %v", err)
	}
	schema := fmt.Sprintf("tool_truth_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("create isolated schema: %v", err)
	}

	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse database URL: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated schema: %v", err)
	}

	_, err = db.Exec(ctx, `
		CREATE TABLE tool_call_logs (
			id varchar(64) PRIMARY KEY,
			request_id varchar(128) NOT NULL,
			session_id varchar(128),
			tenant_id varchar(128) NOT NULL,
			endpoint_id varchar(128),
			user_id varchar(128),
			tool_name varchar(256) NOT NULL,
			tool_type varchar(64) NOT NULL,
			risk_level varchar(16) NOT NULL DEFAULT 'low',
			parameters jsonb DEFAULT '{}'::jsonb,
			result text,
			status varchar(32) NOT NULL DEFAULT 'success',
			matched_policy_id varchar(128),
			matched_policy_name varchar(255),
			matched_action varchar(32),
			match_reason text,
			raw_decision varchar(16),
			effective_decision varchar(16),
			mode varchar(16),
			effective_reason text,
			policy_version varchar(64),
			trace_id varchar(128),
			confidence double precision,
			evidence_json jsonb NOT NULL DEFAULT '[]'::jsonb,
			normalized_target text,
			provenance varchar(64),
			tainted_arguments jsonb NOT NULL DEFAULT '[]'::jsonb,
			created_at timestamptz NOT NULL DEFAULT now()
		);
		CREATE TABLE request_logs (
			request_id varchar(128) NOT NULL,
			tenant_id varchar(128) NOT NULL,
			agent_type varchar(128),
			client_id varchar(128),
			project_id varchar(128),
			PRIMARY KEY (request_id, tenant_id), agent_instance_id varchar(128));
		CREATE TABLE agentguard_policies (
			id varchar(128) PRIMARY KEY, tenant_id varchar(128) NOT NULL
		);
		CREATE TABLE agentguard_policy_versions (
			id varchar(128) PRIMARY KEY, tenant_id varchar(128) NOT NULL, policy_id varchar(128) NOT NULL
		);
	`)
	if err != nil {
		t.Fatalf("create isolated fixture: %v", err)
	}

	migrationPath := filepath.Join("..", "..", "..", "..", "deploy", "migrations", "112_tool_event_runtime_truth.sql")
	migration, err := os.ReadFile(migrationPath)
	if err != nil {
		t.Fatalf("read migration 112: %v", err)
	}
	// The production runner executes CONCURRENTLY outside a transaction. pgx sends a
	// multi-statement Exec as one implicit transaction, so the isolated fixture uses
	// ordinary indexes; deploy/tests/test_runtime_truth_migration.sh covers the exact runner path.
	testableMigration := strings.ReplaceAll(string(migration), "CREATE INDEX CONCURRENTLY", "CREATE INDEX")
	if _, err := db.Exec(ctx, testableMigration); err != nil {
		t.Fatalf("apply migration 112 in isolated schema: %v", err)
	}
	if _, err := db.Exec(ctx, `
		ALTER TABLE tool_call_logs
			ADD COLUMN operation_id varchar(128),
			ADD COLUMN public_event_id varchar(64),
			ADD COLUMN event_type varchar(48),
			ADD COLUMN risk_category varchar(64),
			ADD COLUMN risk_subcategory varchar(64),
			ADD COLUMN reason_summary text,
			ADD COLUMN target_summary text,
			ADD COLUMN mode_default_action varchar(16),
			ADD COLUMN custom_action varchar(16),
			ADD COLUMN final_action varchar(16),
			ADD COLUMN notification_required boolean,
			ADD COLUMN notification_status varchar(16),
			ADD COLUMN discardable_path_matched boolean,
			ADD COLUMN discardable_path_reason text,
			ADD COLUMN execution_forwarded boolean,
			ADD COLUMN application_id varchar(128),
			ADD COLUMN agent_type varchar(128),
			ADD COLUMN model varchar(256),
			ADD COLUMN protocol varchar(32);
		CREATE UNIQUE INDEX uq_tool_call_logs_destructive_operation_event
			ON tool_call_logs (tenant_id, operation_id, event_type)
			WHERE operation_id IS NOT NULL AND btrim(operation_id) <> '';
	`); err != nil {
		t.Fatalf("add destructive lifecycle fixture: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	return db, ctx
}

func TestToolCallLogRoundTripsRuntimeTruthFields(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	repo := NewToolCallLogRepository(db)
	entry := &ToolCallLog{
		RequestID:             "req-tool-truth",
		SessionID:             "session-1",
		TenantID:              "tenant-tool-truth",
		UserID:                "user-1",
		ToolName:              "WebSearch",
		ToolType:              "network",
		RiskLevel:             "medium",
		Status:                "audited",
		EventKind:             "invocation_proposed",
		ExecutionObserved:     false,
		ResultObserved:        false,
		ToolCallID:            "call-42",
		AssetID:               "asset-7",
		SkillInvocationID:     "skill-inv-9",
		MCPServerID:           "mcp-server-3",
		MCPToolID:             "mcp-tool-4",
		DefinitionHash:        "sha256:def",
		AttributionMode:       "explicit",
		AttributionConfidence: 0.98,
	}
	if err := repo.Create(ctx, entry); err != nil {
		t.Fatalf("create tool call log: %v", err)
	}

	logs, err := repo.ListByRequest(ctx, entry.TenantID, entry.RequestID)
	if err != nil {
		t.Fatalf("list by request: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("expected one log, got %d", len(logs))
	}
	got := logs[0]
	if got.EventKind != "invocation_proposed" || got.ExecutionObserved || got.ResultObserved {
		t.Fatalf("runtime fact fields = %#v", got)
	}
	if got.ToolCallID != "call-42" || got.AssetID != "asset-7" || got.SkillInvocationID != "skill-inv-9" {
		t.Fatalf("correlation fields = %#v", got)
	}
	if got.MCPServerID != "mcp-server-3" || got.MCPToolID != "mcp-tool-4" || got.DefinitionHash != "sha256:def" {
		t.Fatalf("asset fields = %#v", got)
	}
	if got.AttributionMode != "explicit" || got.AttributionConfidence != 0.98 {
		t.Fatalf("attribution fields = %#v", got)
	}

	filtered, total, err := repo.ListFiltered(ctx, ToolCallFilter{
		TenantID:  entry.TenantID,
		EventKind: "invocation_proposed",
		Limit:     10,
	})
	if err != nil {
		t.Fatalf("filter by event kind: %v", err)
	}
	if total != 1 || len(filtered) != 1 || filtered[0].ID != entry.ID {
		t.Fatalf("filtered logs total=%d logs=%#v", total, filtered)
	}
}

func TestLegacyEventKindDerivationNeverTreatsStatusAsExecution(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	_, err := db.Exec(ctx, `
		INSERT INTO tool_call_logs (
			id, request_id, session_id, tenant_id, user_id, tool_name, tool_type, risk_level, result, status,
			raw_decision, effective_decision, provenance
		) VALUES
			('tc-legacy-definition', 'req-legacy', '', 'tenant-legacy', '', 'Read', 'file', 'low', 'request tool passed policy check', 'success', NULL, NULL, NULL),
			('tc-legacy-proposed', 'req-legacy', '', 'tenant-legacy', '', 'Bash', 'system', 'low', '', 'success', 'allow', 'allow', NULL),
			('tc-legacy-mcp', 'req-legacy', '', 'tenant-legacy', '', 'demo__write', 'mcp', 'low', '', 'success', NULL, NULL, 'mcp_gateway'),
			('tc-legacy-unknown', 'req-legacy', '', 'tenant-legacy', '', 'unknown', 'unknown', 'low', '', 'success', NULL, NULL, NULL)
	`)
	if err != nil {
		t.Fatalf("insert legacy rows: %v", err)
	}

	logs, err := NewToolCallLogRepository(db).ListByRequest(ctx, "tenant-legacy", "req-legacy")
	if err != nil {
		t.Fatalf("list legacy rows: %v", err)
	}
	kinds := make(map[string]string, len(logs))
	for _, log := range logs {
		kinds[log.ToolName] = log.EventKind
		if log.ExecutionObserved {
			t.Fatalf("legacy row %s was marked executed: %#v", log.ToolName, log)
		}
	}
	if kinds["Read"] != "definition_exposed" || kinds["Bash"] != "invocation_proposed" {
		t.Fatalf("known legacy derivation = %#v", kinds)
	}
	if kinds["demo__write"] != "legacy_unknown" || kinds["unknown"] != "legacy_unknown" {
		t.Fatalf("status-only legacy rows must stay unknown: %#v", kinds)
	}
}

// 端点钩子允许缺少用户与工具结果；所有详情查询都必须保留该行，不能将 SQL NULL 直接扫描进 Go string。
func TestEndpointHookNullableStringsAcrossDetailQueries(t *testing.T) {
	db, ctx := setupRuntimeTruthTestDB(t)
	migration, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "deploy", "migrations", "854_agent_endpoint_hook_attribution.sql"))
	if err != nil {
		t.Fatalf("read endpoint hook migration: %v", err)
	}
	if _, err := db.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply endpoint hook migration in isolated schema: %v", err)
	}
	const tenantID = "tenant-endpoint-null"
	const requestID = "req-endpoint-null"
	const sessionID = "sess-endpoint-null"
	_, err = db.Exec(ctx, `
		INSERT INTO tool_call_logs (
			id, request_id, session_id, tenant_id, endpoint_id, tool_call_id, user_id, tool_name, tool_type,
			risk_level, result, status, event_kind, execution_observed, result_observed, attribution_mode, attribution_confidence, created_at
		) VALUES
			('tc-endpoint-no-user', $1, $2, $3, 'ep-endpoint-native', 'toolu-endpoint-native', NULL, 'endpoint__read',
			 'system', 'low', NULL, 'audited', 'invocation_proposed', FALSE, FALSE, 'endpoint_hook', 1, now()),
			('tc-endpoint-user', $1, NULL, $3, 'ep-endpoint-user', 'toolu-endpoint-user', 'user-endpoint', 'endpoint__write',
			 'system', 'low', NULL, 'audited', 'invocation_proposed', FALSE, FALSE, 'endpoint_hook', 1, now())
	`, requestID, sessionID, tenantID)
	if err != nil {
		t.Fatalf("insert endpoint hooks: %v", err)
	}
	repo := NewToolCallLogRepository(db)
	check := func(label string, logs []ToolCallLog, wantID string) {
		t.Helper()
		if len(logs) != 1 || logs[0].ID != wantID || logs[0].Result != "" || logs[0].TenantID != tenantID {
			t.Fatalf("%s: unexpected logs: %#v", label, logs)
		}
		if wantID == "tc-endpoint-no-user" && logs[0].UserID != "" {
			t.Fatalf("%s: NULL user_id should scan as empty string: %#v", label, logs[0])
		}
		if wantID == "tc-endpoint-no-user" && logs[0].SessionID != sessionID {
			t.Fatalf("%s: session identity = %q, want %q", label, logs[0].SessionID, sessionID)
		}
		if wantID == "tc-endpoint-user" && logs[0].SessionID != "" {
			t.Fatalf("%s: NULL session_id should scan as empty string: %#v", label, logs[0])
		}
		wantEndpoint, wantToolCall := "ep-endpoint-native", "toolu-endpoint-native"
		if wantID == "tc-endpoint-user" {
			wantEndpoint, wantToolCall = "ep-endpoint-user", "toolu-endpoint-user"
		}
		if logs[0].EndpointID != wantEndpoint || logs[0].ToolCallID != wantToolCall {
			t.Fatalf("%s: exact native endpoint/tool tuple was lost: got endpoint=%q tool_call_id=%q, want %q/%q",
				label, logs[0].EndpointID, logs[0].ToolCallID, wantEndpoint, wantToolCall)
		}
	}

	bySession, err := repo.ListBySession(ctx, tenantID, sessionID)
	if err != nil {
		t.Fatalf("list by session: %v", err)
	}
	check("ListBySession", bySession, "tc-endpoint-no-user")

	bounded, err := repo.ListBySessionLimited(ctx, tenantID, sessionID, 10)
	if err != nil {
		t.Fatalf("list by session limited: %v", err)
	}
	check("ListBySessionLimited", bounded, "tc-endpoint-no-user")

	byRequest, err := repo.ListByRequest(ctx, tenantID, requestID)
	if err != nil {
		t.Fatalf("list by request: %v", err)
	}
	if len(byRequest) != 2 {
		t.Fatalf("ListByRequest: got %d logs, want 2", len(byRequest))
	}
	for _, log := range byRequest {
		check("ListByRequest", []ToolCallLog{log}, log.ID)
	}

	byUser, total, err := repo.ListByUser(ctx, tenantID, "user-endpoint", 10, 0)
	if err != nil {
		t.Fatalf("list by user: %v", err)
	}
	if total != 1 {
		t.Fatalf("ListByUser: total=%d, want 1", total)
	}
	check("ListByUser", byUser, "tc-endpoint-user")

	filtered, count, err := repo.ListFiltered(ctx, ToolCallFilter{
		TenantID: tenantID, SessionID: sessionID, Limit: 10,
	})
	if err != nil {
		t.Fatalf("list filtered: %v", err)
	}
	if count != 1 {
		t.Fatalf("ListFiltered: total=%d, want 1", count)
	}
	check("ListFiltered", filtered, "tc-endpoint-no-user")
}
