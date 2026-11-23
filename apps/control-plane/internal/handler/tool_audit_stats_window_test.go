package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func setupToolStatsHandlerTestDB(t *testing.T) (*pgxpool.Pool, context.Context) {
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
	schema := fmt.Sprintf("tool_stats_handler_%d", time.Now().UnixNano())
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+pgx.Identifier{schema}.Sanitize()); err != nil {
		admin.Close()
		t.Fatalf("create handler schema: %v", err)
	}
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatalf("parse test database: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	db, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect handler schema: %v", err)
	}
	_, err = db.Exec(ctx, `
		CREATE TABLE tool_call_logs (
			id varchar(64) PRIMARY KEY, request_id varchar(128) NOT NULL, session_id varchar(128),
			tenant_id varchar(128) NOT NULL, user_id varchar(128),
			tool_name varchar(256) NOT NULL, tool_type varchar(64) NOT NULL, risk_level varchar(16) NOT NULL,
			result text, status varchar(32), matched_policy_id varchar(128), matched_policy_name varchar(255),
			raw_decision varchar(16), effective_decision varchar(16), mode varchar(16),
			trace_id varchar(128), provenance varchar(64), evidence_json jsonb,
			event_kind varchar(32), execution_observed boolean, result_observed boolean,
			tool_call_id text, created_at timestamptz NOT NULL
		)
	`)
	if err != nil {
		t.Fatalf("create handler tool facts: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = admin.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+pgx.Identifier{schema}.Sanitize()+" CASCADE")
		admin.Close()
	})
	return db, ctx
}

func TestGetToolCallStatsUsesRequestedHalfOpenWindow(t *testing.T) {
	db, ctx := setupToolStatsHandlerTestDB(t)
	start := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	end := start.Add(30 * time.Minute)
	_, err := db.Exec(ctx, `
		INSERT INTO tool_call_logs (
			id, request_id, tenant_id, tool_name, tool_type, risk_level, status,
			raw_decision, effective_decision, event_kind, execution_observed, result_observed,
			tool_call_id, created_at
		) VALUES
			('tc-window-inside', 'req-inside', 'tenant-window', 'Bash', 'system', 'high', 'audited',
			 'block', 'audit', 'invocation_proposed', false, false, 'call-inside', $1),
			('tc-window-definition', 'req-def', 'tenant-window', 'Read', 'file', 'low', 'success',
			 NULL, NULL, 'definition_exposed', false, false, NULL, $1),
			('tc-window-before', 'req-before', 'tenant-window', 'Fetch', 'network', 'critical', 'blocked',
			 'block', 'block', 'invocation_proposed', false, false, 'call-before', $2),
			('tc-window-end', 'req-end', 'tenant-window', 'demo__write', 'mcp', 'critical', 'blocked',
			 'block', 'block', 'invocation_proposed', false, false, 'call-end', $3)
	`, start.Add(time.Minute), start.Add(-time.Second), end)
	if err != nil {
		t.Fatalf("insert handler stats facts: %v", err)
	}

	url := fmt.Sprintf("/admin/v1/audit/tools/stats?start=%s&end=%s", start.Format(time.RFC3339), end.Format(time.RFC3339))
	req := httptest.NewRequest(http.MethodGet, url, nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.SessionKey, &repository.Session{TenantID: "tenant-window"}))
	rr := httptest.NewRecorder()
	GetToolCallStats(&Dependencies{ToolCallLogRepo: repository.NewToolCallLogRepository(db)}).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Stats      []repository.ToolCallStats `json:"stats"`
		TotalCount int                        `json:"total_count"`
		Window     struct {
			Start  time.Time `json:"start"`
			End    time.Time `json:"end"`
			Source string    `json:"source"`
		} `json:"window"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode stats response: %v", err)
	}
	if response.TotalCount != 1 || len(response.Stats) != 2 {
		t.Fatalf("windowed handler response = %#v", response)
	}
	if response.Window.Source != "explicit" || !response.Window.Start.Equal(start) || !response.Window.End.Equal(end) {
		t.Fatalf("explicit window = %#v", response.Window)
	}
}

func TestGetToolCallStatsReturnsDefaultWindowMetadata(t *testing.T) {
	db, _ := setupToolStatsHandlerTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/tools/stats", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.SessionKey, &repository.Session{TenantID: "tenant-default-window"}))
	rr := httptest.NewRecorder()
	GetToolCallStats(&Dependencies{ToolCallLogRepo: repository.NewToolCallLogRepository(db)}).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	var response struct {
		Window struct {
			Start  time.Time `json:"start"`
			End    time.Time `json:"end"`
			Source string    `json:"source"`
		} `json:"window"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode default stats response: %v", err)
	}
	if response.Window.Source != "default_24h" || response.Window.End.Sub(response.Window.Start) != 24*time.Hour {
		t.Fatalf("default window = %#v", response.Window)
	}
}

func TestGetToolCallStatsRejectsReversedWindow(t *testing.T) {
	db, _ := setupToolStatsHandlerTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/audit/tools/stats?start=2026-07-11T02:00:00Z&end=2026-07-11T01:00:00Z", nil)
	req = req.WithContext(context.WithValue(req.Context(), auth.SessionKey, &repository.Session{TenantID: "tenant-reversed-window"}))
	rr := httptest.NewRecorder()
	GetToolCallStats(&Dependencies{ToolCallLogRepo: repository.NewToolCallLogRepository(db)}).ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
}
