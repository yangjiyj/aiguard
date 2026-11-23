package repository

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestBuildEvalAuditEventsWhereAppliesTenantAndCorrelationFilters(t *testing.T) {
	start := time.Date(2026, 6, 9, 23, 51, 0, 0, time.UTC)
	end := start.Add(time.Hour)
	filter := EvalAuditEventFilter{
		EvalRunID: "eval-1",
		TaskID:    "task-1",
		SampleID:  "sample-1",
		TraceID:   "trace-1",
		StartTime: &start,
		EndTime:   &end,
	}

	where, args := buildEvalAuditEventsWhere("tenant-1", filter)

	for _, want := range []string{
		"rl.tenant_id = $1",
		"rl.lse_eval_run_id = $2",
		"rl.lse_task_id = $3",
		"rl.lse_sample_id = $4",
		"rl.trace_id = $5",
		"rl.created_at >= $6",
		"rl.created_at <= $7",
	} {
		if !strings.Contains(where, want) {
			t.Fatalf("where clause should contain %q, got %s", want, where)
		}
	}
	if len(args) != 7 {
		t.Fatalf("expected 7 args, got %#v", args)
	}
}

func TestBuildEvalAuditEventsWhereAppliesClientIDAndSourceIPFilters(t *testing.T) {
	filter := EvalAuditEventFilter{
		ClientID: "key-abc",
		SourceIP: "203.0.113.7",
	}

	where, args := buildEvalAuditEventsWhere("tenant-1", filter)

	for _, want := range []string{
		"rl.tenant_id = $1",
		"rl.client_id = $2",
		"(rl.source_ip = $3 OR rl.proxy_source_ip = $3)",
	} {
		if !strings.Contains(where, want) {
			t.Fatalf("where clause should contain %q, got %s", want, where)
		}
	}
	if len(args) != 3 {
		t.Fatalf("expected 3 args, got %#v", args)
	}
	if args[1] != "key-abc" || args[2] != "203.0.113.7" {
		t.Fatalf("unexpected args: %#v", args)
	}
}

func TestBuildEvalAuditEventsListQueryKeepsCountOptionalForSkipTotal(t *testing.T) {
	where, args := buildEvalAuditEventsWhere("tenant-1", EvalAuditEventFilter{TraceID: "trace-1"})

	query, queryArgs, countQuery, countArgs := buildEvalAuditEventsListQuery(where, args, 100, 200)

	if !strings.Contains(query, "LIMIT $3 OFFSET $4") {
		t.Fatalf("eval list query should append pagination after filters, got %s", query)
	}
	if !strings.Contains(query, "COALESCE(content.content_log_count, 0)") || !strings.Contains(query, "COALESCE(sec.security_event_count, 0)") {
		t.Fatalf("eval list query should preserve related counters, got %s", query)
	}
	if len(queryArgs) != 4 || queryArgs[0] != "tenant-1" || queryArgs[1] != "trace-1" || queryArgs[2] != 100 || queryArgs[3] != 200 {
		t.Fatalf("unexpected query args: %#v", queryArgs)
	}
	if !strings.Contains(countQuery, "SELECT COUNT(*) FROM request_logs rl WHERE") || !strings.Contains(countQuery, "rl.trace_id = $2") {
		t.Fatalf("count query should mirror filters for non-skip callers, got %s", countQuery)
	}
	if len(countArgs) != 2 {
		t.Fatalf("unexpected count args: %#v", countArgs)
	}
}

type fakeEvalAuditEventScanner struct {
	values []interface{}
}

func (s fakeEvalAuditEventScanner) Scan(dest ...interface{}) error {
	if len(dest) != len(s.values) {
		return fmt.Errorf("dest count = %d, want %d", len(dest), len(s.values))
	}
	for i, value := range s.values {
		switch ptr := dest[i].(type) {
		case *string:
			*ptr = value.(string)
		case *int:
			*ptr = value.(int)
		case *float64:
			*ptr = value.(float64)
		case *time.Time:
			*ptr = value.(time.Time)
		default:
			return fmt.Errorf("unsupported dest type %T", dest[i])
		}
	}
	return nil
}

func TestScanEvalAuditEventIncludesContentLogCount(t *testing.T) {
	createdAt := time.Date(2026, 6, 20, 8, 0, 0, 0, time.UTC)
	event, err := scanEvalAuditEvent(fakeEvalAuditEventScanner{values: []interface{}{
		"log-1", "req-1", "tenant-1", "project-1", "user-1", "client-1",
		"203.0.113.7",
		"provider-1", "model-1", "model-name", "session-1", "agent", "chat",
		"completed", 200, 123, 10, 20, 0.12, createdAt, "trace-1",
		"run-1", "task-1", "sample-1", "target-1", 2, 3, 5, 4, "agent-1",
	}})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if event.AgentInstanceID != "agent-1" {
		t.Fatalf("agent instance = %q", event.AgentInstanceID)
	}
	if event.SourceIP != "203.0.113.7" {
		t.Fatalf("source ip = %q, want 203.0.113.7", event.SourceIP)
	}
	if event.ContentLogCount != 2 {
		t.Fatalf("content log count = %d, want 2", event.ContentLogCount)
	}
	if event.SecurityEventCount != 3 {
		t.Fatalf("security event count = %d, want 3", event.SecurityEventCount)
	}
	if event.ToolCallCount != 5 {
		t.Fatalf("tool call count = %d, want 5", event.ToolCallCount)
	}
	if event.MCPToolCallCount != 4 {
		t.Fatalf("mcp tool call count = %d, want 4", event.MCPToolCallCount)
	}
}

func TestBuildModelEvalStatusQuery(t *testing.T) {
	q := buildModelEvalStatusQuery()
	for _, sub := range []string{
		"FROM request_logs rl",
		"rl.lse_eval_run_id <> ''",
		"GROUP BY rl.model_id",
		"security_events se",
		"eval_content_safety",
		"rl.tenant_id = $1",
	} {
		if !strings.Contains(q, sub) {
			t.Errorf("query missing %q\n%s", sub, q)
		}
	}
}
