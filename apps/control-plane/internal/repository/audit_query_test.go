package repository

import (
	"strings"
	"testing"
	"time"
)

func TestBuildRequestLogListQueryPagesBeforeFirstUserContentLookup(t *testing.T) {
	start := time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC)
	end := start.Add(24 * time.Hour)

	query, args, countQuery, countArgs := buildRequestLogListQuery(RequestLogListFilter{
		TenantID:  "tenant-1",
		StartTime: start,
		EndTime:   end,
		Limit:     50,
		Offset:    100,
	})

	if !strings.Contains(query, "WITH page AS") {
		t.Fatalf("list query should page request_logs first, got %s", query)
	}
	if strings.Contains(query, "first_user_content") || strings.Contains(query, "DISTINCT ON") {
		t.Fatalf("list query should not pre-aggregate first_user_content, got %s", query)
	}
	if !strings.Contains(query, "LEFT JOIN LATERAL") || !strings.Contains(query, "cl.request_id = page.id") || !strings.Contains(query, "LIMIT 1") {
		t.Fatalf("list query should use a per-page lateral content lookup, got %s", query)
	}
	if !strings.Contains(query, "rl.created_at >= $2") || !strings.Contains(query, "rl.created_at <= $3") {
		t.Fatalf("list query should include bounded time window, got %s", query)
	}
	if !strings.Contains(query, "LIMIT $4 OFFSET $5") {
		t.Fatalf("list query should keep limit/offset after time args, got %s", query)
	}
	if len(args) != 5 || args[0] != "tenant-1" || args[1] != start || args[2] != end || args[3] != 50 || args[4] != 100 {
		t.Fatalf("unexpected query args: %#v", args)
	}
	if !strings.Contains(countQuery, "request_logs rl") || !strings.Contains(countQuery, "rl.created_at >= $2") || !strings.Contains(countQuery, "rl.created_at <= $3") {
		t.Fatalf("count query should mirror list filters, got %s", countQuery)
	}
	if len(countArgs) != 3 || countArgs[0] != "tenant-1" || countArgs[1] != start || countArgs[2] != end {
		t.Fatalf("unexpected count args: %#v", countArgs)
	}
}

func TestBuildAuditActionListQuerySupportsSkipTotalCallerSemantics(t *testing.T) {
	start := time.Date(2026, 6, 20, 1, 2, 3, 0, time.UTC)
	end := start.Add(time.Hour)

	query, args, countQuery, countArgs := buildAuditActionListQuery(AuditActionListFilter{
		TenantID:  "tenant-1",
		Action:    "audit",
		StartTime: start,
		EndTime:   end,
		Limit:     20,
		Offset:    40,
		SkipTotal: true,
	})

	if !strings.Contains(query, "created_at >= $2 AND created_at <= $3") || !strings.Contains(query, "action_taken' = $4") {
		t.Fatalf("audit action list should include time and action filters, got %s", query)
	}
	if !strings.Contains(query, "LIMIT $5 OFFSET $6") {
		t.Fatalf("audit action list should preserve pagination args, got %s", query)
	}
	if len(args) != 6 || args[0] != "tenant-1" || args[1] != start || args[2] != end || args[3] != "audit" || args[4] != 20 || args[5] != 40 {
		t.Fatalf("unexpected list args: %#v", args)
	}
	if !strings.Contains(countQuery, "COUNT(*)") || !strings.Contains(countQuery, "action_taken' = $4") {
		t.Fatalf("count query should still be available for non-skip callers, got %s", countQuery)
	}
	if len(countArgs) != 4 {
		t.Fatalf("unexpected count args: %#v", countArgs)
	}
}
