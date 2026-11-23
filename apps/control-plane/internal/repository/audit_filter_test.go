package repository

import (
	"strings"
	"testing"
)

// buildSecurityEventsWhere 的行为文档式测试（不连真库）：
// user/client 过滤要求 JOIN request_logs，args 顺序必须与占位符编号一致。
func TestBuildSecurityEventsWhereWithFilters(t *testing.T) {
	f := SecurityEventFilter{UserID: "u1", ClientID: "key_1", Severity: "high"}
	join, where, args := buildSecurityEventsWhere("t1", f)

	if !strings.Contains(join, "request_logs rl") {
		t.Fatalf("join should reference request_logs rl, got %q", join)
	}
	if !strings.Contains(where, "se.tenant_id = $1") {
		t.Fatalf("where should pin tenant, got %q", where)
	}
	if !strings.Contains(where, "(se.user_id = $2 OR rl.user_id = $2)") {
		t.Fatalf("where should filter user on both sides, got %q", where)
	}
	if !strings.Contains(where, "rl.client_id = $3") {
		t.Fatalf("where should filter client_id via request_logs, got %q", where)
	}
	if !strings.Contains(where, "se.severity = $4") {
		t.Fatalf("where should filter severity, got %q", where)
	}
	if len(args) != 4 {
		t.Fatalf("args length = %d, want 4", len(args))
	}
	want := []interface{}{"t1", "u1", "key_1", "high"}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %v, want %v", i, args[i], want[i])
		}
	}
}

func TestBuildSecurityEventsWhereEmptyFilter(t *testing.T) {
	join, where, args := buildSecurityEventsWhere("t1", SecurityEventFilter{})

	if join != "" {
		t.Fatalf("empty filter should not join, got %q", join)
	}
	if where != "se.tenant_id = $1" {
		t.Fatalf("where = %q, want only tenant clause", where)
	}
	if len(args) != 1 || args[0] != "t1" {
		t.Fatalf("args = %v, want [t1]", args)
	}
}
