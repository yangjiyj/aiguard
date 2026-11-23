package repository

import (
	"strings"
	"testing"
)

func TestSecEventAlertGraceSeconds_DefaultZero(t *testing.T) {
	t.Setenv("SECEVENT_ALERT_GRACE_SECONDS", "")
	if got := secEventAlertGraceSeconds(); got != 0 {
		t.Fatalf("default grace must be 0 (no behaviour change), got %d", got)
	}
}

func TestSecEventAlertGraceSeconds_ParsesValue(t *testing.T) {
	t.Setenv("SECEVENT_ALERT_GRACE_SECONDS", "300")
	if got := secEventAlertGraceSeconds(); got != 300 {
		t.Fatalf("expected 300, got %d", got)
	}
}

func TestSecEventAlertGraceSeconds_MalformedFallsBack(t *testing.T) {
	t.Setenv("SECEVENT_ALERT_GRACE_SECONDS", "soon")
	if got := secEventAlertGraceSeconds(); got != 0 {
		t.Fatalf("malformed value must fall back to 0, got %d", got)
	}
	t.Setenv("SECEVENT_ALERT_GRACE_SECONDS", "-60")
	if got := secEventAlertGraceSeconds(); got != 0 {
		t.Fatalf("negative value must fall back to 0, got %d", got)
	}
}

func TestListUnalertedQuery_ZeroGraceKeepsLegacyShape(t *testing.T) {
	// grace=0(默认)必须保持既有 SQL 形状:零回归。
	q := listUnalertedQuery(0)
	if strings.Contains(q, "se.created_at < NOW()") {
		t.Fatalf("grace=0 must not add the grace created_at buffer condition, got:\n%s", q)
	}
	// 语义例外：semantic_attack 走独立 severity 集($3)，让 medium 语义命中可进收件箱而不放宽全局 floor。
	if !strings.Contains(q, "se.event_type = 'semantic_attack' AND se.severity = ANY($3::text[])") {
		t.Fatalf("query must apply a semantic_attack-specific severity floor via $3:\n%s", q)
	}
	for _, want := range []string{"se.alerted_at IS NULL", "se.severity = ANY($2::text[])", "ORDER BY se.created_at ASC, se.id ASC", "LIMIT LEAST($1::bigint, $6::bigint)", "oldest AS", "LIMIT $1::bigint"} {
		if !strings.Contains(q, want) {
			t.Fatalf("legacy query shape lost %q:\n%s", want, q)
		}
	}
	if !strings.Contains(q, "COALESCE(se.matched_summary->>'review_state', '') = 'review_pending'") || !strings.Contains(q, "$4::bigint") {
		t.Fatalf("query must skip recent review_pending rows without starving later rows:\n%s", q)
	}
}

func TestSecEventSemanticInboxSeverities_DefaultFallsBackToGlobalFloor(t *testing.T) {
	// 未设时回退全局 floor(默认 high)：零回归——语义事件与其他事件同一道门槛。
	t.Setenv("SECEVENT_INBOX_SEMANTIC_MIN_SEVERITY", "")
	t.Setenv("SECEVENT_INBOX_MIN_SEVERITY", "")
	got := secEventSemanticInboxSeverities()
	if strings.Join(got, ",") != "high,critical" {
		t.Fatalf("unset semantic floor must fall back to global high/critical, got %v", got)
	}
}

func TestSecEventSemanticInboxSeverities_MediumLetsMediumSemanticSurface(t *testing.T) {
	// 显式 medium：语义 medium 命中也进收件箱（本次放宽的目的）。
	t.Setenv("SECEVENT_INBOX_SEMANTIC_MIN_SEVERITY", "medium")
	got := secEventSemanticInboxSeverities()
	if strings.Join(got, ",") != "medium,high,critical" {
		t.Fatalf("semantic floor=medium must surface medium/high/critical, got %v", got)
	}
}

func TestListUnalertedQuery_GraceAddsCreatedAtBuffer(t *testing.T) {
	// grace>0 追加 created_at 落地缓冲条件,给异步 triage 标注留时间。
	q := listUnalertedQuery(300)
	// $4 用于 pending 超时，故 grace 缓冲使用 $5。
	if !strings.Contains(q, "se.created_at < NOW() - ($5::bigint * INTERVAL '1 second')") {
		t.Fatalf("grace>0 must gate on created_at buffer at $5, got:\n%s", q)
	}
	if !strings.Contains(q, "se.event_type = 'semantic_attack' AND se.severity = ANY($3::text[])") {
		t.Fatalf("semantic_attack floor via $3 must persist with grace, got:\n%s", q)
	}
	for _, want := range []string{"se.alerted_at IS NULL", "se.severity = ANY($2::text[])", "ORDER BY se.created_at ASC, se.id ASC", "LIMIT LEAST($1::bigint, $7::bigint)", "oldest AS", "LIMIT $1::bigint"} {
		if !strings.Contains(q, want) {
			t.Fatalf("grace query shape lost %q:\n%s", want, q)
		}
	}
	if !strings.Contains(q, "COALESCE(se.matched_summary->>'review_state', '') = 'review_pending'") || !strings.Contains(q, "$4::bigint") {
		t.Fatalf("query must skip recent review_pending rows without starving later rows:\n%s", q)
	}
}

func TestListUnalertedQuery_ReservesRealtimeAndOldestCapacity(t *testing.T) {
	q := listUnalertedQuery(0)
	for _, want := range []string{
		"WITH recent AS",
		"se.created_at >= NOW() - ($5::bigint * INTERVAL '1 second')",
		"WHEN 'critical' THEN 0",
		"WHEN se.event_type IN ('security_check', 'semantic_attack') THEN 0",
		"LIMIT LEAST($1::bigint, $6::bigint)",
		"oldest AS",
		"LIMIT $1::bigint",
		"ORDER BY queue_priority ASC, created_at ASC, id ASC",
	} {
		if !strings.Contains(q, want) {
			t.Fatalf("dual-lane query lost %q:\n%s", want, q)
		}
	}
}

func TestListUnalertedQuery_ReviewPendingFilterIsNullSafe(t *testing.T) {
	q := listUnalertedQuery(0)
	want := "COALESCE(se.matched_summary->>'review_state', '') = 'review_pending'"
	if !strings.Contains(q, want) {
		t.Fatalf("events without review_state must remain eligible, query lost %q:\n%s", want, q)
	}
}

func TestListUnalertedQuery_GraceKeepsRealtimeParameterOrder(t *testing.T) {
	q := listUnalertedQuery(300)
	for _, want := range []string{
		"se.created_at < NOW() - ($5::bigint * INTERVAL '1 second')",
		"se.created_at >= NOW() - ($6::bigint * INTERVAL '1 second')",
		"LIMIT LEAST($1::bigint, $7::bigint)",
	} {
		if !strings.Contains(q, want) {
			t.Fatalf("grace dual-lane query lost %q:\n%s", want, q)
		}
	}
}

func TestSecEventRealtimeLaneDefaults(t *testing.T) {
	if secEventRealtimeWindowSeconds != 15*60 {
		t.Fatalf("realtime window=%d want 900", secEventRealtimeWindowSeconds)
	}
	if secEventRealtimeQuota != 50 {
		t.Fatalf("realtime quota=%d want 50", secEventRealtimeQuota)
	}
}
