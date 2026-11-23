package repository

import (
	"strings"
	"testing"
	"time"
)

func TestBuildPortalCallRecordQueriesEnforcesTenantUserAndPrivacyBoundary(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	query, args, countQuery, countArgs := buildPortalCallRecordQueries(PortalCallRecordFilter{
		TenantID:  "tenant-a",
		UserID:    "user-a",
		StartTime: start,
		Limit:     50,
	})

	for _, fragment := range []string{
		"rl.tenant_id = $1",
		"rl.user_id = $2",
		"rl.created_at >= $3",
		"COALESCE(rl.endpoint_type, '') <> 'proxy'",
		"COALESCE(rl.request_status, '') NOT IN ('', 'received', 'in_progress')",
		"LIMIT $4",
		"se.tenant_id = rl.tenant_id",
		"se.request_id = rl.request_id",
		"LEFT JOIN billing_reservations br ON br.tenant_id = rl.tenant_id AND br.request_id = rl.request_id",
		"LEFT JOIN billing_charge_records bc ON bc.tenant_id = rl.tenant_id AND bc.request_id = rl.request_id",
		"LEFT JOIN billing_usage_facts buf ON buf.tenant_id = rl.tenant_id AND buf.request_id = rl.request_id",
		billingAmountSQL,
		billingCurrencySQL,
		billingStateSQL,
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("query missing %q:\n%s", fragment, query)
		}
	}
	for _, forbidden := range []string{
		"content_logs",
		"access_content_logs",
		"provider_credentials",
		"secret_ciphertext",
		"billing_wallets",
		"billing_model_prices",
		"billing_ledger_entries",
	} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("privacy boundary: query must not read %q:\n%s", forbidden, query)
		}
	}
	if len(args) != 4 ||
		args[0] != "tenant-a" ||
		args[1] != "user-a" ||
		!args[2].(time.Time).Equal(start) ||
		args[3] != 50 {
		t.Fatalf("unexpected query args: %#v", args)
	}
	if !strings.Contains(countQuery, "rl.tenant_id = $1") ||
		!strings.Contains(countQuery, "rl.user_id = $2") ||
		!strings.Contains(countQuery, "rl.created_at >= $3") ||
		!strings.Contains(countQuery, "COALESCE(rl.endpoint_type, '') <> 'proxy'") ||
		!strings.Contains(countQuery, "COALESCE(rl.request_status, '') NOT IN ('', 'received', 'in_progress')") {
		t.Fatalf("count query must use the same isolation and completion filters:\n%s", countQuery)
	}
	if len(countArgs) != 3 ||
		countArgs[0] != "tenant-a" ||
		countArgs[1] != "user-a" ||
		!countArgs[2].(time.Time).Equal(start) {
		t.Fatalf("unexpected count args: %#v", countArgs)
	}
}

func TestBuildPortalCallRecordQueriesUsesStableCursorAnchor(t *testing.T) {
	before := time.Date(2026, 8, 15, 12, 30, 0, 123, time.UTC)
	filter := PortalCallRecordFilter{
		TenantID:        "tenant-a",
		UserID:          "user-a",
		StartTime:       time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC),
		BeforeCreatedAt: before,
		BeforeRequestID: "req-anchor",
		Limit:           51,
	}

	query, args, _, _ := buildPortalCallRecordQueries(filter)
	if !strings.Contains(query, "(rl.created_at, rl.request_id) < ($4, $5)") {
		t.Fatalf("query missing composite cursor boundary:\n%s", query)
	}
	if !strings.Contains(query, "LIMIT $6") || strings.Contains(query, "OFFSET") {
		t.Fatalf("cursor query must not use offset pagination:\n%s", query)
	}
	if len(args) != 6 || !args[3].(time.Time).Equal(before) || args[4] != "req-anchor" || args[5] != 51 {
		t.Fatalf("unexpected cursor query args: %#v", args)
	}
}

func TestBuildPortalCallRecordQueriesReturnsOnlyOverviewColumns(t *testing.T) {
	query, _, _, _ := buildPortalCallRecordQueries(PortalCallRecordFilter{
		TenantID: "tenant-a",
		UserID:   "user-a",
		Limit:    50,
	})

	for _, fragment := range []string{
		"rl.request_id",
		"rl.created_at",
		"m.model_label",
		"m.model_name",
		"rl.request_status",
		"rl.upstream_status_code",
		"rl.input_tokens",
		"rl.output_tokens",
		"GREATEST(COALESCE(buf.cached_input_tokens, 0), 0) AS cached_input_tokens",
		"GREATEST(COALESCE(buf.cache_write_input_tokens, 0), 0) AS cache_write_input_tokens",
		"rl.latency_ms",
		"rl.agent_type",
		"rl.endpoint_type",
		"NULLIF(rl.input_audit_result->>'action', '')",
		"NULLIF(rl.input_audit_result->>'action_taken', '')",
		"NULLIF(rl.output_audit_result->>'action', '')",
		"NULLIF(rl.output_audit_result->>'action_taken', '')",
		"'未识别模型'",
		"ORDER BY rl.created_at DESC, rl.request_id DESC",
	} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("query missing overview column %q:\n%s", fragment, query)
		}
	}
	if strings.Contains(query, "rl.session_id") {
		t.Fatalf("privacy boundary: query must not read session identifiers:\n%s", query)
	}
	if strings.Contains(query, "NULLIF(rl.model_id") {
		t.Fatalf("privacy boundary: query must not expose internal model identifiers:\n%s", query)
	}
}

func TestPortalCallRecordsSummaryWindowAndIsolation(t *testing.T) {
	query, args := buildPortalCallRecordsSummaryQuery(PortalCallRecordFilter{TenantID: "tenant-a", UserID: "user-a", StartTime: time.Unix(100, 0), BeforeCreatedAt: time.Now(), BeforeRequestID: "cursor", Limit: 1})
	for _, fragment := range []string{"rl.tenant_id = $1", "rl.user_id = $2", "rl.created_at >= $3", "user_history", "AVG(rl.latency_ms)", "NULLIF(COUNT(*),0)"} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("汇总缺少隔离/口径: %s", fragment)
		}
	}
	for _, fragment := range []string{"LIMIT", "OFFSET", "upstream", "security_events", "timing", "rl.request_id) <"} {
		if strings.Contains(query, fragment) {
			t.Fatalf("汇总越界读取: %s", fragment)
		}
	}
	if len(args) != 3 || args[0] != "tenant-a" || args[1] != "user-a" {
		t.Fatalf("汇总参数错误: %+v", args)
	}
}

func TestBuildPortalCallRecordQueriesRequestIDKeepsTenantUserScope(t *testing.T) {
	start := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	reqID := "req_0123abcd-0123-abcd-0123-0123abcd4567"
	query, args, countQuery, countArgs := buildPortalCallRecordQueries(PortalCallRecordFilter{
		TenantID: "tenant-a", UserID: "user-a", StartTime: start, RequestID: reqID, Limit: 2,
	})
	for _, fragment := range []string{"rl.tenant_id = $1", "rl.user_id = $2", "AND rl.request_id = $4", "LIMIT $5"} {
		if !strings.Contains(query, fragment) {
			t.Fatalf("query missing %q:\n%s", fragment, query)
		}
	}
	if len(args) != 5 || args[3] != reqID || args[0] != "tenant-a" || args[1] != "user-a" {
		t.Fatalf("unexpected args: %#v", args)
	}
	if strings.Contains(countQuery, "request_id = $") || len(countArgs) != 3 {
		t.Fatalf("count/summary must not be narrowed by request id: %s %#v", countQuery, countArgs)
	}
}
