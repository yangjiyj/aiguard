package repository

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestForwardProxyKeywordSearchCanonicalSourcesAndFilters(t *testing.T) {
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
	tenantID := fmt.Sprintf("tenant_keyword_%d", suffix)
	projectID := fmt.Sprintf("project_keyword_%d", suffix)
	userID := fmt.Sprintf("user_keyword_%d", suffix)
	t.Cleanup(func() {
		for _, statement := range []struct {
			sql string
			arg string
		}{
			{"DELETE FROM audit_dispositions WHERE tenant_id = $1", tenantID},
			{"DELETE FROM content_logs WHERE tenant_id = $1", tenantID},
			{"DELETE FROM access_content_logs WHERE tenant_id = $1", tenantID},
			{"DELETE FROM request_logs WHERE tenant_id = $1", tenantID},
			{"DELETE FROM users WHERE id = $1", userID},
			{"DELETE FROM projects WHERE id = $1", projectID},
			{"DELETE FROM tenants WHERE id = $1", tenantID},
		} {
			if _, cleanupErr := db.Exec(ctx, statement.sql, statement.arg); cleanupErr != nil {
				t.Logf("cleanup %q: %v", statement.sql, cleanupErr)
			}
		}
		db.Close()
	})

	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name) VALUES ($1, $2, $1)`, projectID, tenantID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1, $2, '关键词归属用户', 'auditor', 'active')`, userID, tenantID); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	base := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	type requestPair struct {
		internal string
		external string
	}
	insertRequest := func(label string, minute int) requestPair {
		t.Helper()
		pair := requestPair{
			internal: fmt.Sprintf("rl_%s_%d", label, suffix),
			external: fmt.Sprintf("req_%s_%d", label, suffix),
		}
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, project_id, user_id, endpoint_type, request_status,
				proxy_mode, proxy_target_host, proxy_target_path, proxy_method,
				proxy_access_type, proxy_access_type_resolved, proxy_provider, proxy_product,
				proxy_tls_inspected, proxy_content_retained, proxy_retention_level,
				proxy_endpoint_kind, risk_state, has_retained_content, environment_scope, created_at
			) VALUES (
				$1, $2, $3, $4, $5, 'proxy', 'success',
				'chat_completion', 'api.deepseek.com', '/v1/chat/completions', 'POST',
				'llm', 'llm', 'deepseek', 'deepseek_api',
				TRUE, TRUE, 'content', 'chat', 'normal', TRUE, 'customer', $6
			)
		`, pair.internal, pair.external, tenantID, projectID, userID, base.Add(time.Duration(minute)*time.Minute)); err != nil {
			t.Fatalf("insert request %s: %v", label, err)
		}
		return pair
	}
	insertACL := func(pair requestPair, content string, minute int) {
		t.Helper()
		if _, err := db.Exec(ctx, `
			INSERT INTO access_content_logs (
				id, request_id, tenant_id, request_content_redacted, response_content_redacted,
				file_metadata_json, environment_scope, created_at
			) VALUES ($1, $2, $3, $4, '', '[]'::jsonb, 'customer', $5)
		`, "acl_"+pair.internal, pair.external, tenantID, content, base.Add(time.Duration(minute)*time.Minute)); err != nil {
			t.Fatalf("insert ACL %s: %v", pair.external, err)
		}
	}
	insertContent := func(pair requestPair, role, content string, minute int) {
		t.Helper()
		if _, err := db.Exec(ctx, `
			INSERT INTO content_logs (id, request_id, tenant_id, user_id, role, content, environment_scope, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, 'customer', $7)
		`, fmt.Sprintf("cl_%s_%s", role, pair.internal), pair.internal, tenantID, userID, role, content, base.Add(time.Duration(minute)*time.Minute)); err != nil {
			t.Fatalf("insert content %s/%s: %v", pair.external, role, err)
		}
	}

	aclOnly := insertRequest("acl_only", 1)
	contentOnly := insertRequest("content_only", 2)
	duplicate := insertRequest("duplicate", 3)
	systemOnly := insertRequest("system", 4)
	toolOnly := insertRequest("tool", 5)
	memoryOnly := insertRequest("memory", 6)
	insertACL(aclOnly, "retention-marker ACL-only", 1)
	insertContent(contentOnly, "user", "retention-marker content-only", 2)
	insertACL(duplicate, "retention-marker duplicate", 3)
	insertContent(duplicate, "assistant", "retention-marker duplicate", 3)
	insertContent(systemOnly, "system", "retention-marker system", 4)
	insertContent(toolOnly, "tool", "retention-marker tool", 5)
	insertContent(memoryOnly, "memory", "retention-marker memory", 6)
	if _, err := db.Exec(ctx, `
		INSERT INTO audit_dispositions (tenant_id, subject_type, subject_id, status)
		VALUES ($1, 'request', $2, 'resolved')
	`, tenantID, aclOnly.external); err != nil {
		t.Fatalf("insert disposition: %v", err)
	}

	repo := NewRequestLogRepository(db)
	filter := ForwardProxyAccessFilter{
		Keyword:          "retention-marker",
		ContentOnly:      true,
		Limit:            20,
		EnvironmentScope: "customer",
		StartTime:        base,
		EndTime:          base.Add(24 * time.Hour),
	}
	records, _, err := repo.ListForwardProxyAccess(ctx, tenantID, filter)
	if err != nil {
		t.Fatalf("search both content stores: %v", err)
	}
	got := make([]string, 0, len(records))
	for _, record := range records {
		got = append(got, record.RequestID)
	}
	sort.Strings(got)
	want := []string{aclOnly.external, contentOnly.external, duplicate.external}
	sort.Strings(want)
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("canonical keyword matches = %v, want %v", got, want)
	}

	for _, scope := range []string{"request", "response"} {
		scoped := filter
		scoped.KeywordScope = scope
		matches, _, err := repo.ListForwardProxyAccess(ctx, tenantID, scoped)
		if err != nil {
			t.Fatal(err)
		}
		expected := 3
		if scope == "response" {
			expected = 1
		}
		if len(matches) != expected {
			t.Fatalf("scope=%s got=%+v", scope, matches)
		}
		if scope == "response" && matches[0].RequestID != duplicate.external {
			t.Fatalf("response matched input: %+v", matches)
		}
		predicates, args := buildForwardProxyWhere(tenantID, scoped)
		var count int
		if err := db.QueryRow(ctx, "SELECT COUNT(*) FROM request_logs rl LEFT JOIN providers p ON p.id=rl.provider_id WHERE "+strings.Join(predicates, " AND "), args...).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != expected {
			t.Fatalf("generic scope=%s count=%d", scope, count)
		}
	}
	genericWhere, genericArgs := buildForwardProxyWhere(tenantID, filter)
	var genericCount int
	if err := db.QueryRow(ctx, "SELECT COUNT(*) FROM request_logs rl WHERE "+strings.Join(genericWhere, " AND "), genericArgs...).Scan(&genericCount); err != nil {
		t.Fatalf("run generic keyword predicate: %v", err)
	}
	if genericCount != 3 {
		t.Fatalf("generic canonical keyword predicate count = %d, want 3", genericCount)
	}
	probeFilter := filter
	probeFilter.Limit = 2
	probeFilter.ProbeHasMore = true
	probed, _, err := repo.ListForwardProxyAccess(ctx, tenantID, probeFilter)
	if err != nil {
		t.Fatalf("probe keyword next page: %v", err)
	}
	if len(probed) != 3 {
		t.Fatalf("limit+1 probe returned %d rows, want 3", len(probed))
	}

	filter.UserID = userID
	filter.Provider = "deepseek"
	filter.Disposition = "resolved"
	filter.SourceIP = "模型中转"
	filter.StartTime = base.Add(30 * time.Second)
	filter.EndTime = base.Add(90 * time.Second)
	records, _, err = repo.ListForwardProxyAccess(ctx, tenantID, filter)
	if err != nil {
		t.Fatalf("search combined filters: %v", err)
	}
	if len(records) != 1 || records[0].RequestID != aclOnly.external {
		t.Fatalf("combined filters returned %+v, want only %s", records, aclOnly.external)
	}
	if records[0].IdentityKind != "key_owner" || records[0].KeyOwner != "关键词归属用户" {
		t.Fatalf("key ownership identity = kind %q owner %q", records[0].IdentityKind, records[0].KeyOwner)
	}

	// Exercise the non-keyword projection too, so an identity column inserted in
	// the wrong scan position cannot hide behind the specialized search query.
	filter.Keyword = ""
	records, _, err = repo.ListForwardProxyAccess(ctx, tenantID, filter)
	if err != nil {
		t.Fatalf("list combined filters without keyword: %v", err)
	}
	if len(records) != 1 || records[0].RequestID != aclOnly.external || records[0].IdentityKind != "key_owner" {
		t.Fatalf("non-keyword identity projection returned %+v", records)
	}
	// The task path must use the same canonical stores, direction and bounds.
	if _, err := db.Exec(ctx, "UPDATE request_logs SET agent_type='openai-codex' WHERE tenant_id=$1", tenantID); err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"all", "request", "response"} {
		runFilter := ForwardProxyAccessFilter{Keyword: "retention-marker", KeywordScope: scope, ContentOnly: true, EnvironmentScope: "customer", StartTime: base, EndTime: base.Add(time.Hour), Limit: 20}
		runs, total, err := repo.ListEvidenceRuns(ctx, tenantID, "agent_tasks", runFilter)
		if err != nil {
			t.Fatal(err)
		}
		expected := 3
		if scope == "response" {
			expected = 1
		}
		if len(runs) != expected || total != expected {
			t.Fatalf("task scope=%s rows=%+v total=%d", scope, runs, total)
		}
		if scope == "response" && runs[0].RepresentativeRequestID != duplicate.external {
			t.Fatalf("task output search matched input: %+v", runs)
		}
		runFilter.Limit = 1
		runFilter.SkipTotal = true
		runFilter.ProbeHasMore = true
		page, pageTotal, err := repo.ListEvidenceRuns(ctx, tenantID, "agent_tasks", runFilter)
		if err != nil || len(page) != 1 || pageTotal != min(expected, 2) {
			t.Fatalf("task page rows=%+v total=%d err=%v", page, pageTotal, err)
		}
		runFilter.StartTime = base.Add(10 * time.Minute)
		outside, _, err := repo.ListEvidenceRuns(ctx, tenantID, "agent_tasks", runFilter)
		if err != nil || len(outside) != 0 {
			t.Fatalf("task time boundary rows=%+v err=%v", outside, err)
		}
		runFilter.StartTime = base
		isolated, _, err := repo.ListEvidenceRuns(ctx, "other-"+tenantID, "agent_tasks", runFilter)
		if err != nil || len(isolated) != 0 {
			t.Fatalf("task tenant boundary rows=%+v err=%v", isolated, err)
		}
	}

}
