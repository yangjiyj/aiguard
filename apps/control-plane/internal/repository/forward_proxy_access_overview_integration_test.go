package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestForwardProxyAccessSummaryBuildsRetentionOverview(t *testing.T) {
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
	tenantID := fmt.Sprintf("tenant_retention_overview_%d", suffix)
	otherTenantID := fmt.Sprintf("tenant_retention_overview_other_%d", suffix)
	projectID := fmt.Sprintf("project_retention_overview_%d", suffix)
	otherProjectID := fmt.Sprintf("project_retention_overview_other_%d", suffix)
	providerID := fmt.Sprintf("provider_retention_overview_%d", suffix)
	modelID := fmt.Sprintf("model_retention_overview_%d", suffix)
	completeID := fmt.Sprintf("ov_complete_%d", suffix)
	requestOnlyID := fmt.Sprintf("ov_request_%d", suffix)
	responseOnlyID := fmt.Sprintf("ov_response_%d", suffix)
	metadataOnlyID := fmt.Sprintf("ov_metadata_%d", suffix)
	otherRequestID := fmt.Sprintf("ov_other_%d", suffix)

	t.Cleanup(func() {
		for _, cleanup := range []struct {
			query string
			args  []interface{}
		}{
			{"DELETE FROM security_events WHERE tenant_id = ANY($1)", []interface{}{[]string{tenantID, otherTenantID}}},
			{"DELETE FROM access_content_logs WHERE tenant_id = ANY($1)", []interface{}{[]string{tenantID, otherTenantID}}},
			{"DELETE FROM content_logs WHERE tenant_id = ANY($1)", []interface{}{[]string{tenantID, otherTenantID}}},
			{"DELETE FROM request_logs WHERE tenant_id = ANY($1)", []interface{}{[]string{tenantID, otherTenantID}}},
			{"DELETE FROM models WHERE id = $1", []interface{}{modelID}},
			{"DELETE FROM providers WHERE id = $1", []interface{}{providerID}},
			{"DELETE FROM projects WHERE id = ANY($1)", []interface{}{[]string{projectID, otherProjectID}}},
			{"DELETE FROM tenants WHERE id = ANY($1)", []interface{}{[]string{tenantID, otherTenantID}}},
		} {
			if _, cleanupErr := db.Exec(ctx, cleanup.query, cleanup.args...); cleanupErr != nil {
				t.Logf("cleanup %q: %v", cleanup.query, cleanupErr)
			}
		}
		db.Close()
	})

	for _, tenant := range []string{tenantID, otherTenantID} {
		if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`, tenant); err != nil {
			t.Fatalf("insert tenant %s: %v", tenant, err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO projects (id, tenant_id, name, status) VALUES ($1, $2, $1, 'active'), ($3, $4, $3, 'active')`, projectID, tenantID, otherProjectID, otherTenantID); err != nil {
		t.Fatalf("insert projects: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO providers (id, tenant_id, name, provider_type, status) VALUES ($1, $2, '留证测试供应商', 'openai', 'active')`, providerID, tenantID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models (id, provider_id, model_name, model_label, status) VALUES ($1, $2, 'public-model', '公开模型', 'active')`, modelID, providerID); err != nil {
		t.Fatalf("insert model: %v", err)
	}

	base := time.Now().UTC().Add(-30 * time.Minute)
	insertRequest := func(requestID, requestTenant, mode, targetHost, requestModelID, riskState string) {
		t.Helper()
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, model_id, endpoint_type, request_status,
				proxy_mode, proxy_target_host, proxy_target_path, proxy_method,
				proxy_access_type, proxy_access_type_resolved, proxy_provider, proxy_product,
				proxy_content_retained, proxy_retention_level, risk_state, has_retained_content, created_at
			) VALUES ($1, $1, $2, NULLIF($3, ''), 'proxy', 'success',
				$4, NULLIF($5, ''), '/v1/chat/completions', 'POST',
				'llm', 'llm', 'third_party', 'model', true, 'content', $6, true, $7)
		`, requestID, requestTenant, requestModelID, mode, targetHost, riskState, base); err != nil {
			t.Fatalf("insert request %s: %v", requestID, err)
		}
	}
	insertRequest(completeID, tenantID, "forward", "api.public.example", "", "normal")
	insertRequest(requestOnlyID, tenantID, "chat_completion", "api.public.example", "", "risk")
	insertRequest(responseOnlyID, tenantID, "chat_completion", "", modelID, "blocked")
	insertRequest(metadataOnlyID, tenantID, "forward", "", modelID, "normal")
	insertRequest(otherRequestID, otherTenantID, "forward", "leak.other.example", "", "risk")

	insertAccessContent := func(requestID, requestTenant, requestContent, responseContent, fileJSON string) {
		t.Helper()
		if _, err := db.Exec(ctx, `
			INSERT INTO access_content_logs (
				id, request_id, tenant_id, request_content_redacted, response_content_redacted,
				file_metadata_json, tool_call_metadata_json, created_at
			) VALUES ($1, $2, $3, $4, $5, $6::jsonb, '[]'::jsonb, $7)
		`, "acl_"+requestID, requestID, requestTenant, requestContent, responseContent, fileJSON, base); err != nil {
			t.Fatalf("insert access content %s: %v", requestID, err)
		}
	}
	insertAccessContent(completeID, tenantID, "请求", "响应", "[]")
	insertAccessContent(metadataOnlyID, tenantID, "", "", `[{"file_name":"evidence.txt"}]`)
	insertAccessContent(otherRequestID, otherTenantID, "跨租户请求", "跨租户响应", "[]")
	if _, err := db.Exec(ctx, `
		INSERT INTO content_logs (id, request_id, tenant_id, session_id, role, content, tokens, created_at)
		VALUES ($1, $2, $3, 'overview', 'developer', '开发者约束', 1, $5),
		       ($4, $6, $3, 'overview', 'assistant', '仅响应', 1, $5)
	`, fmt.Sprintf("cl_request_%d", suffix), requestOnlyID, tenantID, fmt.Sprintf("cl_response_%d", suffix), base, responseOnlyID); err != nil {
		t.Fatalf("insert reverse content: %v", err)
	}

	insertEvent := func(id, requestID, eventTenant, eventProject, eventType, category, findingCategory string) {
		t.Helper()
		matched := fmt.Sprintf(`{"category":%q,"findings":[{"category":%q,"rule_id":%q}]}`, category, findingCategory, findingCategory)
		if _, err := db.Exec(ctx, `
			INSERT INTO security_events (
				id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, created_at
			) VALUES ($1, $2, $3, $4, $5, 'high', 'audit', $6::jsonb, $7)
		`, id, requestID, eventTenant, eventProject, eventType, matched, base); err != nil {
			t.Fatalf("insert event %s: %v", id, err)
		}
	}
	insertEvent(fmt.Sprintf("evt_secret_a_%d", suffix), requestOnlyID, tenantID, projectID, "security_check", "secret", "secret")
	insertEvent(fmt.Sprintf("evt_secret_dup_%d", suffix), requestOnlyID, tenantID, projectID, "security_check", "secret", "secret")
	insertEvent(fmt.Sprintf("evt_secret_b_%d", suffix), responseOnlyID, tenantID, projectID, "security_check", "secret", "secret")
	// 顶层 category 只保存首条 finding；排行必须展开 findings[] 才能看到后续 ssrf。
	insertEvent(fmt.Sprintf("evt_ssrf_%d", suffix), responseOnlyID, tenantID, projectID, "security_check", "secret", "ssrf")
	insertEvent(fmt.Sprintf("evt_ignored_%d", suffix), completeID, tenantID, projectID, "security_check", "agent_claude_code", "agent_claude_code")
	if _, err := db.Exec(ctx, `
		INSERT INTO security_events (
			id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, created_at
		) VALUES ($1, $2, $3, $4, 'security_check', 'high', 'audit', $5::jsonb, $6)
	`, fmt.Sprintf("evt_mixed_%d", suffix), responseOnlyID, tenantID, projectID,
		`{"category":"agent_claude_code","stage":"input","findings":[{"category":"agent_claude_code","rule_id":"agent_claude_code"},{"category":"secret","rule_id":"secret"}]}`,
		base); err != nil {
		t.Fatalf("insert mixed findings event: %v", err)
	}
	insertEvent(fmt.Sprintf("evt_other_%d", suffix), otherRequestID, otherTenantID, otherProjectID, "security_check", "cross_tenant", "cross_tenant")
	insertEvent(fmt.Sprintf("evt_cross_request_%d", suffix), responseOnlyID, otherTenantID, otherProjectID, "security_check", "cross_tenant_attention", "cross_tenant_attention")

	repo := NewRequestLogRepository(db)
	summary, err := repo.GetForwardProxyAccessSummary(ctx, tenantID, ForwardProxyAccessFilter{
		ContentOnly: true,
		StartTime:   base.Add(-time.Hour),
		EndTime:     base.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("get retention overview: %v", err)
	}
	if summary.Total != 4 || summary.RetainedContentCount != 4 {
		t.Fatalf("filtered retention denominator mismatch: %+v", summary)
	}
	if summary.UniqueModelCount != 2 {
		t.Fatalf("unique public model count=%d want 2", summary.UniqueModelCount)
	}
	quality := summary.EvidenceQuality
	if quality.CompleteCount != 1 || quality.RequestOnlyCount != 1 || quality.ResponseOnlyCount != 1 || quality.MetadataOnlyCount != 1 {
		t.Fatalf("unexpected evidence quality: %+v", quality)
	}
	if quality.CompleteCount+quality.RequestOnlyCount+quality.ResponseOnlyCount+quality.MetadataOnlyCount != summary.Total {
		t.Fatalf("evidence quality must partition total: quality=%+v total=%d", quality, summary.Total)
	}
	if len(summary.Timeline) != 1 {
		t.Fatalf("expected one populated hourly bucket, got %+v", summary.Timeline)
	}
	point := summary.Timeline[0]
	if point.TotalCount != 4 || point.NormalCount != 2 || point.RiskCount != 1 || point.BlockedCount != 1 {
		t.Fatalf("unexpected timeline point: %+v", point)
	}
	categories := map[string]int{}
	for _, item := range summary.TopRiskCategories {
		categories[item.Name] = item.Count
	}
	if categories["secret"] != 2 || categories["ssrf"] != 1 {
		t.Fatalf("risk categories must count distinct affected requests: %+v", summary.TopRiskCategories)
	}
	for _, forbidden := range []string{"agent_claude_code", "cross_tenant"} {
		if _, ok := categories[forbidden]; ok {
			t.Fatalf("ignored or cross-tenant category leaked into overview: %+v", summary.TopRiskCategories)
		}
	}

	attentionSummary, err := repo.GetForwardProxyAccessSummary(ctx, tenantID, ForwardProxyAccessFilter{
		RiskState:   "attention",
		ContentOnly: true,
		StartTime:   base.Add(-time.Hour),
		EndTime:     base.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("get attention retention overview: %v", err)
	}
	for _, category := range attentionSummary.TopRiskCategories {
		if category.Name == "cross_tenant_attention" {
			t.Fatalf("cross-tenant attention category leaked into overview: %+v", attentionSummary.TopRiskCategories)
		}
	}
}
