package repository

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestForwardProxyAccessSummaryProviderFacetUsesSameDirectionAsList(t *testing.T) {
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
	tenantID := fmt.Sprintf("tenant_provider_facet_%d", suffix)
	// db.Close() 放 t.Cleanup 末尾：defer 会先于 t.Cleanup 执行，先关池会让 DELETE 静默失败。
	t.Cleanup(func() {
		for _, stmt := range []string{
			"DELETE FROM request_logs WHERE tenant_id = $1",
			"DELETE FROM tenants WHERE id = $1",
		} {
			if _, err := db.Exec(ctx, stmt, tenantID); err != nil {
				t.Logf("cleanup %s (%q): %v", tenantID, stmt, err)
			}
		}
		db.Close()
	})

	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $2, 'enterprise', 'active', TRUE)`, tenantID, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	insertRequest := func(requestID, direction, provider string) {
		t.Helper()
		proxyMode := direction
		if direction == "reverse" {
			proxyMode = "reverse"
		}
		_, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, endpoint_type, request_status,
				proxy_mode, proxy_target_host, proxy_target_path, proxy_method,
				proxy_access_type, proxy_access_type_resolved, proxy_provider, proxy_product, proxy_tls_inspected,
				proxy_content_retained, proxy_retention_level, risk_state, created_at
			)
			VALUES ($1, $1, $2, 'proxy', 'success', $3, $4, '/v1/chat/completions', 'POST',
				'llm', 'llm', $5, $5, true, true, 'content', 'normal', $6)
		`, requestID, tenantID, proxyMode, provider+".example.test", provider, time.Now().UTC())
		if err != nil {
			t.Fatalf("insert request %s: %v", requestID, err)
		}
	}

	insertRequest(fmt.Sprintf("req_forward_openai_%d", suffix), "forward", "openai")
	insertRequest(fmt.Sprintf("req_forward_openai_2_%d", suffix), "forward", "openai")
	insertRequest(fmt.Sprintf("req_forward_deepseek_%d", suffix), "forward", "deepseek")
	insertRequest(fmt.Sprintf("req_reverse_openai_%d", suffix), "reverse", "openai")
	insertRequest(fmt.Sprintf("req_reverse_tencent_%d", suffix), "reverse", "tencent")

	repo := NewRequestLogRepository(db)
	records, total, err := repo.ListForwardProxyAccess(ctx, tenantID, ForwardProxyAccessFilter{Direction: "forward", Limit: 100})
	if err != nil {
		t.Fatalf("list forward access: %v", err)
	}
	summary, err := repo.GetForwardProxyAccessSummary(ctx, tenantID, ForwardProxyAccessFilter{Direction: "forward"})
	if err != nil {
		t.Fatalf("summary forward access: %v", err)
	}
	if total != 3 || len(records) != 3 || summary.Total != 3 {
		t.Fatalf("forward list and summary should use same direction where, list total=%d records=%d summary=%+v", total, len(records), summary)
	}
	gotProviders := map[string]int{}
	for _, item := range summary.TopProviders {
		gotProviders[item.Name] = item.Count
	}
	if gotProviders["openai"] != 2 || gotProviders["deepseek"] != 1 {
		t.Fatalf("unexpected forward provider facet: %+v", summary.TopProviders)
	}
	if _, ok := gotProviders["tencent"]; ok {
		t.Fatalf("reverse-only provider leaked into forward facet: %+v", summary.TopProviders)
	}
}

func TestForwardProxyAccessSummaryUsesPublicModelNameAndAgentCounts(t *testing.T) {
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
	tenantID := fmt.Sprintf("tenant_agent_summary_%d", suffix)
	providerID := fmt.Sprintf("provider_agent_summary_%d", suffix)
	modelID := fmt.Sprintf("model_internal_demo_%d", suffix)
	t.Cleanup(func() {
		for _, cleanup := range []struct {
			stmt string
			arg  string
		}{
			{"DELETE FROM request_logs WHERE tenant_id = $1", tenantID},
			{"DELETE FROM models WHERE id = $1", modelID},
			{"DELETE FROM providers WHERE id = $1", providerID},
			{"DELETE FROM tenants WHERE id = $1", tenantID},
		} {
			if _, cleanupErr := db.Exec(ctx, cleanup.stmt, cleanup.arg); cleanupErr != nil {
				t.Logf("cleanup %q: %v", cleanup.stmt, cleanupErr)
			}
		}
		db.Close()
	})
	if _, err := db.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO providers (id, tenant_id, name, provider_type, status) VALUES ($1, $2, '测试供应商', 'openai', 'active')`, providerID, tenantID); err != nil {
		t.Fatalf("insert provider: %v", err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO models (id, provider_id, model_name, model_label, status) VALUES ($1, $2, 'gpt-5.5', 'GPT-5.5', 'active')`, modelID, providerID); err != nil {
		t.Fatalf("insert model: %v", err)
	}
	insertRequest := func(index int, agentType string) {
		t.Helper()
		requestID := fmt.Sprintf("req_agent_summary_%d_%d", suffix, index)
		if _, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, provider_id, model_id, endpoint_type,
				request_status, proxy_mode, proxy_target_host, proxy_access_type_resolved, agent_type, risk_state, created_at
			) VALUES ($1, $1, $2, $3, $4, 'anthropic_messages', 'success', 'chat_completion', $5, 'llm', NULLIF($6, ''), 'normal', $7)
		`, requestID, tenantID, providerID, modelID, modelID, agentType, time.Now().UTC()); err != nil {
			t.Fatalf("insert request: %v", err)
		}
	}
	insertRequest(1, "claude-code")
	insertRequest(2, "agent-tool-call")
	insertRequest(3, "")
	orphanTarget := fmt.Sprintf("model_orphaned_%d", suffix)
	orphanRequestID := fmt.Sprintf("req_agent_summary_orphan_%d", suffix)
	if _, err := db.Exec(ctx, `
		INSERT INTO request_logs (
			id, request_id, tenant_id, endpoint_type, request_status, proxy_mode,
			proxy_target_host, proxy_access_type_resolved, risk_state, created_at
		) VALUES ($1, $1, $2, 'anthropic_messages', 'success', 'chat_completion', $3, 'llm', 'normal', $4)
	`, orphanRequestID, tenantID, orphanTarget, time.Now().UTC()); err != nil {
		t.Fatalf("insert orphaned internal target: %v", err)
	}

	repo := NewRequestLogRepository(db)
	records, _, err := repo.ListForwardProxyAccess(ctx, tenantID, ForwardProxyAccessFilter{Limit: 10})
	if err != nil {
		t.Fatalf("list access: %v", err)
	}
	summary, err := repo.GetForwardProxyAccessSummary(ctx, tenantID, ForwardProxyAccessFilter{})
	if err != nil {
		t.Fatalf("summarize access: %v", err)
	}
	if summary.AgentRequestCount != 2 || summary.IdentifiedAgentCount != 1 || summary.UnidentifiedAgentCount != 1 {
		t.Fatalf("unexpected agent counts: %+v", summary)
	}
	if summary.UniqueModelCount != 1 {
		t.Fatalf("public model labels should collapse to one unique target, got %+v", summary)
	}
	for _, target := range summary.TopTargets {
		if target.Name == modelID {
			t.Fatalf("internal model id leaked through target host: %+v", summary.TopTargets)
		}
	}
	if len(summary.TopTargets) != 1 || summary.TopTargets[0].Name != "GPT-5.5" || summary.TopTargets[0].Count != 3 {
		t.Fatalf("target ranking must contain public targets only: %+v", summary.TopTargets)
	}
	if len(summary.TopAgents) != 2 {
		t.Fatalf("unexpected top agents: %+v", summary.TopAgents)
	}
	if len(records) != 4 {
		t.Fatalf("public model label not returned: %+v", records)
	}
	publicLabelCount := 0
	for _, record := range records {
		if record.TargetHost == modelID || record.TargetHost == orphanTarget {
			t.Fatalf("internal model id leaked: %+v", record)
		}
		if record.TargetHost == "GPT-5.5" {
			publicLabelCount++
		}
	}
	if publicLabelCount != 3 {
		t.Fatalf("expected three resolved public model labels, got %d in %+v", publicLabelCount, records)
	}
}
