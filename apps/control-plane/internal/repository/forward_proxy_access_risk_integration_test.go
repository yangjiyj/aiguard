package repository

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestListForwardProxyAccessTreatsWeakAuditSignalsAsNormal(t *testing.T) {
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
	tenantID := fmt.Sprintf("tenant_weak_signal_%d", suffix)
	weakReq := fmt.Sprintf("req_weak_signal_%d", suffix)
	agentReq := fmt.Sprintf("req_agent_inventory_%d", suffix)
	strongReq := fmt.Sprintf("req_strong_signal_%d", suffix)

	// db.Close() 必须放在 t.Cleanup 末尾而非 defer：defer 在测试函数返回时先执行，
	// t.Cleanup 回调在其后运行，先 defer 关池会让下面所有 DELETE 静默失败、租户残留。
	t.Cleanup(func() {
		for _, stmt := range []string{
			"DELETE FROM security_events WHERE tenant_id = $1",
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
	insertRequest := func(requestID, host string) {
		t.Helper()
		_, err := db.Exec(ctx, `
			INSERT INTO request_logs (
				id, request_id, tenant_id, endpoint_type, request_status,
				proxy_mode, proxy_target_host, proxy_target_path, proxy_method,
				proxy_access_type, proxy_access_type_resolved, proxy_provider, proxy_product, proxy_tls_inspected,
				proxy_content_retained, proxy_retention_level, created_at
			)
			VALUES ($1, $1, $2, 'proxy', 'success', 'forward', $3, '/v1/chat/completions', 'POST', 'ai_ide', 'ai_ide', 'tencent', 'WorkBuddy', true, true, 'content', $4)
		`, requestID, tenantID, host, time.Now().UTC())
		if err != nil {
			t.Fatalf("insert request %s: %v", requestID, err)
		}
	}
	insertEvent := func(id, requestID, severity, action, matched string) {
		t.Helper()
		_, err := db.Exec(ctx, `
			INSERT INTO security_events (id, request_id, tenant_id, project_id, event_type, severity, action_taken, matched_summary, created_at)
			VALUES ($1, $2, $3, 'project_default', 'security_check', $4, $5, $6::jsonb, $7)
		`, id, requestID, tenantID, severity, action, matched, time.Now().UTC())
		if err != nil {
			t.Fatalf("insert event %s: %v", id, err)
		}
	}

	insertRequest(weakReq, "weak.tencent.local")
	insertEvent("evt_weak_"+fmt.Sprint(suffix), weakReq, "high", "security_audit_only", `{
		"findings":[{"type":"prompt_injection","category":"structured_template_injection","rule_id":"prompt_injection_template_injection","severity":"high"}]
	}`)

	insertRequest(agentReq, "telemetry.individual.githubcopilot.com")
	_, err = db.Exec(ctx, `
		UPDATE request_logs
		SET input_audit_result = $2::jsonb, proxy_provider = 'github', proxy_product = 'github_copilot'
		WHERE request_id = $1
	`, agentReq, `{
		"stage":"input",
		"provider":"github",
		"product":"github_copilot",
		"access_type":"ai_ide",
		"target_host":"telemetry.individual.githubcopilot.com",
		"findings":[{"type":"agent","category":"agent_github_copilot","rule_id":"agent_github_copilot","severity":"low","confidence":1}]
	}`)
	if err != nil {
		t.Fatalf("update agent inventory request: %v", err)
	}
	insertEvent("evt_agent_"+fmt.Sprint(suffix), agentReq, "medium", "audit", `{
		"stage":"input",
		"provider":"github",
		"product":"github_copilot",
		"access_type":"ai_ide",
		"target_host":"telemetry.individual.githubcopilot.com",
		"findings":[{"type":"agent","category":"agent_github_copilot","rule_id":"agent_github_copilot","severity":"low","confidence":1,"matched_text_preview":"git***lot"}]
	}`)

	insertRequest(strongReq, "strong.tencent.local")
	insertEvent("evt_strong_"+fmt.Sprint(suffix), strongReq, "high", "security_audit_only", `{
		"findings":[{"type":"secret","category":"aws_secret_key","rule_id":"secret_aws_secret_key","severity":"high"}]
	}`)

	// 列表的 risk_state/action_taken 读预计算列，生产由 worker(BackfillRiskColumns/
	// RefreshRecentRiskColumns)维护；夹具用同一套权威 SET 子句按租户回填。
	if _, err := db.Exec(ctx, fmt.Sprintf("UPDATE request_logs rl SET %s WHERE rl.tenant_id = $1", forwardProxyRiskColumnsSetClause()), tenantID); err != nil {
		t.Fatalf("backfill risk columns: %v", err)
	}

	repo := NewRequestLogRepository(db)
	weak, _, err := repo.ListForwardProxyAccess(ctx, tenantID, ForwardProxyAccessFilter{TargetHost: "weak.tencent.local", Limit: 10})
	if err != nil {
		t.Fatalf("list weak access: %v", err)
	}
	if len(weak) != 1 {
		t.Fatalf("expected one weak record, got %d", len(weak))
	}
	if weak[0].RiskState != "normal" || weak[0].ActionTaken != "allow" || len(weak[0].RiskReasons) != 0 || weak[0].SecurityEventCount != 0 {
		t.Fatalf("weak audit-only signal should not become customer-visible risk: %+v", weak[0])
	}

	agent, _, err := repo.ListForwardProxyAccess(ctx, tenantID, ForwardProxyAccessFilter{TargetHost: "telemetry.individual.githubcopilot.com", Limit: 10})
	if err != nil {
		t.Fatalf("list agent inventory access: %v", err)
	}
	if len(agent) != 1 {
		t.Fatalf("expected one agent inventory record, got %d", len(agent))
	}
	if agent[0].RiskState != "normal" || agent[0].ActionTaken != "allow" || len(agent[0].RiskReasons) != 0 || agent[0].SecurityEventCount != 0 {
		t.Fatalf("agent inventory-only signal should not become customer-visible risk: %+v", agent[0])
	}

	strong, _, err := repo.ListForwardProxyAccess(ctx, tenantID, ForwardProxyAccessFilter{TargetHost: "strong.tencent.local", Limit: 10})
	if err != nil {
		t.Fatalf("list strong access: %v", err)
	}
	if len(strong) != 1 {
		t.Fatalf("expected one strong record, got %d", len(strong))
	}
	if strong[0].RiskState != "risk" || strong[0].ActionTaken != "audit" || len(strong[0].RiskReasons) == 0 || strong[0].SecurityEventCount != 1 {
		t.Fatalf("strong signal should remain customer-visible risk: %+v", strong[0])
	}
}

func TestForwardProxyActionableAlertCountExpressionUsesAlertGroup(t *testing.T) {
	expr := forwardProxyEffectiveActionableAlertCountExpr()
	if !strings.Contains(expr, "alert_group_id IS NOT NULL") {
		t.Fatalf("actionable alert count must use the alert bridge group fact: %s", expr)
	}
}
