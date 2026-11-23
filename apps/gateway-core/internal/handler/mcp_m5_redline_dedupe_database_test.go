package handler

// M-5（Postgres）：occurrence SQL 在真实库里要能执行（占位符类型推断、表与约束），且折叠计数准确、幂等。
import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/agentguard"
)

func TestM5_RedlineDedupeAgainstRealPostgres(t *testing.T) {
	dsn := os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is required; use disposable PostgreSQL")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	tenant := fmt.Sprintf("f_m5_%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, "DELETE FROM security_event_occurrences WHERE tenant_id=$1", tenant)
		_, _ = pool.Exec(ctx, "DELETE FROM security_events WHERE tenant_id=$1", tenant)
		_, _ = pool.Exec(ctx, "DELETE FROM request_logs WHERE tenant_id=$1", tenant)
		_, _ = pool.Exec(ctx, "DELETE FROM projects WHERE tenant_id=$1", tenant)
		_, _ = pool.Exec(ctx, "DELETE FROM tenants WHERE id=$1", tenant)
		pool.Close()
	})
	if _, err := pool.Exec(ctx, `INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO projects(id,tenant_id,name) VALUES($1,$2,$1) ON CONFLICT DO NOTHING`, defaultMCPProjectID, tenant); err != nil {
		t.Logf("projects 预置: %v（若默认项目已由迁移创建可忽略）", err)
	}
	rec := newMCPProxyAuditRecorder(pool)
	rec.redlineDedupe = newMCPRedlineEventDedupe(10 * time.Minute)

	d := mcpToolCallDecision{Qualified: "demo__echo", MCPServerID: "srv1", Decision: agentguard.Decision{
		RawDecision: agentguard.DecisionAudit, EffectiveDecision: agentguard.DecisionAudit,
		Evidence: []agentguard.Evidence{{RuleID: "mcp_redline_pii", Category: "mcp_redline"}},
	}}
	const n = 30
	for i := 0; i < n; i++ {
		r := mcpBlockRecord()
		r.TenantID, r.ProjectID = tenant, defaultMCPProjectID
		r.RequestID = fmt.Sprintf("req_m5_%d_%d", time.Now().UnixNano(), i)
		if err := rec.writeMCPProxyAuditTx(ctx, r, []mcpToolCallDecision{d}, true); err != nil {
			t.Fatalf("第 %d 次写入失败: %v", i, err)
		}
	}
	var events, occurrences int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_events WHERE tenant_id=$1`, tenant).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM security_event_occurrences WHERE tenant_id=$1`, tenant).Scan(&occurrences); err != nil {
		t.Fatal(err)
	}
	if events != 1 || occurrences != n-1 {
		t.Fatalf("%d 次相同红线命中应折叠为 1 条完整事件 + %d 条 occurrence，实际 events=%d occurrences=%d", n, n-1, events, occurrences)
	}
	var source string
	if err := pool.QueryRow(ctx, `SELECT matched_summary->>'source' FROM security_events WHERE tenant_id=$1`, tenant).Scan(&source); err != nil || source != "gateway_mcp" {
		t.Fatalf("代表事件 source 必须是 gateway_mcp: %q %v", source, err)
	}
}
