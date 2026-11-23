package repository

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func platformEgressTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is required; use disposable PostgreSQL")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

// 挂靠的请求日志直接是 completed：写一条平台出站拒绝后，审计流水线的待处理数不变。
// 合流（批次 3/4）：endpoint_type=platform_egress 的自建请求日志不算业务请求（NonBusinessEndpointTypes），
// 审计流水线的请求数也不变；completed 直接查这条请求日志。
func TestPlatformEgressEventDoesNotLeavePendingAuditOnRealPostgres(t *testing.T) {
	db := platformEgressTestPool(t)
	ctx := context.Background()
	stats := NewServiceHealthReadModelRepository(db)
	before, err := stats.AuditPipelineStats(ctx, 24)
	if err != nil {
		t.Fatal(err)
	}
	eventID, err := RecordPlatformEgressDenied(ctx, db, "tenant_default", "", "notify_channel:webhook", "pending-check.example")
	if err != nil || eventID == "" {
		t.Fatalf("event=%q err=%v", eventID, err)
	}
	after, err := stats.AuditPipelineStats(ctx, 24)
	if err != nil {
		t.Fatal(err)
	}
	if after.PendingCount != before.PendingCount || after.RequestCount != before.RequestCount {
		t.Fatalf("pending %d -> %d, requests %d -> %d", before.PendingCount, after.PendingCount, before.RequestCount, after.RequestCount)
	}
	var outcome, endpoint string
	if err := db.QueryRow(ctx, `SELECT rl.audit_outcome, rl.endpoint_type FROM security_events se
		JOIN request_logs rl ON rl.request_id = se.request_id WHERE se.id = $1`, eventID).Scan(&outcome, &endpoint); err != nil {
		t.Fatal(err)
	}
	if outcome != "completed" || endpoint != "platform_egress" {
		t.Fatalf("anchoring request log: audit_outcome=%q endpoint_type=%q", outcome, endpoint)
	}
}
