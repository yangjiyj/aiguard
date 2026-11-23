package repository

import (
	"context"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 平台自身出站被拒的安全事件挂靠一条 platform_egress 请求日志。
func TestRecordPlatformEgressDeniedOnRealPostgres(t *testing.T) {
	dsn := os.Getenv("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL")
	if dsn == "" {
		t.Fatal("MCP_SUPPLY_CHAIN_TEST_DATABASE_URL is required; use disposable PostgreSQL")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status,is_test) VALUES('t_egress_evt','t','enterprise','active',true) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	// 事件挂在租户自己的项目上（没有项目的租户只打日志，见 TestPlatformEgressEventUsesTenantProjectOnRealPostgres）。
	if _, err := db.Exec(ctx, `INSERT INTO projects(id,tenant_id,name,code,status) VALUES('proj_t_egress_evt','t_egress_evt','默认应用','default','active') ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	id, err := RecordPlatformEgressDenied(ctx, db, "t_egress_evt", "", "notify_channel:webhook", "127.0.0.1")
	if err != nil || id == "" {
		t.Fatalf("record: id=%q err=%v", id, err)
	}
	var source, eventType, action string
	if err := db.QueryRow(ctx, `SELECT matched_summary->>'source', event_type, action_taken FROM security_events WHERE id=$1`, id).Scan(&source, &eventType, &action); err != nil {
		t.Fatal(err)
	}
	if source != "platform_egress" || eventType != "platform_egress_denied" || action != "block" {
		t.Fatalf("event = %s/%s/%s", source, eventType, action)
	}
	var requestID string
	_ = db.QueryRow(ctx, `SELECT request_id FROM security_events WHERE id=$1`, id).Scan(&requestID)
	if requestID == "" {
		t.Fatal("event must reference a request log")
	}
	_, _ = db.Exec(ctx, `DELETE FROM security_events WHERE id=$1`, id)
	_, _ = db.Exec(ctx, `DELETE FROM request_logs WHERE request_id=$1`, requestID)
}
