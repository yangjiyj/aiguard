package opsalert

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/alert"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 真实库：运维告警写进 alert_groups（满足全部约束），同类型同作用域折叠计数，
// 且 TTL 自动关闭（只关 input 侧）不会关掉它。
func TestEmitPersistsFoldedOpsAlertGroupOnPostgres(t *testing.T) {
	url := os.Getenv("BILLING_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("BILLING_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	tenant := fmt.Sprintf("tenant_ops_%d", time.Now().UnixNano())
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, tenant); err != nil {
		t.Fatal(err)
	}
	groups := repository.NewAlertGroupRepository(db)
	e := NewEmitter(groups, alert.NewInboxService(repository.NewAlertInboxRepository(db)), nil)
	old := time.Now().UTC().Add(-60 * 24 * time.Hour)
	for i := 0; i < 2; i++ {
		if _, err := e.Emit(ctx, Event{TenantID: tenant, Type: TypeFinalizeFailed, ScopeKey: "model:gpt", ScopeLabel: "模型 gpt", OccurredAt: old}); err != nil {
			t.Fatalf("emit %d: %v", i, err)
		}
	}
	if _, err := e.Emit(ctx, Event{TenantID: tenant, Type: TypeReservationLeak, Count: 3}); err != nil {
		t.Fatal(err)
	}
	var n, occurrences int
	var title, severity string
	if err := db.QueryRow(ctx, `SELECT count(*) FILTER (WHERE alert_type=$2), max(occurrence_count) FILTER (WHERE alert_type=$2),
		max(title) FILTER (WHERE alert_type=$2), max(severity) FILTER (WHERE alert_type=$2)
		FROM alert_groups WHERE tenant_id=$1`, tenant, TypeFinalizeFailed).Scan(&n, &occurrences, &title, &severity); err != nil {
		t.Fatal(err)
	}
	if n != 1 || occurrences != 2 || title != "计费结算失败 · 模型 gpt" || severity != "high" {
		t.Fatalf("groups=%d occurrences=%d title=%q severity=%q", n, occurrences, title, severity)
	}
	var inbox int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM alert_inbox WHERE tenant_id=$1`, tenant).Scan(&inbox); err != nil || inbox != 2 {
		t.Fatalf("inbox rows=%d err=%v", inbox, err)
	}
	if _, err := groups.AutoCloseStale(ctx, time.Now().UTC(), 14*24*time.Hour, time.Hour, 1000); err != nil {
		t.Fatal(err)
	}
	var open int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM alert_groups WHERE tenant_id=$1 AND status='open'`, tenant).Scan(&open); err != nil || open != 2 {
		t.Fatalf("TTL must not close ops alerts: open=%d err=%v", open, err)
	}
}
