package opsalert

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func billingScannerFixture(t *testing.T) (*pgxpool.Pool, string) {
	t.Helper()
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
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenant := "tenant_bscan_" + suffix
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, []any{tenant}},
		{`INSERT INTO projects(id,tenant_id,name) VALUES ($1,$2,'p')`, []any{tenant + "-p", tenant}},
		{`INSERT INTO users(id,tenant_id,username,email,password_hash,role,status) VALUES ($1,$2,'zhangsan',$3,'x','developer','active')`, []any{tenant + "-u", tenant, tenant + "@t.invalid"}},
	} {
		if _, err := db.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
	}
	return db, tenant
}

func insertOutcome(t *testing.T, db *pgxpool.Pool, tenant, requestID, outcome string, at time.Time) {
	t.Helper()
	if _, err := db.Exec(context.Background(), `INSERT INTO request_logs(id,request_id,tenant_id,project_id,user_id,request_status,billing_outcome,created_at)
		VALUES ($2,$2,$1,$5,$6,'x',$3,$4)`, tenant, requestID, outcome, at, tenant+"-p", tenant+"-u"); err != nil {
		t.Fatal(err)
	}
}

// 预算用尽断流按员工聚合进告警组；重复扫描不重复计数；新事件折叠进同一个告警组。
func TestBillingScannerGroupsBudgetRejectionsAndCountsOnce(t *testing.T) {
	db, tenant := billingScannerFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	insertOutcome(t, db, tenant, tenant+"-r1", "budget_exhausted", now.Add(-time.Minute))
	insertOutcome(t, db, tenant, tenant+"-r2", "budget_exhausted", now.Add(-time.Minute))
	insertOutcome(t, db, tenant, tenant+"-r3", "failed", now.Add(-time.Minute))
	insertOutcome(t, db, tenant, tenant+"-r4", "settled", now.Add(-time.Minute))
	scanner := NewBillingScanner(db, NewEmitter(repository.NewAlertGroupRepository(db), nil, nil))
	if _, err := scanner.RunOnce(ctx, now); err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.RunOnce(ctx, now); err != nil {
		t.Fatal(err)
	}
	insertOutcome(t, db, tenant, tenant+"-r5", "budget_exhausted", now)
	if _, err := scanner.RunOnce(ctx, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query(ctx, `SELECT alert_type, title, occurrence_count, (body_json->>'count')::int FROM alert_groups WHERE tenant_id=$1 ORDER BY alert_type`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string][3]any{}
	for rows.Next() {
		var typ, title string
		var occ, count int
		if err := rows.Scan(&typ, &title, &occ, &count); err != nil {
			t.Fatal(err)
		}
		got[typ] = [3]any{title, occ, count}
	}
	if len(got) != 2 {
		t.Fatalf("groups=%v", got)
	}
	if g := got[TypeBudgetExhausted]; g[0] != "预算用尽断流 · 员工 zhangsan" || g[1] != 2 || g[2] != 1 {
		t.Fatalf("budget group=%v (want 2 folded scans: 2 events then 1)", g)
	}
	if g := got[TypeFinalizeFailed]; g[1] != 1 {
		t.Fatalf("finalize group=%v", g)
	}
}

// 钱包透支：按钱包聚合，告警带透支后可用余额。
func TestBillingScannerReportsWalletOverdraft(t *testing.T) {
	db, tenant := billingScannerFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()
	walletID := tenant + "-w"
	if _, err := db.Exec(ctx, `INSERT INTO billing_wallets(id,tenant_id,user_id,currency,balance_micros) VALUES ($1,$2,$3,'CNY',-5000)`, walletID, tenant, tenant+"-u"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO billing_ledger_entries(id,tenant_id,wallet_id,event_type,balance_delta_micros,reserved_delta_micros,balance_after_micros,reserved_after_micros,idempotency_key,metadata_json,created_at)
		VALUES ($1,$2,$3,'adjustment',-5000,0,-5000,0,'k1','{"overdraft":true}',$4)`, tenant+"-l1", tenant, walletID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	scanner := NewBillingScanner(db, NewEmitter(repository.NewAlertGroupRepository(db), nil, nil))
	if _, err := scanner.RunOnce(ctx, now); err != nil {
		t.Fatal(err)
	}
	var title string
	var available int64
	if err := db.QueryRow(ctx, `SELECT title, (body_json->>'available_after_micros')::bigint FROM alert_groups WHERE tenant_id=$1 AND alert_type=$2`, tenant, TypeWalletOverdraft).Scan(&title, &available); err != nil {
		t.Fatal(err)
	}
	if title != "钱包透支 · 钱包 zhangsan" || available != -5000 {
		t.Fatalf("title=%q available=%d", title, available)
	}
}
