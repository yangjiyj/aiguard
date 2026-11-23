package billing

import (
	"context"
	"testing"
	"time"
)

// 残留预占（没有对应 fact，且早于“最大请求时长 + 5 分钟”）会被清理，额度随之释放；
// 未过期的、已有 fact 的、其他租户的一律不动。
func TestPruneStaleEmployeeReservationsReleasesAllowanceOnlyForExpiredOnes(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	cap := int64(1_000_000)
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &cap}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	// 先用真实路径占住额度，再手动把创建时间改老，模拟 finalize 失败后残留的预占。
	for _, id := range []string{"stale-no-fact", "stale-with-fact", "fresh"} {
		if err := insertLegacyEmployeeHold(ctx, store, tenant, user, id, "CNY", 300_000, now); err != nil {
			t.Fatalf("reserve %s: %v", id, err)
		}
	}
	age := func(id string, by time.Duration) {
		t.Helper()
		if _, err := db.Exec(ctx, `UPDATE billing_employee_reservations SET created_at=$3 WHERE tenant_id=$1 AND request_id=$2`, tenant, id, now.Add(-by)); err != nil {
			t.Fatal(err)
		}
	}
	age("stale-no-fact", 2*time.Hour)
	age("stale-with-fact", 2*time.Hour)
	age("fresh", 10*time.Minute) // 仍在“最大请求时长 + 5 分钟”窗口内
	if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_id,model_name,billable_amount_micros,currency,status,occurred_at,admitted_at) VALUES($1,$2,'stale-with-fact','metering',$3,'m',300000,'CNY','settled',$4,$4)`, "ttl-fact-"+tenant, tenant, user, now); err != nil {
		t.Fatal(err)
	}
	// 额度现在被三笔预占（含已有 fact 的一笔，已计入已用）占住：再申请 400000 必须被拒。
	if err := store.ReserveEmployeeAllowance(ctx, tenant, user, "blocked", "CNY", 400_000, now); err != nil {
		t.Fatal("legacy employee holds must not constrain funded wallet")
	}

	result, err := store.PruneStaleEmployeeReservations(ctx, 30*time.Minute+5*time.Minute, now, 100)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted != 1 {
		t.Fatalf("deleted = %d, want exactly the stale reservation without a fact", result.Deleted)
	}
	// 按租户汇报释放数，供“预占泄漏清理”告警使用。
	if result.ByTenant[tenant] != 1 || len(result.ByTenant) != 1 {
		t.Fatalf("by tenant = %v", result.ByTenant)
	}
	remaining := map[string]bool{}
	rows, err := db.Query(ctx, `SELECT request_id FROM billing_employee_reservations WHERE tenant_id=$1`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		remaining[id] = true
	}
	if remaining["stale-no-fact"] || !remaining["stale-with-fact"] || !remaining["fresh"] {
		t.Fatalf("remaining = %v", remaining)
	}
	// 释放后：已用 300000（fact）+ 在途 300000（fresh）= 600000，还能再申请 300000。
	if err := store.ReserveEmployeeAllowance(ctx, tenant, user, "after-prune", "CNY", 300_000, now); err != nil {
		t.Fatalf("allowance should be freed after pruning the stale reservation: %v", err)
	}
	// 再跑一次是幂等的。
	again, err := store.PruneStaleEmployeeReservations(ctx, 35*time.Minute, now, 100)
	if err != nil || again.Deleted != 0 {
		t.Fatalf("second run = %+v %v", again, err)
	}
}

// 批量上限：一次最多删 limit 条，剩余的留给下一轮，避免长事务。
func TestPruneStaleEmployeeReservationsHonorsBatchLimit(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	cap := int64(100_000_000)
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &cap}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	for _, id := range []string{"b1", "b2", "b3"} {
		if err := insertLegacyEmployeeHold(ctx, store, tenant, user, id, "CNY", 1, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(ctx, `UPDATE billing_employee_reservations SET created_at=$2 WHERE tenant_id=$1`, tenant, now.Add(-3*time.Hour)); err != nil {
		t.Fatal(err)
	}
	first, err := store.PruneStaleEmployeeReservations(ctx, 35*time.Minute, now, 2)
	if err != nil || first.Deleted != 2 || !first.Backlog {
		t.Fatalf("first = %+v %v", first, err)
	}
	second, err := store.PruneStaleEmployeeReservations(ctx, 35*time.Minute, now, 2)
	if err != nil || second.Deleted != 1 || second.Backlog {
		t.Fatalf("second = %+v %v", second, err)
	}
}

func insertLegacyEmployeeHold(ctx context.Context, s *Store, tenant, user, request, currency string, amount int64, at time.Time) error {
	start, end, e := allowanceMonth(at, "Asia/Shanghai")
	if e != nil {
		return e
	}
	_, e = s.db.Exec(ctx, `INSERT INTO billing_employee_reservations(tenant_id,request_id,user_id,month_start,month_end,amount_micros,currency) VALUES($1,$2,$3,$4,$5,$6,$7)`, tenant, request, user, start, end, amount, currency)
	return e
}
