package billing

import (
	"context"
	"testing"
	"time"
)

func TestEmployeeAllowanceStatusReportsPercentAndThreshold(t *testing.T) {
	cases := []struct {
		limit, used int64
		percent     int64
		threshold   int
	}{{1000, 0, 0, 0}, {1000, 799, 79, 0}, {1000, 800, 80, 80}, {1000, 1000, 100, 100}, {1000, 1500, 150, 100}}
	for _, c := range cases {
		limit := c.limit
		got := NewEmployeeAllowanceStatus(EmployeeAllowance{EffectiveMicros: &limit, UsedMicros: c.used, Currency: "CNY"})
		if got == nil || got.Percent != c.percent || got.Threshold != c.threshold {
			t.Fatalf("limit=%d used=%d got=%#v", c.limit, c.used, got)
		}
	}
	if NewEmployeeAllowanceStatus(EmployeeAllowance{}) != nil {
		t.Fatal("未设置额度时不返回状态")
	}
}

func TestEmployeeAllowanceForUserReadsOnlyThatEmployee(t *testing.T) {
	store, db, tenantID, userID := setupBillingStoreTest(t)
	ctx := context.Background()
	if err := store.SaveEmployeeSettings(ctx, tenantID, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai"}); err != nil {
		t.Fatal(err)
	}
	if status, err := store.EmployeeAllowanceForUser(ctx, tenantID, userID, time.Now()); err != nil || status == nil || status.MonthlyStatus == nil || status.MonthlyStatus.GrantedMicros != 0 {
		t.Fatalf("未设置额度应返回 nil: %#v %v", status, err)
	}
	amount := int64(1_000_000)
	if err := store.SetEmployeeAllowances(ctx, tenantID, []string{userID}, &amount); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts (id,tenant_id,request_id,user_id,model_name,billable_amount_micros,currency,status,occurred_at,admitted_at)
		VALUES ($1,$2,$1,$3,'m',820000,'CNY','settled',$4,$4)`, "fact_eas_"+tenantID, tenantID, userID, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	status, err := store.EmployeeAllowanceForUser(ctx, tenantID, userID, now)
	if err != nil || status == nil || status.Percent != 82 || status.Threshold != 80 || status.LimitMicros != 1_000_000 {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	if other, err := store.EmployeeAllowanceForUser(ctx, "tenant_other_"+tenantID, userID, now); err != nil || other != nil {
		t.Fatalf("跨租户不得读到: %#v %v", other, err)
	}
}

func TestEmployeeAllowanceStatusPreservesExplicitZeroLimit(t *testing.T) {
	zero := int64(0)
	status := NewEmployeeAllowanceStatus(EmployeeAllowance{EffectiveMicros: &zero, Currency: "CNY"})
	if status == nil || status.LimitMicros != 0 {
		t.Fatal("explicit zero allowance must remain distinguishable from no limit")
	}
	if NewEmployeeAllowanceStatus(EmployeeAllowance{}) != nil {
		t.Fatal("missing allowance must remain unrestricted")
	}
}
