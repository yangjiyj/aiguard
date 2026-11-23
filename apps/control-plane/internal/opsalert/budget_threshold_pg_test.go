package opsalert

import (
	"context"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 真实库：员工月额度到 80% 时外发一次；重复扫描、重建扫描器（模拟重启）都不再外发。
func TestBudgetThresholdScannerPersistsDedupAcrossRestart(t *testing.T) {
	db, tenant := billingScannerFixture(t)
	ctx := context.Background()
	user := tenant + "-u"
	if _, err := db.Exec(ctx, `INSERT INTO billing_employee_settings(tenant_id,currency,timezone,default_monthly_micros) VALUES ($1,'CNY','Asia/Shanghai',NULL)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO billing_employee_allowances(tenant_id,user_id,monthly_micros) VALUES ($1,$2,1000000)`, tenant, user); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts (id,tenant_id,request_id,user_id,model_name,billable_amount_micros,currency,status,occurred_at,admitted_at)
		VALUES ($1,$2,$1,$3,'m',850000,'CNY','settled',$4,$4)`, tenant+"-f1", tenant, user, now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	store := billing.NewStore(db)
	n := &fakeNotifier{}
	newScanner := func() *BudgetThresholdScanner {
		s := NewBudgetThresholdScanner(db, store, nil, NewEmitter(repository.NewAlertGroupRepository(db), nil, n))
		base := s.tenants
		s.tenants = func(ctx context.Context) ([]string, error) {
			ids, err := base(ctx)
			for _, id := range ids {
				if id == tenant {
					return []string{tenant}, err
				}
			}
			return nil, err
		}
		return s
	}
	for i := 0; i < 2; i++ {
		if _, err := newScanner().RunOnce(ctx, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(n.titles) != 1 {
		t.Fatalf("应只外发一次，实际 %v", n.titles)
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT count(*) FROM billing_budget_threshold_notices WHERE tenant_id=$1 AND scope_type='employee' AND scope_id=$2 AND threshold=80`, tenant, user).Scan(&count); err != nil || count != 1 {
		t.Fatalf("去重记录 count=%d err=%v", count, err)
	}
	var disposition string
	if err := db.QueryRow(ctx, `SELECT disposition_class FROM alert_groups WHERE tenant_id=$1 AND alert_type=$2`, tenant, TypeBudgetThreshold80).Scan(&disposition); err != nil || disposition != "informational" {
		t.Fatalf("disposition=%q err=%v", disposition, err)
	}
}
