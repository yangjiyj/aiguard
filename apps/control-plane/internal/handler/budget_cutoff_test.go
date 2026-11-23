package handler

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

type cutoffFixture struct {
	t        *testing.T
	deps     *Dependencies
	store    *billing.Store
	tenantID string
	userID   string
	adminID  string
}

// openCutoffTestDB 打开断流用例专用的一次性库。断流开关与预检是全局的，会看到同库里其他用例留下的
// 事实/额度，所以这里用独立的 BUDGET_CUTOFF_TEST_DATABASE_URL（未设置则跳过），并在每个用例开始时清空全局性数据。
func openCutoffTestDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	databaseURL := os.Getenv("BUDGET_CUTOFF_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("set BUDGET_CUTOFF_TEST_DATABASE_URL (disposable PostgreSQL) to run budget cutoff integration tests")
	}
	db, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("connect db: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

// clearGlobalBillingState 清掉会影响全局预检的数据；只在一次性库上调用。
func clearGlobalBillingState(t *testing.T, db *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	for _, statement := range []string{
		`ALTER TABLE billing_usage_facts DISABLE TRIGGER USER`,
		`DELETE FROM billing_usage_facts`,
		`ALTER TABLE billing_usage_facts ENABLE TRIGGER USER`,
		`DELETE FROM billing_employee_allowances`,
		`DELETE FROM billing_employee_reservations`,
		`DELETE FROM billing_employee_settings`,
		`DELETE FROM quota_policies`,
		`DELETE FROM request_logs WHERE billing_outcome IN ('budget_exhausted','budget_unpriced','budget_unavailable')`,
	} {
		if _, err := db.Exec(ctx, statement); err != nil {
			t.Fatalf("clear %q: %v", statement, err)
		}
	}
}

func newCutoffFixture(t *testing.T, mode string) *cutoffFixture {
	t.Helper()
	db := openCutoffTestDB(t)
	clearGlobalBillingState(t, db)
	store := billing.NewStore(db)
	deps := &Dependencies{BillingStore: store, BillingMode: mode, SystemRepo: repository.NewSystemRepository(db)}
	tenantID := billingHandlerTestTenant(t, "hcut")
	ctx := context.Background()
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, tenantID); err != nil {
		t.Fatal(err)
	}
	userID := tenantID + "-u"
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role,status) VALUES ($1,$2,'zhangsan','developer','active')`, userID, tenantID); err != nil {
		t.Fatal(err)
	}
	adminID := tenantID + "-admin"
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role,status) VALUES ($1,$2,'root-admin','platform_admin','active')`, adminID, tenantID); err != nil {
		t.Fatal(err)
	}
	return &cutoffFixture{t: t, deps: deps, store: store, tenantID: tenantID, userID: userID, adminID: adminID}
}

func (f *cutoffFixture) addPrice(model string) {
	f.t.Helper()
	if _, err := f.store.CreateModelPrice(context.Background(), billing.NewModelPrice{TenantID: f.tenantID, ModelName: model, Currency: "CNY", PricingMode: billing.PricingModeDirect,
		DirectPrice: billing.DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 2_000_000}, EffectiveAt: time.Now().Add(-24 * time.Hour)}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *cutoffFixture) addEmployeeQuota(micros int64) {
	f.t.Helper()
	if err := f.store.SaveEmployeeSettings(context.Background(), f.tenantID, billing.EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &micros}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *cutoffFixture) addUnpricedFact(model string) {
	f.t.Helper()
	db := openCutoffTestDB(f.t)
	now := time.Now().UTC()
	if _, err := db.Exec(context.Background(), `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_id,model_name,currency,status,occurred_at,admitted_at)
		VALUES($1,$2,$1,'metering',$3,$4,'CNY','unpriced',$5,$5)`, f.tenantID+"-uf-"+model, f.tenantID, f.userID, model, now.Add(-time.Hour)); err != nil {
		f.t.Fatal(err)
	}
}
