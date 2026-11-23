package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
)

func cutoffRedis(t *testing.T) *redis.Client {
	t.Helper()
	raw := os.Getenv("ATOMIC_QUOTA_TEST_REDIS_URL")
	if raw == "" {
		t.Skip("ATOMIC_QUOTA_TEST_REDIS_URL is not set")
	}
	options, err := redis.ParseURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

type cutoffStatusBody struct {
	Data struct {
		HasMoneyQuota bool   `json:"has_money_quota"`
		Blocked       bool   `json:"blocked"`
		Layer         string `json:"layer"`
		Message       string `json:"message"`
		Resolved      bool   `json:"resolved"`
	} `json:"data"`
}

func (f *cutoffFixture) status(query string) (*httptest.ResponseRecorder, cutoffStatusBody) {
	f.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/internal/v1/billing/cutoff-status?model_name=m&"+query, nil)
	rec := httptest.NewRecorder()
	f.addPrice("m")
	GetBillingCutoffStatus(f.deps)(rec, req)
	var body cutoffStatusBody
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return rec, body
}

func TestCutoffStatusUsesWalletMoneyInsteadOfIndependentAllowanceUsage(t *testing.T) {
	f := newCutoffFixture(t, "metering")
	f.addEmployeeQuota(1_000_000)
	db := openCutoffTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_id,model_name,billable_amount_micros,currency,status,occurred_at,admitted_at) VALUES($1,$2,$1,'metering',$3,'m',1000000,'CNY','settled',$4,$4)`, f.tenantID+"-sf", f.tenantID, f.userID, now); err != nil {
		t.Fatal(err)
	}
	rec, body := f.status("tenant_id=" + f.tenantID + "&user_id=" + f.userID)
	if rec.Code != http.StatusOK || !body.Data.HasMoneyQuota || body.Data.Blocked {
		t.Fatalf("monthly real credit must be available despite historical usage: status=%d body=%s", rec.Code, rec.Body.String())
	}
	wallet, err := f.store.GetWalletByUser(ctx, f.tenantID, f.userID, "CNY")
	if err != nil || wallet.BalanceMicros != 1_000_000 {
		t.Fatalf("monthly wallet not synchronized: wallet=%+v err=%v", wallet, err)
	}
	if _, err := f.store.Adjust(ctx, f.tenantID, wallet.ID, "drain-monthly", -wallet.BalanceMicros, f.adminID); err != nil {
		t.Fatal(err)
	}
	rec, body = f.status("tenant_id=" + f.tenantID + "&user_id=" + f.userID)
	if rec.Code != http.StatusOK || !body.Data.Blocked || body.Data.Layer != "wallet" || body.Data.Message == "" {
		t.Fatalf("empty wallet must block priced admission: status=%d body=%s", rec.Code, rec.Body.String())
	}
}

// 部门预算用尽（Redis 里的已用金额 >= 策略额度）-> 断流，层级为部门预算；未用尽则放行。
func TestCutoffStatusBlocksUserWhenDepartmentBudgetIsExhausted(t *testing.T) {
	f := newCutoffFixture(t, "metering")
	redisClient := cutoffRedis(t)
	f.deps.BudgetSnapshot = budget.NewSnapshotReader(redisClient)
	f.addEmployeeQuota(10_000_000_000)
	ctx := context.Background()
	db := openCutoffTestDB(t)
	team := "dept-" + f.tenantID
	if _, err := db.Exec(ctx, `INSERT INTO teams(id,tenant_id,name,path) VALUES($1,$2,'研发部',$3)`, team, f.tenantID, "/"+team); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE users SET department_id=$1 WHERE id=$2 AND tenant_id=$3`, team, f.userID, f.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO quota_policies(id,tenant_id,scope_type,scope_ref,monthly_budget_micros,enforcement_mode,overage_action,status) VALUES($1,$2,'team',$3,5000000000,'enforce','rate_limit','active')`, "qp-"+team, f.tenantID, team); err != nil {
		t.Fatal(err)
	}

	rec, body := f.status("tenant_id=" + f.tenantID + "&user_id=" + f.userID)
	if rec.Code != http.StatusOK || body.Data.Blocked {
		t.Fatalf("budget not used yet must stay open: %s", rec.Body.String())
	}

	now, err := redisClient.Time(ctx).Result()
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation("Asia/Shanghai")
	bucket := budget.QuotaPeriodBucket("Asia/Shanghai", now.In(loc).Format("2006-01"))
	key := budget.BudgetKey("team", team, bucket)
	if err := redisClient.HSet(ctx, key, "cost_micros", "5000000000").Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { redisClient.Del(ctx, key) })

	rec, body = f.status("tenant_id=" + f.tenantID + "&user_id=" + f.userID)
	if rec.Code != http.StatusOK || !body.Data.Blocked || body.Data.Layer != "department_budget" ||
		!strings.Contains(body.Data.Message, "本月部门预算已用完") || !strings.Contains(body.Data.Message, "研发部") {
		t.Fatalf("exhausted department budget must cut off: %s", rec.Body.String())
	}
}

// 只给源 IP：通过登录态映射解析出唯一用户后判定；解析不出用户则放行（resolved=false）。
func TestCutoffStatusResolvesUserFromSourceIP(t *testing.T) {
	f := newCutoffFixture(t, "metering")
	f.addEmployeeQuota(0)
	db := openCutoffTestDB(t)
	ip := "198.51.100.23"
	if _, err := db.Exec(context.Background(), `INSERT INTO user_login_history(user_id,logged_at,ip,success,event) VALUES($1,NOW(),$2,true,'login')`, f.userID, ip); err != nil {
		t.Fatal(err)
	}
	rec, body := f.status("tenant_id=" + f.tenantID + "&source_ip=" + ip)
	if rec.Code != http.StatusOK || !body.Data.Resolved || !body.Data.Blocked || body.Data.Layer != "wallet" {
		t.Fatalf("source ip must resolve to the empty wallet: %s", rec.Body.String())
	}
	rec, body = f.status("tenant_id=" + f.tenantID + "&source_ip=198.51.100.99")
	if rec.Code != http.StatusOK || body.Data.Resolved || body.Data.Blocked {
		t.Fatalf("unknown ip must not be attributed or blocked: %s", rec.Body.String())
	}
}

func TestCutoffStatusRequiresTenant(t *testing.T) {
	f := newCutoffFixture(t, "metering")
	rec, _ := f.status("user_id=" + f.userID)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d", rec.Code)
	}
}

func TestCutoffStatusUnpricedModelBypassesAnEmptyWallet(t *testing.T) {
	f := newCutoffFixture(t, "metering")
	f.addEmployeeQuota(0)
	rec := httptest.NewRecorder()
	GetBillingCutoffStatus(f.deps)(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/billing/cutoff-status?model_name=unpriced&tenant_id="+f.tenantID+"&user_id="+f.userID, nil))
	var body struct {
		Data cutoffStatus `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || !body.Data.Resolved || !body.Data.Unpriced || body.Data.Blocked {
		t.Fatalf("unpriced calls must remain open: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
