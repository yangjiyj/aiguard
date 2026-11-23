package billing

import (
	"context"
	"testing"
	"time"
)

// 员工额度：已用 + 在途预占 >= 额度即视为用尽；未配额度返回 nil。
func TestEmployeeAllowanceCutoffStatus(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	at := time.Date(2026, 10, 15, 4, 0, 0, 0, time.UTC)
	if got, err := store.EmployeeAllowanceCutoff(ctx, tenant, user, at); err != nil || got != nil {
		t.Fatalf("no allowance configured must not cut off: %+v %v", got, err)
	}
	cap := int64(1_000_000)
	if err := store.SaveEmployeeSettings(ctx, tenant, EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &cap}); err != nil {
		t.Fatal(err)
	}
	if got, err := store.EmployeeAllowanceCutoff(ctx, tenant, user, at); err != nil || got != nil {
		t.Fatalf("unused allowance must not cut off: %+v %v", got, err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_id,model_name,billable_amount_micros,currency,status,occurred_at,admitted_at) VALUES($1,$2,'cut-settled','metering',$3,'m',1000000,'CNY','settled',$4,$4)`, "cutfact-"+user, tenant, user, at); err != nil {
		t.Fatal(err)
	}
	got, err := store.EmployeeAllowanceCutoff(ctx, tenant, user, at)
	if err != nil || got == nil || got.LimitMicros != 1_000_000 || got.UsedMicros != 1_000_000 || got.Username == "" {
		t.Fatalf("exhausted allowance must be reported: %+v %v", got, err)
	}
	// 下个月自动恢复。
	next := time.Date(2026, 10, 31, 17, 0, 0, 0, time.UTC)
	if got, err := store.EmployeeAllowanceCutoff(ctx, tenant, user, next); err != nil || got != nil {
		t.Fatalf("next month must reset: %+v %v", got, err)
	}
}

// 部门预算：沿用户所在部门的祖先链取金额预算策略，连同租户级、个人级一起返回。
func TestUserBudgetPoliciesWalkTeamAncestors(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	root, leaf := "root-"+tenant, "leaf-"+tenant
	if _, err := db.Exec(ctx, `INSERT INTO teams(id,tenant_id,name,path) VALUES($1,$2,'总部',$3),($4,$2,'研发部',$5)`, root, tenant, "/"+root, leaf, "/"+root+"/"+leaf); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `UPDATE users SET department_id=$1 WHERE id=$2 AND tenant_id=$3`, leaf, user, tenant); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		id, scope, ref string
		monthly        int64
	}{
		{"qp-root-" + tenant, "team", root, 9_000_000},
		{"qp-leaf-" + tenant, "team", leaf, 5_000_000},
		{"qp-tenant-" + tenant, "tenant", "", 100_000_000},
	} {
		if _, err := db.Exec(ctx, `INSERT INTO quota_policies(id,tenant_id,scope_type,scope_ref,monthly_budget_micros,enforcement_mode,overage_action,status) VALUES($1,$2,$3,NULLIF($4,''),$5,'enforce','rate_limit','active')`, row.id, tenant, row.scope, row.ref, row.monthly); err != nil {
			t.Fatal(err)
		}
	}
	// 没有金额预算的策略（只有 token 限额）不应返回。
	if _, err := db.Exec(ctx, `INSERT INTO quota_policies(id,tenant_id,scope_type,scope_ref,monthly_token_limit,enforcement_mode,status) VALUES($1,$2,'team',$3,100,'soft','active')`, "qp-tok-"+tenant, tenant, "other-"+tenant); err != nil {
		t.Fatal(err)
	}
	got, err := store.UserBudgetPolicies(ctx, tenant, user)
	if err != nil {
		t.Fatal(err)
	}
	byScope := map[string]BudgetPolicyScope{}
	for _, item := range got {
		byScope[item.Scope+":"+item.ScopeID] = item
	}
	if len(got) != 3 || byScope["team:"+leaf].Name != "研发部" || byScope["team:"+leaf].MonthlyMicros != 5_000_000 ||
		byScope["team:"+root].MonthlyMicros != 9_000_000 || byScope["tenant:"+tenant].MonthlyMicros != 100_000_000 {
		t.Fatalf("policies = %+v", got)
	}
	if byScope["team:"+leaf].Timezone == "" {
		t.Fatal("timezone must be reported for bucket calculation")
	}
}

// 按源 IP 解析用户：只认近窗口内成功登录且唯一的用户；多人共用同一 IP 时不归属任何人。
func TestResolveUserBySourceIPRequiresUniqueRecentLogin(t *testing.T) {
	store, db, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	other := tenant + "-other"
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role,status) VALUES ($1,$2,$1,'developer','active')`, other, tenant); err != nil {
		t.Fatal(err)
	}
	insertLogin := func(userID, ip string, ago time.Duration, success bool) {
		t.Helper()
		if _, err := db.Exec(ctx, `INSERT INTO user_login_history(user_id,logged_at,ip,success,event) VALUES($1,$2,$3,$4,'login')`, userID, time.Now().Add(-ago), ip, success); err != nil {
			t.Fatal(err)
		}
	}
	ip := "203.0.113.7"
	if got, err := store.ResolveUserBySourceIP(ctx, tenant, ip, 12*time.Hour); err != nil || got != "" {
		t.Fatalf("unknown ip = %q %v", got, err)
	}
	insertLogin(user, ip, time.Hour, true)
	insertLogin(other, ip, 30*time.Hour, true) // 窗口外，不计入
	insertLogin(other, ip, time.Hour, false)   // 失败登录，不计入
	if got, err := store.ResolveUserBySourceIP(ctx, tenant, ip, 12*time.Hour); err != nil || got != user {
		t.Fatalf("unique login must resolve: %q %v", got, err)
	}
	insertLogin(other, ip, 2*time.Hour, true)
	if got, err := store.ResolveUserBySourceIP(ctx, tenant, ip, 12*time.Hour); err != nil || got != "" {
		t.Fatalf("shared ip must not be attributed: %q %v", got, err)
	}
	if got, err := store.ResolveUserBySourceIP(ctx, tenant, "", 12*time.Hour); err != nil || got != "" {
		t.Fatalf("empty ip = %q %v", got, err)
	}
}

// 预付费钱包：可用余额 <= 0（含没有钱包）视为用尽。
func TestWalletCutoffStatus(t *testing.T) {
	store, _, tenant, user := setupBillingStoreTest(t)
	ctx := context.Background()
	exhausted, err := store.WalletCutoff(ctx, tenant, user)
	if err != nil || exhausted {
		t.Fatalf("no configured wallet means no wallet quota: %v %v", exhausted, err)
	}
	wallet, err := store.EnsureWallet(ctx, tenant, user, "CNY")
	if err != nil {
		t.Fatal(err)
	}
	if exhausted, _ := store.WalletCutoff(ctx, tenant, user); exhausted {
		t.Fatal("automatic empty wallet must not enforce")
	}
	if _, err := store.Credit(ctx, tenant, wallet.ID, "cut-credit", 5_000_000, "admin"); err != nil {
		t.Fatal(err)
	}
	if exhausted, err := store.WalletCutoff(ctx, tenant, user); err != nil || exhausted {
		t.Fatalf("funded wallet must not be exhausted: %v %v", exhausted, err)
	}
}
