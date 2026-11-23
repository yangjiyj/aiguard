package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/budget"
)

type budgetTreeBody struct {
	Data billing.BudgetTreeNode `json:"data"`
}

func findBudgetNode(n *billing.BudgetTreeNode, id string) *billing.BudgetTreeNode {
	if n.ID == id {
		return n
	}
	for _, c := range n.Children {
		if got := findBudgetNode(c, id); got != nil {
			return got
		}
	}
	return nil
}

// 预算树：组织 → 部门 → 员工，部门用量来自与断流判定同源的预算快照；部门预算改了，树上剩余跟着变。
func TestBudgetTreeShowsHierarchyUsageAndRefreshesAfterEdit(t *testing.T) {
	databaseURL := os.Getenv("BILLING_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("BILLING_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenant, team, child, alice, bob := "bt_"+sfx, "btd_"+sfx, "btc_"+sfx, "bta_"+sfx, "btb_"+sfx
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO tenants(id,name,edition,status) VALUES($1,'测试单位','enterprise','active')`, []any{tenant}},
		{`INSERT INTO teams(id,tenant_id,name,path) VALUES($1,$2,'研发部',$3)`, []any{team, tenant, "/" + team}},
		{`INSERT INTO teams(id,tenant_id,name,parent_team_id,path) VALUES($1,$2,'平台组',$3,$4)`, []any{child, tenant, team, "/" + team + "/" + child}},
		{`INSERT INTO users(id,tenant_id,username,email,password_hash,role,status,department_id) VALUES($1,$2,'alice',$3,'x','developer','active',$4)`, []any{alice, tenant, alice + "@t.invalid", child}},
		{`INSERT INTO users(id,tenant_id,username,email,password_hash,role,status,department_id) VALUES($1,$2,'bob',$3,'x','developer','active',$4)`, []any{bob, tenant, bob + "@t.invalid", team}},
		{`INSERT INTO billing_employee_settings(tenant_id,currency,timezone,default_monthly_micros) VALUES($1,'CNY','Asia/Shanghai',1000000)`, []any{tenant}},
		{`INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_id,model_name,billable_amount_micros,currency,status,occurred_at,admitted_at) VALUES($1,$2,'bt-req','metering',$3,'m',1000000,'CNY','settled',NOW(),NOW())`, []any{"btf_" + sfx, tenant, alice}},
		{`INSERT INTO quota_policies(id,tenant_id,scope_type,scope_ref,monthly_budget_micros,enforcement_mode,status,quota_timezone) VALUES($1,$2,'team',$3,5000000,'enforce','active','Asia/Shanghai')`, []any{"btq_" + sfx, tenant, team}},
		{`INSERT INTO quota_policies(id,tenant_id,scope_type,user_id,monthly_budget_micros,enforcement_mode,status,quota_timezone) VALUES($1,$2,'user',$3,3000000,'soft','active','Asia/Shanghai')`, []any{"btp_" + sfx, tenant, bob}},
	} {
		if _, err := db.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatalf("%s: %v", stmt.sql, err)
		}
	}
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	month := time.Now().In(mustShanghai(t)).Format("2006-01")
	mr.HSet(budget.BudgetKey("team", team, month), "cost_micros", "4500000")
	mr.HSet(budget.BudgetKey("user", bob, month), "cost_micros", "100")
	deps := &Dependencies{BillingStore: billing.NewStore(db), BudgetSnapshot: budget.NewSnapshotReader(rdb), BillingMode: "metering"}

	get := func(role string) (*httptest.ResponseRecorder, budgetTreeBody) {
		req := billingHandlerAdminRequest(httptest.NewRequest(http.MethodGet, "/admin/v1/billing/budget-tree?tenant_id="+tenant, nil), "admin", tenant, role)
		rec := httptest.NewRecorder()
		GetBillingBudgetTree(deps)(rec, req)
		var body budgetTreeBody
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec, body
	}
	for _, role := range []string{"developer", "dept_manager", "auditor", "security_officer"} {
		if rec, _ := get(role); rec.Code != http.StatusForbidden {
			t.Fatalf("%s must be rejected, got %d", role, rec.Code)
		}
	}
	// 单位管理员只读本单位：原“配额与限流”页它本就能配组织/部门预算，迁到预算树后不能丢。
	if rec, body := get("tenant_admin"); rec.Code != http.StatusOK || body.Data.ID != tenant {
		t.Fatalf("tenant_admin own tenant: status=%d id=%s", rec.Code, body.Data.ID)
	}
	other := billingHandlerAdminRequest(httptest.NewRequest(http.MethodGet, "/x?tenant_id=someone-else", nil), "admin", tenant, "tenant_owner")
	otherRec := httptest.NewRecorder()
	GetBillingBudgetTree(deps)(otherRec, other)
	if otherRec.Code != http.StatusForbidden {
		t.Fatalf("tenant_owner must not read another tenant, got %d", otherRec.Code)
	}
	rec, body := get("platform_admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	root := body.Data
	if root.Kind != "organization" || root.Name != "测试单位" || root.Status != billing.BudgetStatusUnlimited {
		t.Fatalf("root=%+v", root)
	}
	dept := findBudgetNode(&root, team)
	if dept == nil || *dept.BudgetMicros != 5_000_000 || *dept.UsedMicros != 4_500_000 || *dept.RemainMicros != 500_000 || dept.Status != billing.BudgetStatusWarning {
		t.Fatalf("department node=%+v", dept)
	}
	if findBudgetNode(dept, child) == nil || findBudgetNode(dept, bob) == nil {
		t.Fatal("child department and direct employee must hang under 研发部")
	}
	b := findBudgetNode(&root, bob)
	if b.PersonalBudgetMicros == nil || *b.PersonalBudgetMicros != 3_000_000 || *b.PersonalUsedMicros != 100 || b.PersonalStatus != billing.BudgetStatusNormal {
		t.Fatalf("bob legacy personal budget=%+v", b)
	}
	a := findBudgetNode(&root, alice)
	if a == nil || a.Status != billing.BudgetStatusExhausted || !a.Inherited || *a.RemainMicros != 0 {
		t.Fatalf("alice (default 1.00, used 1.00)=%+v", a)
	}

	// 编辑部门预算后重新读取，剩余额度随之刷新。
	if _, err := db.Exec(ctx, `UPDATE quota_policies SET monthly_budget_micros=4000000 WHERE id=$1`, "btq_"+sfx); err != nil {
		t.Fatal(err)
	}
	_, body = get("platform_admin")
	dept = findBudgetNode(&body.Data, team)
	if *dept.BudgetMicros != 4_000_000 || *dept.RemainMicros != 0 || dept.Status != billing.BudgetStatusExhausted {
		t.Fatalf("after edit department=%+v", dept)
	}
}

// 没有配置预算快照（Redis 未接）时，设置了预算的部门显示“用量未知”，不能显示成 0 已用。
func TestBudgetTreeWithoutSnapshotMarksUsageUnknown(t *testing.T) {
	databaseURL := os.Getenv("BILLING_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("BILLING_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	sfx := fmt.Sprintf("%d", time.Now().UnixNano())
	tenant, team := "btu_"+sfx, "btud_"+sfx
	for _, q := range []string{
		`INSERT INTO tenants(id,name,edition,status) VALUES('` + tenant + `','单位','enterprise','active')`,
		`INSERT INTO teams(id,tenant_id,name,path) VALUES('` + team + `','` + tenant + `','财务部','/` + team + `')`,
		`INSERT INTO quota_policies(id,tenant_id,scope_type,scope_ref,monthly_budget_micros,enforcement_mode,status) VALUES('btuq_` + sfx + `','` + tenant + `','team','` + team + `',1000000,'soft','active')`,
	} {
		if _, err := db.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	deps := &Dependencies{BillingStore: billing.NewStore(db)}
	req := billingHandlerAdminRequest(httptest.NewRequest(http.MethodGet, "/x?tenant_id="+tenant, nil), "admin", tenant, "platform_admin")
	rec := httptest.NewRecorder()
	GetBillingBudgetTree(deps)(rec, req)
	var body budgetTreeBody
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	dept := findBudgetNode(&body.Data, team)
	if rec.Code != http.StatusOK || dept == nil || dept.Status != billing.BudgetStatusUnknown || dept.UsedMicros != nil {
		t.Fatalf("status=%d dept=%+v", rec.Code, dept)
	}
}

func mustShanghai(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	return loc
}
