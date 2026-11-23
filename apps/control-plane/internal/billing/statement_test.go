package billing

import (
	"context"
	"testing"
	"time"
)

func insertStatementFact(t *testing.T, store *Store, tenant, id, user, dept, deptName, model, status string, prompt, output int64, amount *int64, at time.Time) {
	t.Helper()
	_, err := store.db.Exec(context.Background(), `INSERT INTO billing_usage_facts(id,tenant_id,request_id,billing_mode,user_id,user_name,department_id,department_name,model_name,prompt_tokens,output_tokens,billable_amount_micros,currency,status,occurred_at)
		VALUES($1,$2,$1,'metering',NULLIF($3,''),$4,NULLIF($5,''),$6,$7,$8,$9,$10,'CNY',$11,$12)`,
		id, tenant, user, user, dept, deptName, model, prompt, output, amount, status, at)
	if err != nil {
		t.Fatal(err)
	}
}

// 月度分账单：按部门汇总、展开到员工×模型；未定价/用量未知单列“未计费”，不混进 0 元；只统计所选月份（按账期时区）。
func TestMonthlyStatementGroupsDepartmentsEmployeesAndUnbilled(t *testing.T) {
	store, _, tenant, user := setupBillingStoreTest(t)
	sh, _ := time.LoadLocation("Asia/Shanghai")
	inMonth := time.Date(2026, 10, 15, 10, 0, 0, 0, sh)
	amt := func(v int64) *int64 { return &v }
	insertStatementFact(t, store, tenant, "st-1-"+tenant, user, "d1", "研发部", "gpt-6-luna", "settled", 1000, 500, amt(1_234_567), inMonth)
	insertStatementFact(t, store, tenant, "st-2-"+tenant, user, "d1", "研发部", "gpt-6-luna", "settled", 100, 50, amt(5_433), inMonth)
	insertStatementFact(t, store, tenant, "st-3-"+tenant, user, "d1", "研发部", "glm-5.2", "unpriced", 300, 30, nil, inMonth)
	insertStatementFact(t, store, tenant, "st-4-"+tenant, user, "d1", "研发部", "chatgpt", "usage_unknown", 0, 0, amt(0), inMonth)
	insertStatementFact(t, store, tenant, "st-5-"+tenant, "", "", "", "gpt-6-luna", "settled", 10, 10, amt(1_000_000), inMonth)
	insertStatementFact(t, store, tenant, "st-6-"+tenant, user, "d1", "研发部", "gpt-6-luna", "failed", 10, 0, nil, inMonth)
	// 10 月 1 日 00:30（上海）属于 10 月；9 月 30 日 23:30（上海）不属于。
	insertStatementFact(t, store, tenant, "st-7-"+tenant, user, "d1", "研发部", "gpt-6-luna", "settled", 1, 1, amt(1), time.Date(2026, 10, 1, 0, 30, 0, 0, sh))
	insertStatementFact(t, store, tenant, "st-8-"+tenant, user, "d1", "研发部", "gpt-6-luna", "settled", 1, 1, amt(999_999_999), time.Date(2026, 9, 30, 23, 30, 0, 0, sh))

	st, err := store.MonthlyStatement(context.Background(), tenant, "2026-10")
	if err != nil {
		t.Fatal(err)
	}
	if st.Month != "2026-10" || st.Timezone != "Asia/Shanghai" || st.Currency != "CNY" {
		t.Fatalf("header=%+v", st)
	}
	// 合计：已计费 1_234_567+5_433+1+1_000_000；本月 7 次调用（含 1 次失败），失败只计次数不计金额、也不算未计费
	if st.Total.BilledMicros != 2_240_001 || st.Total.Requests != 7 || st.Total.UnbilledRequests != 2 || st.Total.FailedRequests != 1 {
		t.Fatalf("total=%+v", st.Total)
	}
	if len(st.Departments) != 2 {
		t.Fatalf("departments=%+v", st.Departments)
	}
	dev := st.Departments[0]
	if dev.DepartmentName != "研发部" || dev.BilledMicros != 1_240_001 || dev.UnbilledRequests != 2 || dev.UnpricedRequests != 1 || dev.UsageUnknownRequests != 1 {
		t.Fatalf("研发部=%+v", dev)
	}
	if len(dev.Employees) != 1 || dev.Employees[0].UserID != user || len(dev.Employees[0].Models) != 3 {
		t.Fatalf("employees=%+v", dev.Employees)
	}
	luna := dev.Employees[0].Models[0]
	if luna.ModelName != "gpt-6-luna" || luna.Requests != 4 || luna.BilledMicros != 1_240_001 || luna.TotalTokens != 1_662 || luna.UnbilledRequests != 0 {
		t.Fatalf("gpt-6-luna=%+v", luna)
	}
	var unpriced *StatementLine
	for i := range dev.Employees[0].Models {
		if dev.Employees[0].Models[i].ModelName == "glm-5.2" {
			unpriced = &dev.Employees[0].Models[i]
		}
	}
	if unpriced == nil || unpriced.BilledMicros != 0 || unpriced.UnbilledRequests != 1 || unpriced.UnpricedRequests != 1 {
		t.Fatalf("glm-5.2=%+v", unpriced)
	}
	if st.Departments[1].DepartmentName != "未分配部门" || st.Departments[1].BilledMicros != 1_000_000 {
		t.Fatalf("未分配部门=%+v", st.Departments[1])
	}

	if _, err := store.MonthlyStatement(context.Background(), tenant, "2026-13"); err == nil {
		t.Fatal("invalid month must be rejected")
	}
}
