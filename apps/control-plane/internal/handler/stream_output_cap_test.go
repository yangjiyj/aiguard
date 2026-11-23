package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// Priced streams use the actual wallet, including other in-flight reservations.
func TestQuoteGatewayBillingStreamOutputTokenCapUsesRealWallet(t *testing.T) {
	f := newCutoffFixture(t, "metering")
	f.addEmployeeQuota(1_000_000)
	f.addPrice("gpt-chat")
	call := func(requestID string) map[string]any {
		body, _ := json.Marshal(map[string]any{
			"tenant_id": f.tenantID, "user_id": f.userID, "request_id": requestID, "model_name": "gpt-chat",
			"usage": map[string]any{"prompt_tokens": 100_000, "output_tokens": 1_000},
		})
		rec := httptest.NewRecorder()
		QuoteGatewayBilling(f.deps)(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/billing/quotes", bytes.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
		}
		var decoded map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &decoded)
		return decoded
	}
	if got := call("cap-first"); got["stream_output_token_cap"] != float64(450_000) {
		t.Fatalf("first cap=%v", got)
	}
	// 额度 ¥1，另一请求在途预占 ¥0.102；本次可用 = ¥0.898，扣输入 ¥0.1 后按 ¥2/百万输出折算。
	got := call("cap-on")
	if got["stream_output_token_cap"] != float64(399_000) {
		t.Fatalf("stream_output_token_cap=%v want 399000 (%v)", got["stream_output_token_cap"], got)
	}
}

// 巨额钱包不构成合理的输出约束，不应把其折算结果下发给网关。
func TestStreamOutputTokenCapIgnoresHugeWallet(t *testing.T) {
	quote := &gatewayBillingQuote{Price: &billing.ModelPrice{Currency: "CNY"}, AdmittedAt: time.Now().UTC(), CustomerPrice: billing.DirectPrice{OutputPerMillionMicros: 500000}}
	cap := streamOutputTokenCap(context.Background(), &billing.Store{}, BillingReserveRequest{}, quote, 300000000, true)
	if cap != nil {
		t.Fatalf("巨额钱包不应下发 cap，得到 %d", *cap)
	}
}

func TestStreamOutputTokenCapRequiresExplicitMoneyQuota(t *testing.T) {
	f := newCutoffFixture(t, "metering")
	req := BillingReserveRequest{TenantID: f.tenantID, UserID: f.userID}
	quote := &gatewayBillingQuote{Price: &billing.ModelPrice{Currency: "CNY"}, AdmittedAt: time.Now().UTC(), CustomerPrice: billing.DirectPrice{OutputPerMillionMicros: 2000000}}
	if got := streamOutputTokenCap(context.Background(), f.store, req, quote, 1000000, true); got != nil {
		t.Fatalf("只有钱包不能下发 cap: %d", *got)
	}
	f.addEmployeeQuota(1000000)
	if got := streamOutputTokenCap(context.Background(), f.store, req, quote, 1000000, true); got == nil || *got != 500000 {
		t.Fatalf("员工额度应下发 cap: %v", got)
	}
	if _, err := openCutoffTestDB(t).Exec(context.Background(), "DELETE FROM billing_employee_settings WHERE tenant_id=$1", f.tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := openCutoffTestDB(t).Exec(context.Background(), `INSERT INTO quota_policies(id,tenant_id,scope_type,user_id,status,enforcement_mode,overage_action,monthly_budget_micros) VALUES ($1,$2,'user',$3,'active','enforce','rate_limit',1000000)`, f.tenantID+"-cap", f.tenantID, f.userID); err != nil {
		t.Fatal(err)
	}
	if got := streamOutputTokenCap(context.Background(), f.store, req, quote, 1000000, true); got == nil || *got != 500000 {
		t.Fatalf("金额策略应下发 cap: %v", got)
	}
}

// 用显式额度来源模拟门控，避免把普通用户的资金准入状态当作已配置预算。
type streamCapBudgetStub struct {
	configured bool
	policies   []billing.BudgetPolicyScope
	err        error
}

func (s streamCapBudgetStub) EmployeeAllowanceBudgetFor(context.Context, string, string, string, string, time.Time) (billing.Micros, bool, error) {
	return 1000000, s.configured, s.err
}
func (s streamCapBudgetStub) UserBudgetPolicies(context.Context, string, string) ([]billing.BudgetPolicyScope, error) {
	return s.policies, s.err
}

func TestStreamOutputTokenCapExplicitBudgetGate(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source streamCapBudgetStub
		want   bool
	}{
		{"只有钱包", streamCapBudgetStub{}, false},
		{"员工额度", streamCapBudgetStub{configured: true}, true},
		{"个人金额策略", streamCapBudgetStub{policies: []billing.BudgetPolicyScope{{Scope: "user", MonthlyMicros: 1000000}}}, true},
		{"部门金额策略", streamCapBudgetStub{policies: []billing.BudgetPolicyScope{{Scope: "team", DailyMicros: 1000000}}}, true},
		{"组织金额策略", streamCapBudgetStub{policies: []billing.BudgetPolicyScope{{Scope: "tenant", MonthlyMicros: 1000000}}}, true},
		{"无法读取", streamCapBudgetStub{err: errors.New("读取失败")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			quote := &gatewayBillingQuote{Price: &billing.ModelPrice{Currency: "CNY"}, AdmittedAt: time.Now().UTC(), CustomerPrice: billing.DirectPrice{OutputPerMillionMicros: 2000000}}
			got := streamOutputTokenCap(context.Background(), tc.source, BillingReserveRequest{}, quote, 1000000, true)
			if (got != nil) != tc.want {
				t.Fatalf("预算门控错误: %v", got)
			}
			if got != nil && *got != 500000 {
				t.Fatalf("cap=%d", *got)
			}
		})
	}
	for _, value := range []int64{999999, 1000000, 1000001, 599999982} {
		quote := &gatewayBillingQuote{Price: &billing.ModelPrice{Currency: "CNY"}, AdmittedAt: time.Now().UTC(), CustomerPrice: billing.DirectPrice{OutputPerMillionMicros: 1000000}}
		got := streamOutputTokenCap(context.Background(), streamCapBudgetStub{configured: true}, BillingReserveRequest{}, quote, billing.Micros(value), true)
		if (got != nil) != (value <= 1000000) {
			t.Fatalf("全局上限错误: budget=%d cap=%v", value, got)
		}
	}
}
