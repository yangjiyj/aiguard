package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/governor"
	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/modelrouter"
)

// 断流提示的金额符号必须跟随计价币种（只换符号，不做汇率换算）；没带币种时保持历史的 ¥。
func TestBudgetMessageMoneyFormattingFollowsCurrency(t *testing.T) {
	cases := []struct {
		micros   int64
		currency string
		want     string
	}{
		{5_000_000_000, "USD", "$5,000.00"},
		{5_000_000_000, "usd", "$5,000.00"},
		{-1_500_000, "USD", "-$1.50"},
		{5_000_000_000, "CNY", "¥5,000.00"},
		{5_000_000_000, "", "¥5,000.00"},
	}
	for _, c := range cases {
		if got := formatBudgetMicros(c.micros, c.currency); got != c.want {
			t.Fatalf("formatBudgetMicros(%d,%q)=%q 期望 %q", c.micros, c.currency, got, c.want)
		}
	}
}

func TestWriteQuotaAdmissionErrorUsesTenantCurrencySymbol(t *testing.T) {
	limitErr := &governor.AdmissionLimitError{
		Metric: "month_cost_micros", Scope: "team", ScopeName: "研发部", Limit: 5_000_000_000, Used: 5_000_000_000,
		BudgetCutoff: true, RequestID: "req-usd", ResetAt: shanghaiTime(2026, 11, 1), Currency: "USD",
	}
	w := httptest.NewRecorder()
	writeQuotaAdmissionError(w, limitErr, "req-fallback")
	var body ErrorResponse
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body.Error.Message, "$5,000.00 / $5,000.00") || strings.Contains(body.Error.Message, "¥") {
		t.Fatalf("美元租户的断流提示不应出现 ¥：%q", body.Error.Message)
	}
}

// 控制面询价/预占响应带 currency；网关把它记到请求信封，随准入请求传到限额错误。
func TestApplyBillingCostCurrencyRecordsQuoteCurrency(t *testing.T) {
	envelope := &modelrouter.RequestEnvelope{}
	applyBillingCostCurrency(envelope, " usd ")
	if envelope.QuotaCostCurrency != "USD" {
		t.Fatalf("应记录规范化币种 USD：%q", envelope.QuotaCostCurrency)
	}
	applyBillingCostCurrency(envelope, "")
	if envelope.QuotaCostCurrency != "USD" {
		t.Fatalf("空币种不应覆盖已记录值：%q", envelope.QuotaCostCurrency)
	}
	applyBillingCostCurrency(nil, "USD") // 不应 panic
}

func TestBillingControlPlaneResponseParsesCurrency(t *testing.T) {
	var result billingControlPlaneResponse
	if err := json.Unmarshal([]byte(`{"billable_amount_micros":10,"currency":"USD"}`), &result); err != nil {
		t.Fatal(err)
	}
	if result.Currency != "USD" {
		t.Fatalf("响应币种未解析：%+v", result)
	}
}
