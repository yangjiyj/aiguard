package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestMonthlyWalletFundingGuardUsesBalance429AndCurrency409(t *testing.T) {
	for _, v := range []struct {
		err    error
		status int
		code   string
	}{
		{billing.ErrInsufficientBalance, http.StatusTooManyRequests, "insufficient_balance"},
		{billing.ErrAllowanceCurrency, http.StatusConflict, "allowance_currency_mismatch"},
	} {
		w := httptest.NewRecorder()
		employeeAllowanceHTTPError(w, v.err)
		if w.Code != v.status {
			t.Fatalf("guard status=%d want=%d", w.Code, v.status)
		}
		var response struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if e := json.Unmarshal(w.Body.Bytes(), &response); e != nil || response.Error.Code != v.code || response.Error.Message == "" {
			t.Fatalf("guard reason contract failed: %v", e)
		}
		if v.status == 429 && response.Error.Message != billingInsufficientBalanceMessage {
			t.Fatal("balance guard must use the existing balance reason")
		}
	}
}

func TestMonthlyWalletHTTPFreeZeroBalanceReleaseAndPaidZeroEstimate(t *testing.T) {
	db, store, tenant, user, _ := billingEndToEndFixture(t)
	ctx := context.Background()
	w, e := store.GetWalletByUser(ctx, tenant, user, "CNY")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = store.Adjust(ctx, tenant, w.ID, tenant+"-zero-free-test", -w.BalanceMicros, "test"); e != nil {
		t.Fatal(e)
	}
	if _, e = store.CreateModelPrice(ctx, billing.NewModelPrice{TenantID: tenant, ModelName: "http-free", Currency: "CNY", PricingMode: billing.PricingModeDirect}); e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec(ctx, `INSERT INTO billing_customer_limits(tenant_id,user_id,daily_token_limit,monthly_token_limit) VALUES($1,$2,100,200)`, tenant, user); e != nil {
		t.Fatal(e)
	}
	request := tenant + "-free-request"
	payload, _ := json.Marshal(map[string]any{"tenant_id": tenant, "user_id": user, "request_id": request, "model_name": "http-free", "usage": billing.Usage{PromptTokens: 2, OutputTokens: 1}})
	quote := httptest.NewRecorder()
	QuoteGatewayBilling(&Dependencies{BillingStore: store, BillingMode: "metering"})(quote, httptest.NewRequest(http.MethodPost, "/internal/v1/billing/quotes", bytes.NewReader(payload)))
	if quote.Code != 200 {
		t.Fatalf("fully free quote at zero balance=%d %s", quote.Code, quote.Body.String())
	}
	releaseBody, _ := json.Marshal(map[string]any{"tenant_id": tenant, "request_id": request})
	for i := 0; i < 2; i++ {
		released := httptest.NewRecorder()
		ReleaseGatewayBilling(&Dependencies{BillingStore: store})(released, httptest.NewRequest(http.MethodPost, "/internal/v1/billing/releases", bytes.NewReader(releaseBody)))
		if released.Code != 200 {
			t.Fatalf("free failed request release=%d %s", released.Code, released.Body.String())
		}
	}
	var tokens int64
	if e = db.QueryRow(ctx, `SELECT COALESCE(sum(reserved_tokens),0) FROM billing_limit_counters WHERE tenant_id=$1 AND user_id=$2`, tenant, user).Scan(&tokens); e != nil || tokens != 0 {
		t.Fatalf("free HTTP failure retained token holds=%d %v", tokens, e)
	}
	if _, e = store.CreateModelPrice(ctx, billing.NewModelPrice{TenantID: tenant, ModelName: "http-paid-zero-estimate", Currency: "CNY", PricingMode: billing.PricingModeDirect, DirectPrice: billing.DirectPrice{InputPerMillionMicros: 1}}); e != nil {
		t.Fatal(e)
	}
	zero := int64(0)
	payload, _ = json.Marshal(map[string]any{"tenant_id": tenant, "user_id": user, "request_id": tenant + "-paid-zero", "model_name": "http-paid-zero-estimate", "usage": billing.Usage{}, "estimated_output_tokens": &zero})
	paid := httptest.NewRecorder()
	QuoteGatewayBilling(&Dependencies{BillingStore: store, BillingMode: "metering"})(paid, httptest.NewRequest(http.MethodPost, "/internal/v1/billing/quotes", bytes.NewReader(payload)))
	if paid.Code != http.StatusTooManyRequests {
		t.Fatalf("zero estimate on nonfree model escaped balance guard=%d %s", paid.Code, paid.Body.String())
	}
}
