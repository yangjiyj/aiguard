package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestProxyMeasurementDoesNotRequireBillingStore(t *testing.T) {
	for _, source := range []string{"forward_proxy", "reverse_proxy"} {
		payload, _ := json.Marshal(map[string]any{"usage_source": source, "model_name": "priced-model"})
		w := httptest.NewRecorder()
		RecordGatewayMeasurement(nil)(w, httptest.NewRequest(http.MethodPost, "/internal/v1/billing/measurements", bytes.NewReader(payload)))
		if w.Code != 200 {
			t.Fatalf("source=%s status=%d %s", source, w.Code, w.Body.String())
		}
	}
}

func TestProxyObservationCannotDebitOrReleaseDirectReservations(t *testing.T) {
	db, store, tenant, user, _ := billingEndToEndFixture(t)
	ctx := context.Background()
	limit := int64(1000)
	if err := store.SaveEmployeeSettings(ctx, tenant, billing.EmployeeSettings{Currency: "CNY", Timezone: "Asia/Shanghai", DefaultMonthlyMicros: &limit}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateModelPrice(ctx, billing.NewModelPrice{TenantID: tenant, ModelName: "direct-priced", Currency: "CNY", PricingMode: billing.PricingModeDirect, DirectPrice: billing.DirectPrice{InputPerMillionMicros: 1_000_000, OutputPerMillionMicros: 1_000_000}, EffectiveAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	request := tenant + "-direct-hold"
	payload, _ := json.Marshal(map[string]any{"tenant_id": tenant, "user_id": user, "request_id": request, "model_name": "direct-priced", "usage": billing.Usage{PromptTokens: 1, OutputTokens: 1}})
	quoted := httptest.NewRecorder()
	QuoteGatewayBilling(&Dependencies{BillingStore: store})(quoted, httptest.NewRequest(http.MethodPost, "/internal/v1/billing/quotes", bytes.NewReader(payload)))
	if quoted.Code != 200 {
		t.Fatalf("quote=%d %s", quoted.Code, quoted.Body.String())
	}
	for _, source := range []string{"forward_proxy", "reverse_proxy"} {
		payload, _ := json.Marshal(map[string]any{"tenant_id": tenant, "user_id": user, "request_id": request, "model_name": "direct-priced", "usage_source": source, "request_status": "success", "usage": billing.Usage{PromptTokens: 500, OutputTokens: 500}})
		rec := httptest.NewRecorder()
		RecordGatewayMeasurement(&Dependencies{BillingStore: store})(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/billing/measurements", bytes.NewReader(payload)))
		if rec.Code != 200 {
			t.Fatalf("proxy=%d %s", rec.Code, rec.Body.String())
		}
	}
	var balance, reserved, employee, facts int64
	if err := db.QueryRow(ctx, `SELECT balance_micros,reserved_micros FROM billing_wallets WHERE tenant_id=$1 AND user_id=$2`, tenant, user).Scan(&balance, &reserved); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COALESCE(SUM(amount_micros),0) FROM billing_employee_reservations WHERE tenant_id=$1`, tenant).Scan(&employee); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_usage_facts WHERE tenant_id=$1`, tenant).Scan(&facts); err != nil {
		t.Fatal(err)
	}
	if balance != 1_001_000 || reserved != 2 || employee != 0 || facts != 0 {
		t.Fatalf("balance=%d reserved=%d employee=%d facts=%d", balance, reserved, employee, facts)
	}
}
