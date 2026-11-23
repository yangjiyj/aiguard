package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminCreditUsesTenantUSDCurrencyWithGlobalCNYDefault(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	ctx := context.Background()
	tenant := billingHandlerTestTenant(t, "usd-credit")
	user := tenant + "-u"
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES($1,$1,'enterprise','active')`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,$1,'developer','active')`, user, tenant); err != nil {
		t.Fatal(err)
	}
	store := billing.NewStore(db)
	if err := store.SaveEmployeeSettings(ctx, tenant, billing.EmployeeSettings{Currency: "USD", Timezone: "Asia/Shanghai"}); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"tenant_id": tenant, "user_id": user, "amount_micros": 1000, "idempotency_key": tenant + "-credit", "reason": "QA synthetic currency proof"})
	req := billingHandlerAdminRequest(httptest.NewRequest(http.MethodPost, "/admin/v1/billing/customers/credit", bytes.NewReader(payload)), "test-admin", tenant, "platform_admin")
	recorder := httptest.NewRecorder()
	CreditCustomerWallet(&Dependencies{BillingStore: store})(recorder, req)
	if recorder.Code != 200 {
		t.Fatalf("credit=%d %s", recorder.Code, recorder.Body.String())
	}
	wallet, err := store.FindWalletForUser(ctx, tenant, user, "USD")
	if err != nil || wallet == nil || wallet.BalanceMicros != 1000 {
		t.Fatalf("wallet=%+v err=%v", wallet, err)
	}
	var cny int64
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_wallets WHERE tenant_id=$1 AND currency='CNY'`, tenant).Scan(&cny); err != nil || cny != 0 {
		t.Fatalf("CNY wallets=%d err=%v", cny, err)
	}
}
