package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestPriceCurrencyMismatchHTTPContract(t *testing.T) {
	w := httptest.NewRecorder()
	billingHTTPError(w, billing.ErrPriceCurrencyMismatch)
	if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), `"price_currency_mismatch"`) || !strings.Contains(w.Body.String(), "该模型价格币种与系统币种不一致，请管理员重新设置价格") {
		t.Fatalf("价格币种错误响应：%d %s", w.Code, w.Body.String())
	}
}

func TestBillingAnalyticsFilterParsesCurrencyForAuthorizedUser(t *testing.T) {
	for _, currency := range []string{"USD", "CNY", "EUR"} {
		r := billingHandlerAdminRequest(httptest.NewRequest("GET", "/?currency="+currency, nil), "admin", "tenant", "tenant_admin")
		w := httptest.NewRecorder()
		filter, ok := billingAnalyticsFilter(w, r, &Dependencies{})
		if currency == "EUR" {
			if ok || w.Code != 400 {
				t.Fatalf("应拒绝未知币种：%v %d", ok, w.Code)
			}
		} else if !ok || filter.Currency != currency {
			t.Fatalf("查询币种未生效：%+v %v", filter, ok)
		}
	}
}

func TestGatewayRejectsForeignCurrencyPriceBeforeCreatingWallet(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	ctx := context.Background()
	tenant := billingHandlerTestTenant(t, "price-mismatch")
	user := tenant + "-user"
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES($1,$1,'enterprise','active')`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,$1,'developer','active')`, user, tenant); err != nil {
		t.Fatal(err)
	}
	store := billing.NewStore(db)
	if err := store.SaveEmployeeSettings(ctx, tenant, billing.EmployeeSettings{Currency: "USD", Timezone: "UTC"}); err != nil {
		t.Fatal(err)
	}
	if err := store.EnsureDefaultCustomerGroup(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	// 只剩旧币种 active 价格时，解析可查得它，但准入不得创建该币种的钱包。
	if _, err := db.Exec(ctx, `INSERT INTO billing_model_prices(id,tenant_id,model_name,version,pricing_mode,currency,input_per_million_micros,output_per_million_micros,status,effective_at) VALUES($1,$2,'legacy-only',1,'direct','CNY',100,100,'active',NOW()-INTERVAL '1 hour')`, tenant+"-price", tenant); err != nil {
		t.Fatal(err)
	}
	for _, handler := range []http.HandlerFunc{ReserveGatewayBilling(&Dependencies{BillingStore: store}), QuoteGatewayBilling(&Dependencies{BillingStore: store})} {
		body, _ := json.Marshal(BillingReserveRequest{TenantID: tenant, UserID: user, RequestID: tenant + "-req", ModelName: "legacy-only", Usage: billing.Usage{PromptTokens: 10}})
		r := httptest.NewRequest(http.MethodPost, "/internal/v1/billing/reserve", strings.NewReader(string(body)))
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "price_currency_mismatch") {
			t.Fatalf("错误币种应拒绝：%d %s", w.Code, w.Body.String())
		}
	}
	var count int
	if err := db.QueryRow(ctx, `SELECT COUNT(*) FROM billing_wallets WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("错误币种创建了钱包：%d %v", count, err)
	}
}
