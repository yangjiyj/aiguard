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

// 切换系统币种仅平台管理员；租户管理员（admin/tenant_owner/tenant_admin）与三员分立角色一律 403。
func TestCurrencySwitchRoleAndTenantBoundary(t *testing.T) {
	for _, tc := range []struct {
		role, query string
		status      int
	}{
		{"developer", "", 403}, {"auditor", "", 403}, {"security_officer", "", 403}, {"platform_connector", "", 403},
		{"admin", "", 403}, {"tenant_owner", "", 403}, {"tenant_admin", "", 403},
		{"admin", "?tenant_id=other", 403}, {"tenant_owner", "?tenant_id=other", 403}, {"tenant_admin", "?tenant_id=other", 403},
		// platform_admin 通过角色闸门后，币种参数非法才得到 400。
		{"platform_admin", "?tenant_id=t", 400}, {"platform_admin", "", 400},
	} {
		t.Run(tc.role+tc.query, func(t *testing.T) {
			r := billingHandlerAdminRequest(httptest.NewRequest(http.MethodPost, "/admin/v1/billing/currency-switch"+tc.query, strings.NewReader(`{"currency":"EUR","preview":true}`)), "actor", "t", tc.role)
			w := httptest.NewRecorder()
			SwitchBillingCurrency(&Dependencies{})(w, r)
			if w.Code != tc.status {
				t.Fatalf("状态=%d %s", w.Code, w.Body.String())
			}
		})
	}
}

// 未登录与平台管理员缺租户：401 / 400。
func TestCurrencySwitchRequiresLoginAndTenant(t *testing.T) {
	w := httptest.NewRecorder()
	SwitchBillingCurrency(&Dependencies{})(w, httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{}`)))
	if w.Code != 401 {
		t.Fatalf("未登录应 401：%d", w.Code)
	}
	w = httptest.NewRecorder()
	SwitchBillingCurrency(&Dependencies{})(w, billingHandlerAdminRequest(httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(`{"currency":"USD","preview":true}`)), "actor", "", "platform_admin"))
	if w.Code != 400 {
		t.Fatalf("缺租户应 400：%d", w.Code)
	}
}

func TestEmployeeBillingSettingsRoleAndTenantBoundary(t *testing.T) {
	for _, tc := range []struct {
		role, tenant, query string
		status              int
	}{
		{"developer", "t", "", 403}, {"auditor", "t", "", 403}, {"security_officer", "t", "", 403}, {"platform_connector", "t", "", 403},
		{"admin", "t", "?tenant_id=other", 403}, {"tenant_owner", "t", "?tenant_id=other", 403}, {"tenant_admin", "t", "?tenant_id=other", 403},
		{"platform_admin", "t", "?tenant_id=other", 503}, {"platform_admin", "t", "", 503},
		{"admin", "t", "", 503}, {"tenant_owner", "t", "", 503}, {"tenant_admin", "t", "", 503},
		{"admin", "t", "?tenant_id=t", 503}, {"tenant_owner", "t", "?tenant_id=t", 503}, {"tenant_admin", "t", "?tenant_id=t", 503},
		{"platform_admin", "", "", 400},
	} {
		t.Run(tc.role+tc.tenant+tc.query, func(t *testing.T) {
			r := billingHandlerAdminRequest(httptest.NewRequest(http.MethodGet, "/admin/v1/billing/employee-settings"+tc.query, nil), "actor", tc.tenant, tc.role)
			w := httptest.NewRecorder()
			GetEmployeeBillingSettings(&Dependencies{})(w, r)
			if w.Code != tc.status {
				t.Fatalf("状态=%d，预期=%d，响应=%s", w.Code, tc.status, w.Body.String())
			}
		})
	}
}

func switchRequest(t *testing.T, store *billing.Store, tenant, actor, body string) (int, map[string]any) {
	t.Helper()
	r := billingHandlerAdminRequest(httptest.NewRequest(http.MethodPost, "/admin/v1/billing/currency-switch?tenant_id="+tenant, strings.NewReader(body)), actor, tenant, "platform_admin")
	w := httptest.NewRecorder()
	SwitchBillingCurrency(&Dependencies{BillingStore: store})(w, r)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

// 预览返回 unpriced_models / legacy_orphan_prices；有清单且没带 confirm_unpriced 时执行返回 409 并带清单，
// 带上确认后才真正执行。
func TestSwitchBillingCurrencyHTTPUnpricedConfirmContract(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	ctx := context.Background()
	tenant := billingHandlerTestTenant(t, "sw-unpriced")
	user := tenant + "-u"
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',TRUE)`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,email,password_hash,role,status) VALUES($1,$2,$1,$3,'x','platform_admin','active')`, user, tenant, user+"@t.invalid"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(context.Background(), `UPDATE tenants SET status='disabled' WHERE id=$1`, tenant)
	})
	store := billing.NewStore(db)
	if err := store.EnsureDefaultCustomerGroup(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	prov := tenant + "-p"
	for _, stmt := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO providers(id,tenant_id,name,provider_type,status) VALUES($2::varchar,$1::varchar,'p','openai','active')`, []any{tenant, prov}},
		{`INSERT INTO models(id,provider_id,model_name,status) VALUES($1::varchar||'-m',$1::varchar,'live-model','active')`, []any{prov}},
		{`INSERT INTO billing_model_prices(id,tenant_id,model_name,version,pricing_mode,currency,input_per_million_micros,output_per_million_micros,status,effective_at) VALUES($2::varchar||'-pr',$1::varchar,'live-model',1,'direct','CNY',1,1,'active',NOW()-INTERVAL '1 hour')`, []any{tenant, prov}},
		{`INSERT INTO billing_model_prices(id,tenant_id,model_name,version,pricing_mode,currency,input_per_million_micros,output_per_million_micros,status,effective_at) VALUES($2::varchar||'-orph',$1::varchar,'orphan-model',1,'direct','CNY',1,1,'active',NOW()-INTERVAL '1 hour')`, []any{tenant, prov}},
	} {
		if _, err := db.Exec(ctx, stmt.sql, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	code, preview := switchRequest(t, store, tenant, user, `{"currency":"USD","preview":true}`)
	if code != 200 {
		t.Fatalf("预览：%d %+v", code, preview)
	}
	data := preview["data"].(map[string]any)
	unpriced := data["unpriced_models"].([]any)
	orphans := data["legacy_orphan_prices"].(map[string]any)
	if len(unpriced) != 1 || unpriced[0].(map[string]any)["model_name"] != "live-model" || orphans["pairs"].(float64) != 1 || orphans["rows"].(float64) != 1 {
		t.Fatalf("预览契约：%+v", data)
	}
	token := data["confirm_token"].(string)
	// 不带确认：409 + 清单。
	code, refused := switchRequest(t, store, tenant, user, `{"currency":"USD","preview":false,"confirm_token":"`+token+`"}`)
	errBody, _ := refused["error"].(map[string]any)
	if code != 409 || errBody["code"] != "currency_switch_unpriced_confirm_required" || len(refused["unpriced_models"].([]any)) != 1 {
		t.Fatalf("未确认应 409：%d %+v", code, refused)
	}
	// 带确认：执行。
	code, done := switchRequest(t, store, tenant, user, `{"currency":"USD","preview":false,"confirm_token":"`+token+`","confirm_unpriced":true}`)
	if code != 200 || done["data"].(map[string]any)["executed"] != true {
		t.Fatalf("确认后应执行：%d %+v", code, done)
	}
}
