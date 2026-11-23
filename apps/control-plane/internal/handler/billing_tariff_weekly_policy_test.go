package handler

import (
	"context"
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestTariffAPIsRejectNewDateRulesBeforeDatabaseWrites(t *testing.T) {
	deps := &Dependencies{BillingStore: billing.NewStore(nil)}
	for name, handler := range map[string]http.HandlerFunc{"create": CreateBillingTariffPlan(deps), "update": UpdateBillingTariffPlan(deps)} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/test?tenant_id=tenant-a", strings.NewReader(`{"name":"weekly","timezone":"UTC","rules":[{"code":"date","name":"date","model_name":"model-a","special_date":"2026-10-01T00:00:00Z","start_minute":0,"end_minute":1440,"multiplier_ppm":700000}]}`))
			request = billingHandlerAdminRequest(request, "admin-a", "tenant-a", "platform_admin")
			response := httptest.NewRecorder()
			handler(response, request)
			var body struct {
				Error struct {
					Code string `json:"code"`
				} `json:"error"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if response.Code != http.StatusBadRequest || body.Error.Code != "tariff_date_rules_unsupported" {
				t.Fatalf("status=%d code=%s", response.Code, body.Error.Code)
			}
		})
	}
}

func TestLegacyTariffWriteErrorsHaveReadableConflictCode(t *testing.T) {
	response := httptest.NewRecorder()
	billingTariffHTTPError(response, billing.ErrTariffLegacyDateRulesReadOnly)
	var body struct {
		Error struct{ Code, Message string } `json:"error"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusConflict || body.Error.Code != "tariff_legacy_date_rules_read_only" || body.Error.Message == "" {
		t.Fatalf("status=%d code=%s", response.Code, body.Error.Code)
	}
}

func TestLegacyDateTariffAPIRefusesWeeklyReplacement(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	store := billing.NewStore(db)
	ctx := context.Background()
	tenant := billingHandlerTestTenant(t, "legacy-api")
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES($1,$1,'enterprise','active')`, tenant); err != nil {
		t.Fatal(err)
	}
	input := billing.NewTariffPlan{TenantID: tenant, Name: "legacy-api", Rules: []billing.TariffRule{{Code: "original", Name: "original", ModelName: "model-a", StartMinute: 0, EndMinute: 1440, MultiplierPPM: 700000}}}
	plan, err := store.CreateTariffPlan(ctx, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.PublishTariffPlan(ctx, tenant, plan.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(ctx, `UPDATE billing_tariff_rules SET special_date='2026-10-01' WHERE tenant_id=$1 AND plan_id=$2`, tenant, plan.ID); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/test?tenant_id="+tenant, strings.NewReader(`{"name":"replacement","rules":[{"code":"weekly","name":"weekly","model_name":"model-a","start_minute":0,"end_minute":1440,"multiplier_ppm":1000000}]}`))
	request = billingHandlerAdminRequest(request, "admin-a", tenant, "platform_admin")
	route := chi.NewRouteContext()
	route.URLParams.Add("id", plan.ID)
	request = request.WithContext(context.WithValue(request.Context(), chi.RouteCtxKey, route))
	response := httptest.NewRecorder()
	UpdateBillingTariffPlan(&Dependencies{BillingStore: store})(response, request)
	var body struct {
		Error struct{ Code string } `json:"error"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusConflict || body.Error.Code != "tariff_legacy_date_rules_read_only" {
		t.Fatalf("status=%d code=%s", response.Code, body.Error.Code)
	}
	original, err := store.GetTariffPlan(ctx, tenant, plan.ID)
	if err != nil || original.Status != "active" || original.Version != 1 || original.Rules[0].SpecialDate == nil || original.Rules[0].MultiplierPPM != 700000 {
		t.Fatalf("API changed historical plan=%+v err=%v", original, err)
	}
}
