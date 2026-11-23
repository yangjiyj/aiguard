package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestUpdateBillingTariffValidatesAdminAndPayload(t *testing.T) {
	deps := &Dependencies{BillingStore: billing.NewStore(nil)}
	for _, tc := range []struct {
		name, role, query, body string
		status                  int
	}{
		{"unauthenticated", "", "tenant_id=tenant-a", `{}`, http.StatusUnauthorized},
		{"employee", "developer", "tenant_id=tenant-a", `{}`, http.StatusForbidden},
		{"missing tenant", "platform_admin", "", `{}`, http.StatusBadRequest},
		{"malformed JSON", "platform_admin", "tenant_id=tenant-a", `{`, http.StatusBadRequest},
		{"no rules", "platform_admin", "tenant_id=tenant-a", `{"name":"p","rules":[]}`, http.StatusBadRequest},
		{"missing model", "platform_admin", "tenant_id=tenant-a", `{"name":"p","rules":[{"name":"a"}]}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/test?"+tc.query, strings.NewReader(tc.body))
			if tc.role != "" {
				req = billingHandlerAdminRequest(req, "admin-a", "tenant-a", tc.role)
			}
			rec := httptest.NewRecorder()
			UpdateBillingTariffPlan(deps)(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status=%d body=%s, want %d", rec.Code, rec.Body.String(), tc.status)
			}
		})
	}
}

func TestUpdateBillingTariffHandlerVersionsAndTenantScope(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	store := billing.NewStore(db)
	deps := &Dependencies{BillingStore: store}
	ctx := context.Background()
	tenantID := billingHandlerTestTenant(t, "htariff")
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, tenantID); err != nil {
		t.Fatal(err)
	}
	rule := billing.TariffRule{Code: "flat", Name: "全天", ModelName: "model-a", Band: billing.TariffBandFlat,
		Weekdays: []int16{1, 2, 3, 4, 5, 6, 7}, StartMinute: 0, EndMinute: 1440, MultiplierPPM: 1_000_000}
	plan, err := store.CreateTariffPlan(ctx, billing.NewTariffPlan{TenantID: tenantID, Name: "editable", Timezone: "Asia/Shanghai", Rules: []billing.TariffRule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PublishTariffPlan(ctx, tenantID, plan.ID); err != nil {
		t.Fatal(err)
	}
	rule.MultiplierPPM = 700_000
	body, err := json.Marshal(createTariffPlanRequest{Name: plan.Name, Timezone: "Asia/Shanghai", EffectiveAt: time.Now().UTC(), Rules: []billing.TariffRule{rule}})
	if err != nil {
		t.Fatal(err)
	}
	call := func(tenant string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/test?tenant_id="+tenant, strings.NewReader(string(body)))
		req = billingHandlerAdminRequest(req, "admin-a", tenantID, "platform_admin")
		route := chi.NewRouteContext()
		route.URLParams.Add("id", plan.ID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
		rec := httptest.NewRecorder()
		UpdateBillingTariffPlan(deps)(rec, req)
		return rec
	}
	if rec := call(tenantID + "_other"); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec := call(tenantID)
	if rec.Code != http.StatusOK {
		t.Fatalf("edit status=%d body=%s", rec.Code, rec.Body.String())
	}
	var response struct {
		Data billing.TariffPlan `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Data.ID == plan.ID || response.Data.Version != 2 || response.Data.Status != "draft" || response.Data.Rules[0].MultiplierPPM != 700_000 {
		t.Fatalf("edit response = %#v", response.Data)
	}
	quote, err := store.ResolveTariffQuoteForModel(ctx, tenantID, "model-a", time.Now().UTC())
	if err != nil || quote.PlanVersion != 1 || quote.MultiplierPPM != 1_000_000 {
		t.Fatalf("unpublished draft changed active billing: quote=%#v err=%v", quote, err)
	}
}
