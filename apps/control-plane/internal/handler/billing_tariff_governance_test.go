package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRetireTariffAdminKeepsHistoryAndChangesNewQuote(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	ctx := context.Background()
	tenant := billingHandlerTestTenant(t, "retire-audit")
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES($1,$1,'enterprise','active')`, tenant); err != nil {
		t.Fatal(err)
	}
	repo := &capturingSystemRepo{}
	chain := &recordingChainWriter{}
	store := billing.NewStore(db)
	deps := &Dependencies{BillingStore: store, SystemRepo: repo, AuditAppender: audit_chain.NewAppender(chain, false)}
	plan, err := store.CreateTariffPlan(ctx, billing.NewTariffPlan{TenantID: tenant, Name: "retire", Timezone: "UTC", EffectiveAt: time.Now().Add(-time.Hour), Rules: []billing.TariffRule{{Code: "all", Name: "all", ModelName: "m", StartMinute: 0, EndMinute: 1440, MultiplierPPM: 1_200_000}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.PublishTariffPlan(ctx, tenant, plan.ID); err != nil {
		t.Fatal(err)
	}
	invoke := func(h http.HandlerFunc) *httptest.ResponseRecorder {
		req := billingHandlerAdminRequest(httptest.NewRequest(http.MethodPost, "/test?tenant_id="+tenant, nil), "admin", tenant, "platform_admin")
		route := chi.NewRouteContext()
		route.URLParams.Add("id", plan.ID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	rec := invoke(DeleteBillingTariffPlan(deps))
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "tariff_active") {
		t.Fatalf("active delete=%d %s", rec.Code, rec.Body.String())
	}
	rec = invoke(RetireBillingTariffPlan(deps))
	if rec.Code != 200 {
		t.Fatalf("retire=%d %s", rec.Code, rec.Body.String())
	}
	quote, err := store.ResolveTariffQuoteForModel(ctx, tenant, "m", time.Now())
	if err != nil || quote.MultiplierPPM != billing.TariffRatioFlat {
		t.Fatalf("new quote=%+v err=%v", quote, err)
	}
	rec = invoke(DeleteBillingTariffPlan(deps))
	if rec.Code != 204 {
		t.Fatalf("retired delete=%d %s", rec.Code, rec.Body.String())
	}
	history, err := store.GetTariffPlan(ctx, tenant, plan.ID)
	if err != nil || history.DeletedAt == nil || len(history.Rules) != 1 {
		t.Fatalf("history=%+v err=%v", history, err)
	}
	if len(repo.auditOps) != 2 || repo.auditOps[0].ActionType != "billing.tariff.retire" || repo.auditOps[1].ActionType != "billing.tariff.delete" || chain.count() != 2 {
		t.Fatalf("audit=%+v chain=%d", repo.auditOps, chain.count())
	}
}
