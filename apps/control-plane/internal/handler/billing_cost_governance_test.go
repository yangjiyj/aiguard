package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

func TestFixedCostAdminCRUDWritesCriticalAuditAndRejectsCurrency(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	ctx := context.Background()
	tenant := billingHandlerTestTenant(t, "fixed-audit")
	actor := tenant + "-actor"
	provider := tenant + "-provider"
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES($1,$1,'enterprise','active')`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO users(id,tenant_id,username,email,password_hash,role,status) VALUES($1::varchar,$2::varchar,$1::varchar,$1::text||'@test.invalid','x','platform_admin','active')`, actor, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type) VALUES($1,$2,$1,'openai')`, provider, tenant); err != nil {
		t.Fatal(err)
	}
	repo := &capturingSystemRepo{}
	chain := &recordingChainWriter{}
	deps := &Dependencies{BillingStore: billing.NewStore(db), SystemRepo: repo, AuditAppender: audit_chain.NewAppender(chain, false)}
	invoke := func(method, url string, payload any, h http.HandlerFunc) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(payload)
		req := billingHandlerAdminRequest(httptest.NewRequest(method, url, strings.NewReader(string(body))), actor, tenant, "platform_admin")
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec
	}
	req := billing.ChannelFixedCost{ProviderID: provider, Currency: "CNY", AmountMicros: 100_000_000, Period: "month", EffectiveFrom: "2026-10-01", Note: "contract"}
	rec := invoke(http.MethodPut, "/test?tenant_id="+tenant, req, PutBillingChannelFixedCost(deps))
	if rec.Code != 200 {
		t.Fatalf("save=%d %s", rec.Code, rec.Body.String())
	}
	var result struct{ Data billing.ChannelFixedCost }
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	req.ID = result.Data.ID
	req.Currency = "USD"
	rec = invoke(http.MethodPut, "/test?tenant_id="+tenant, req, PutBillingChannelFixedCost(deps))
	if rec.Code != 409 || !strings.Contains(rec.Body.String(), "cost_currency_mismatch") {
		t.Fatalf("currency=%d %s", rec.Code, rec.Body.String())
	}
	rec = invoke(http.MethodGet, "/test?tenant_id="+tenant, nil, ListBillingChannelFixedCosts(deps))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), provider) {
		t.Fatalf("list=%d %s", rec.Code, rec.Body.String())
	}
	rec = invoke(http.MethodDelete, "/test?tenant_id="+tenant+"&id="+result.Data.ID, nil, DeleteBillingChannelFixedCost(deps))
	if rec.Code != 204 {
		t.Fatalf("delete=%d %s", rec.Code, rec.Body.String())
	}
	if len(repo.auditOps) != 2 || repo.auditOps[0].ActionType != "billing.channel_fixed_cost.upsert" || repo.auditOps[1].ActionType != "billing.channel_fixed_cost.delete" || chain.count() != 2 {
		t.Fatalf("audit=%+v chain=%d", repo.auditOps, chain.count())
	}
}
