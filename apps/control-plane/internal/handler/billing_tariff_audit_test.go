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

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
)

// 新建资费草稿与发布资费都要写操作审计，并同步进入审计链（关键事件）。
func TestCreateAndPublishBillingTariffPlanWriteAudit(t *testing.T) {
	db := openBillingHandlerTestDB(t)
	systemRepo := &capturingSystemRepo{}
	chain := &recordingChainWriter{}
	deps := &Dependencies{BillingStore: billing.NewStore(db), SystemRepo: systemRepo, AuditAppender: audit_chain.NewAppender(chain, false)}
	ctx := context.Background()
	tenantID := billingHandlerTestTenant(t, "htaudit")
	if _, err := db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status) VALUES ($1,$1,'enterprise','active')`, tenantID); err != nil {
		t.Fatal(err)
	}
	rule := billing.TariffRule{Code: "flat", Name: "全天", ModelName: "model-a", Band: billing.TariffBandFlat,
		Weekdays: []int16{1, 2, 3, 4, 5, 6, 7}, StartMinute: 0, EndMinute: 1440, MultiplierPPM: 1_000_000}
	body, _ := json.Marshal(createTariffPlanRequest{Name: "审计资费", Timezone: "Asia/Shanghai", EffectiveAt: time.Now().UTC(), Rules: []billing.TariffRule{rule}})
	req := billingHandlerAdminRequest(httptest.NewRequest(http.MethodPost, "/test?tenant_id="+tenantID, strings.NewReader(string(body))), "admin-a", tenantID, "platform_admin")
	rec := httptest.NewRecorder()
	CreateBillingTariffPlan(deps)(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created struct {
		Data billing.TariffPlan `json:"data"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	req = billingHandlerAdminRequest(httptest.NewRequest(http.MethodPost, "/test?tenant_id="+tenantID, nil), "admin-a", tenantID, "platform_admin")
	route := chi.NewRouteContext()
	route.URLParams.Add("id", created.Data.ID)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, route))
	rec = httptest.NewRecorder()
	PublishBillingTariffPlan(deps)(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("publish status=%d body=%s", rec.Code, rec.Body.String())
	}
	actions := []string{}
	for _, op := range systemRepo.auditOps {
		actions = append(actions, op.ActionType)
	}
	if strings.Join(actions, ",") != "billing.tariff.create,billing.tariff.publish" {
		t.Fatalf("audit actions=%v", actions)
	}
	if chain.count() != 2 {
		t.Fatalf("tariff audits must be in the chain synchronously, got %d", chain.count())
	}
}
