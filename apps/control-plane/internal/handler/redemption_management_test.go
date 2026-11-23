package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRedemptionAdministrationCSVDetailsAndBatchPreserveAccessBoundary(t *testing.T) {
	db, _, _ := setupOrgHandlerPool(t)
	tenant := "redemption_admin_" + uuid.NewString()[:8]
	admin := tenant + "_user"
	mustExec(t, db, "INSERT INTO tenants(id,name,is_test) VALUES($1,$1,true)", tenant)
	mustExec(t, db, "INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,$1,'platform_admin','active')", admin, tenant)
	ctx := context.Background()
	store := billing.NewStore(db)
	deps := &Dependencies{BillingStore: store}
	codes, err := store.CreateRedemptionCodes(ctx, billing.NewRedemptionBatch{TenantID: tenant, Label: "export-fixture", AmountMicros: 200, Count: 2, CreatedBy: admin})
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, path, body, role string) *http.Request {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		c := context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: admin, TenantID: tenant, Role: role})
		route := chi.NewRouteContext()
		route.URLParams.Add("id", codes[0].ID)
		return r.WithContext(context.WithValue(c, chi.RouteCtxKey, route))
	}
	export := httptest.NewRecorder()
	ExportBillingRedemptionHints(deps)(export, request("GET", "/x?tenant_id="+tenant+"&batch=export-fixture", "", "platform_admin"))
	if export.Code != 200 || !strings.HasPrefix(export.Body.String(), "code_hint,status") || strings.Contains(export.Body.String(), codes[0].Code) {
		t.Fatal("CSV exposes plaintext or misses hint/status")
	}
	denied := httptest.NewRecorder()
	ExportBillingRedemptionHints(deps)(denied, request("GET", "/x?tenant_id="+tenant+"&batch=export-fixture", "", "viewer"))
	if denied.Code != 403 {
		t.Fatal("viewer accessed billing administration")
	}
	if _, _, err = store.RedeemCode(ctx, tenant, admin, codes[0].Code); err != nil {
		t.Fatal(err)
	}
	detail := httptest.NewRecorder()
	GetBillingRedemptionDetail(deps)(detail, request("GET", "/x?tenant_id="+tenant, "", "platform_admin"))
	var body struct {
		Data struct {
			LedgerID string `json:"ledger_id"`
		}
	}
	if detail.Code != 200 || json.Unmarshal(detail.Body.Bytes(), &body) != nil || body.Data.LedgerID == "" {
		t.Fatal("exact ledger detail unavailable")
	}
	foreign := httptest.NewRecorder()
	GetBillingRedemptionDetail(deps)(foreign, request("GET", "/x?tenant_id=foreign-tenant", "", "platform_admin"))
	if foreign.Code < 400 {
		t.Fatal("foreign detail leaked")
	}
	payload, _ := json.Marshal(map[string]any{"tenant_id": tenant, "ids": []string{codes[0].ID, codes[1].ID}})
	batch := httptest.NewRecorder()
	BatchUpdateBillingRedemptions(deps)(batch, request("POST", "/x", string(payload), "platform_admin"))
	if batch.Code != 200 || !strings.Contains(batch.Body.String(), `"changed":1`) {
		t.Fatal("batch must not change a redeemed code")
	}
}
