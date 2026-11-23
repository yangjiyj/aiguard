package handler

import (
	"context"
	"encoding/json"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"net/http/httptest"
	"testing"
)

func TestRedemptionRevealAdminOnly(t *testing.T) {
	for _, role := range []string{"viewer", "developer", "tenant_admin"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/x?tenant_id=t", nil)
		r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: "u", Role: role}))
		RevealBillingRedemption(nil)(w, r)
		if w.Code != 403 {
			t.Fatalf("role %s accepted", role)
		}
	}
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "fixture-redemption-encryption-secret")
	db, tenant, user := setupOrgHandlerPool(t)
	t.Cleanup(func() {
		_, err := db.Exec(context.Background(), "DELETE FROM billing_redemption_codes WHERE tenant_id=$1", tenant)
		if err != nil {
			t.Error(err)
		}
	})
	s := billing.NewStore(db)
	codes, err := s.CreateRedemptionCodes(context.Background(), billing.NewRedemptionBatch{TenantID: tenant, Label: "copy-fixture", AmountMicros: 100, Count: 1, CreatedBy: user})
	if err != nil {
		t.Fatal("create failed")
	}
	for _, target := range []string{tenant, "other-tenant"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/x?tenant_id="+target, nil)
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", codes[0].ID)
		ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rc)
		ctx = context.WithValue(ctx, auth.UserKey, &repository.User{ID: user, Role: "platform_admin"})
		RevealBillingRedemption(&Dependencies{BillingStore: s})(w, r.WithContext(ctx))
		if target != tenant {
			if w.Code != 404 {
				t.Fatal("cross tenant accepted")
			}
			continue
		}
		if w.Code != 200 || w.Header().Get("Cache-Control") != "private, no-store" {
			t.Fatal("copy response contract")
		}
		var body struct {
			Data struct {
				Code string `json:"code"`
			} `json:"data"`
		}
		if json.Unmarshal(w.Body.Bytes(), &body) != nil || body.Data.Code != codes[0].Code {
			t.Fatal("copy mismatch")
		}
	}
}
