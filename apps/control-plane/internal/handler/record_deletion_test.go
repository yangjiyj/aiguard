package handler

import (
	"context"
	"fmt"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/billing"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestKeyDeleteHTTPRequiresAdminOrExactPortalOwner(t *testing.T) {
	deps, db, tenant, user, project := portalProjectFixture(t)
	key := &repository.InternalKey{TenantID: tenant, UserID: user, ProjectID: project, Status: "active"}
	if err := deps.KeyRepo.Create(context.Background(), key, "sk-delete-http-"+tenant); err != nil {
		t.Fatal(err)
	}
	route := chi.NewRouter()
	route.Delete("/keys/{id}", DeleteKey(deps))
	route.Delete("/personal/{id}", DeletePortalCustomerKey(deps))
	request := func(path, role string, portal bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodDelete, path, nil)
		if portal {
			r.Header.Set("X-JJDGuard-Tenant-Id", tenant)
		} else {
			r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: user, TenantID: tenant, Role: role}))
		}
		w := httptest.NewRecorder()
		route.ServeHTTP(w, r)
		return w
	}
	for _, role := range []string{"viewer", "security_officer", "auditor", "dept_manager", "developer"} {
		if w := request("/keys/"+key.ID, role, false); w.Code != 403 {
			t.Fatalf("%s deleted key: %d", role, w.Code)
		}
	}
	if w := request("/personal/"+key.ID+"?user_id=foreign", "", true); w.Code != 404 {
		t.Fatalf("foreign owner got %d", w.Code)
	}
	if w := request("/personal/"+key.ID+"?user_id="+user, "", true); w.Code != 204 {
		t.Fatalf("owner delete: %d %s", w.Code, w.Body.String())
	}
	got, err := deps.KeyRepo.GetByHash(context.Background(), key.KeyHash)
	if err != nil || got.IsValid() {
		t.Fatal("old key remains usable")
	}
	var count int
	if err = db.QueryRow(context.Background(), "SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND action_type='portal_delete_key'", tenant).Scan(&count); err != nil || count != 1 {
		t.Fatal("missing owner audit")
	}
}

func TestRedemptionDeleteHTTPArchivesRedeemedAndRejectsNonAdmin(t *testing.T) {
	db, _, _ := setupOrgHandlerPool(t)
	tenant := "archive_http_" + fmt.Sprint(time.Now().UnixNano())
	user := tenant + "_admin"
	mustExec(t, db, "INSERT INTO tenants(id,name,is_test) VALUES($1,$1,true)", tenant)
	mustExec(t, db, "INSERT INTO users(id,tenant_id,username,role,status) VALUES($1,$2,$1,'platform_admin','active')", user, tenant)
	store := billing.NewStore(db)
	deps := &Dependencies{BillingStore: store}
	codes, err := store.CreateRedemptionCodes(context.Background(), billing.NewRedemptionBatch{TenantID: tenant, Label: "http-delete", AmountMicros: 200, Count: 1, CreatedBy: user})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = store.RedeemCode(context.Background(), tenant, user, codes[0].Code); err != nil {
		t.Fatal(err)
	}
	route := chi.NewRouter()
	route.Delete("/redemptions/{id}", DeleteBillingRedemption(deps))
	for _, role := range []string{"viewer", "tenant_admin", "platform_admin"} {
		r := httptest.NewRequest("DELETE", "/redemptions/"+codes[0].ID+"?tenant_id="+tenant, nil)
		r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: user, TenantID: tenant, Role: role}))
		w := httptest.NewRecorder()
		route.ServeHTTP(w, r)
		want := 403
		if role == "platform_admin" {
			want = 204
		}
		if w.Code != want {
			t.Fatalf("role %s status %d", role, w.Code)
		}
	}
}
