package handler

import (
	"context"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
	"net/http/httptest"
	"testing"
 "time"
 "github.com/yangjiyj/aiguard/apps/control-plane/internal/audit_chain"
)

func TestPortalOwnedKeyRevokeRequiresExactUserAndAudits(t *testing.T) {
	e, u, dept := chatLoginFixture(t)
	ctx := context.Background()
 chain:=&recordingChainWriter{};e.deps.AuditAppender=audit_chain.NewAppender(chain,false)
	project := u.ID + "-key-project"
	if _, err := e.pool.Exec(ctx, "INSERT INTO projects(id,tenant_id,name,team_id,status) VALUES($1,$2,$1,$3,'active')", project, e.tenantID, dept); err != nil {
		t.Fatal(err)
	}
	keys := repository.NewInternalKeyRepository(e.pool)
	e.deps.KeyRepo = keys
	k := &repository.InternalKey{TenantID: e.tenantID, UserID: u.ID, ProjectID: project, Status: "active", Scopes: []string{"chat"}}
	if err := keys.Create(ctx, k, "fixture-private-key-not-for-logs"); err != nil {
		t.Fatal(err)
	}
	revoke := func(user string) int {
		r := httptest.NewRequest("POST", "/keys/"+k.ID+"/revoke?user_id="+user, nil)
		r.Header.Set(portalIntegrationTenantHeader, e.tenantID)
 r.RemoteAddr="198.51.100.25:1234"
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", k.ID)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
		w := httptest.NewRecorder()
		RevokePortalKey(e.deps)(w, r)
		return w.Code
	}
	if status := revoke("another-user"); status != 404 {
		t.Fatalf("foreign revoke status=%d", status)
	}
	kept, err := keys.GetByID(ctx, e.tenantID, k.ID)
	if err != nil || kept.Status != "active" {
		t.Fatal("foreign revoke changed key")
	}
	if status := revoke(u.ID); status != 204 {
		t.Fatalf("self revoke status=%d", status)
	}
	if status := revoke(u.ID); status != 204 {
		t.Fatalf("idempotent revoke status=%d", status)
	}
 var ip string
 if err:=e.pool.QueryRow(ctx,"SELECT ip_address FROM audit_operations WHERE tenant_id=$1 AND target_id=$2 ORDER BY created_at LIMIT 1",e.tenantID,k.ID).Scan(&ip);err!=nil || ip!="198.51.100.25" {t.Errorf("audit source=%q err=%v",ip,err)}
 want:=1
 deadline:=time.Now().Add(time.Second)
 for chain.count()<want && time.Now().Before(deadline){time.Sleep(time.Millisecond)}
 if chain.count()!=want {t.Errorf("committed audit missing in chain: %d",chain.count())}
	var count int
	if err = e.pool.QueryRow(ctx, "SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND user_id=$2 AND target_id=$3 AND action_type='portal_revoke_key'", e.tenantID, u.ID, k.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("real-user audits=%d err=%v", count, err)
	}
}

func TestManagedEmployeeKeyDoesNotConsumePersonalKeySlots(t *testing.T) {
	keys := []*repository.InternalKey{{Status: "active", IsEmployee: true}, {Status: "active"}, {Status: "revoked"}}
	if portalActiveKeyCount(keys) != 1 {
		t.Fatal("managed employee Key consumed personal slots")
	}
}

func TestPersonalKeyRevealRateAndRealUserAudit(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "isolated-personal-reveal-encryption")
	e, u, dept := chatLoginFixture(t)
	ctx := context.Background()
 chain:=&recordingChainWriter{};e.deps.AuditAppender=audit_chain.NewAppender(chain,false)
	project := u.ID + "-reveal-project"
	if _, err := e.pool.Exec(ctx, "INSERT INTO projects(id,tenant_id,name,team_id,status) VALUES($1,$2,$1,$3,'active')", project, e.tenantID, dept); err != nil {
		t.Fatal(err)
	}
	e.deps.KeyRepo = repository.NewInternalKeyRepository(e.pool)
	k := &repository.InternalKey{TenantID: e.tenantID, UserID: u.ID, ProjectID: project, Status: "active", Scopes: []string{"chat"}}
	if err := e.deps.KeyRepo.Create(ctx, k, "fixture-recoverable-owned-secret"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		r := httptest.NewRequest("POST", "/reveal?user_id="+u.ID, nil)
		r.Header.Set(portalIntegrationTenantHeader, e.tenantID)
 r.RemoteAddr="198.51.100.25:1234"
		rc := chi.NewRouteContext()
		rc.URLParams.Add("id", k.ID)
		r = r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rc))
		w := httptest.NewRecorder()
		RevealPortalCustomerKey(e.deps)(w, r)
		expected := 200
		if i == 5 {
			expected = 429
		}
		if w.Code != expected {
			t.Fatalf("reveal attempt=%d status=%d code=%s", i, w.Code, decodeConsoleError(t, w).Error.Code)
		}
	}
 deadline:=time.Now().Add(time.Second)
 for chain.count()<5 && time.Now().Before(deadline){time.Sleep(time.Millisecond)}
 if chain.count()!=5 {t.Errorf("reveal audit chain count=%d",chain.count())}
	var count int
	if err := e.pool.QueryRow(ctx, "SELECT count(*) FROM audit_operations WHERE tenant_id=$1 AND user_id=$2 AND action_type='portal_customer_reveal_key'", e.tenantID, u.ID).Scan(&count); err != nil || count != 5 {
		t.Fatalf("real-owner reveal audits=%d err=%v", count, err)
	}
}
