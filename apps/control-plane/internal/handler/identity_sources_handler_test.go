package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identityruntime"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func buildIdentityDeps(pool *pgxpool.Pool) *Dependencies {
	return &Dependencies{
		IdentitySourceRepo: repository.NewIdentitySourceRepository(pool),
		OIDCTester:         identity.NewOIDCTester(),
		SystemRepo:         &orgTestSystemRepo{},
	}
}

// setupIdentitySecretKey sets the provider secret key for draft encryption in tests.
func setupIdentitySecretKey(t *testing.T) {
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "identity-unit-test-secret-key")
}

func TestGetIdentitySourcesEmpty(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDeps(pool)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/identity/sources", nil)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	GetIdentitySources(deps)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	data := resp["data"].([]any)
	if len(data) != 0 {
		t.Fatalf("expected empty, got %v", data)
	}
}

func TestSaveDraftSuccess(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildIdentityDeps(pool)

	body := bytes.NewReader([]byte(`{"display_name":"企业 IdP","issuer_url":"https://idp.example.com","client_id":"test-client","client_secret":"super-secret","scopes":"openid profile email","subject_claim":"sub","username_claim":"preferred_username","name_claim":"name","email_claim":"email"}`))
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft", body)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var dto identitySourceDTO
	_ = json.Unmarshal(w.Body.Bytes(), &dto)
	if dto.DisplayName != "企业 IdP" {
		t.Fatalf("bad name: %s", dto.DisplayName)
	}
	if !dto.ClientSecretSet {
		t.Fatal("client_secret_set should be true")
	}
	if strings.Contains(w.Body.String(), "super-secret") {
		t.Fatal("response should not contain plaintext secret")
	}
}

func TestSaveDraftValidation(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDeps(pool)

	body := bytes.NewReader([]byte(`{"issuer_url":"https://idp.example.com","client_id":"test-client"}`))
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft", body)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestSaveDraftEncryptsSecret(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildIdentityDeps(pool)

	body := bytes.NewReader([]byte(`{"display_name":"Test IdP","issuer_url":"https://idp.example.com","client_id":"c","client_secret":"my-secret-123"}`))
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft", body)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d %s", w.Code, w.Body.String())
	}

	ctx := context.Background()
	draft, err := deps.IdentitySourceRepo.GetDraft(ctx, tenantID)
	if err != nil || draft == nil {
		t.Fatalf("draft not found: %v", err)
	}
	if !strings.HasPrefix(draft.ClientSecretEnc, "enc:v1:") {
		t.Fatalf("secret should be encrypted, got: %s", draft.ClientSecretEnc)
	}
	if strings.Contains(draft.ClientSecretEnc, "my-secret-123") {
		t.Fatal("ciphertext should not contain plaintext")
	}
}

func TestActivateWithoutTest(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildIdentityDeps(pool)

	body := bytes.NewReader([]byte(`{"display_name":"Test IdP","issuer_url":"https://idp.example.com","client_id":"c","client_secret":"s"}`))
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft", body)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)

	req2 := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/activate", nil)
	req2 = withOrgUserCtx(req2, tenantID, userID)
	w2 := httptest.NewRecorder()
	ActivateIdentitySource(deps)(w2, req2)

	if w2.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", w2.Code, w2.Body.String())
	}
	if !strings.Contains(w2.Body.String(), "测试连接") {
		t.Fatalf("error should mention test: %s", w2.Body.String())
	}
}

func TestDisableRequiresConfirm(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildIdentityDeps(pool)

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/disable", bytes.NewReader([]byte(`{"confirm":false}`)))
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	DisableIdentitySource(deps)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
}

func TestActivateAfterSuccessfulConnectionTest(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildRuntimeIdentityDeps(t, pool, &fakeIdentityRuntime{publication: identityruntime.Publication{
		Digest:   handlerTestDigest,
		Previous: identityruntime.RuntimeSnapshot{Realm: identityruntime.RealmName, Alias: identityruntime.ProviderAlias},
	}})

	body := bytes.NewReader([]byte(`{"display_name":"Test IdP","issuer_url":"https://idp.example.com","client_id":"c","client_secret":"s"}`))
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft", body)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("save failed: %d %s", w.Code, w.Body.String())
	}
	draft, err := deps.IdentitySourceRepo.GetDraft(context.Background(), tenantID)
	if err != nil || draft == nil {
		t.Fatalf("draft missing: %v", err)
	}
	if err := deps.IdentitySourceRepo.UpdateTestResult(context.Background(), tenantID, draft.ID, draft.Version, &repository.TestResult{Success: true}); err != nil {
		t.Fatal(err)
	}

	activate := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/sources/activate", nil)
	activate = withOrgUserCtx(activate, tenantID, userID)
	aw := httptest.NewRecorder()
	ActivateIdentitySource(deps)(aw, activate)
	if aw.Code != http.StatusOK {
		t.Fatalf("activate failed: %d %s", aw.Code, aw.Body.String())
	}
}

func TestIdentitySourceNoSecretLeak(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildIdentityDeps(pool)

	body := bytes.NewReader([]byte(`{"display_name":"Leak Test","issuer_url":"https://idp.example.com","client_id":"c","client_secret":"topsecret-abc-xyz"}`))
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft", body)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)

	if strings.Contains(w.Body.String(), "topsecret-abc-xyz") {
		t.Fatalf("plaintext secret leaked in response: %s", w.Body.String())
	}

	req2 := httptest.NewRequest(http.MethodGet, "/admin/v1/identity/sources", nil)
	req2 = withOrgUserCtx(req2, tenantID, userID)
	w2 := httptest.NewRecorder()
	GetIdentitySources(deps)(w2, req2)

	if strings.Contains(w2.Body.String(), "topsecret-abc-xyz") {
		t.Fatalf("plaintext secret leaked in list: %s", w2.Body.String())
	}
}

func TestCrossTenantIsolation(t *testing.T) {
	pool, tenantA, userA := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildIdentityDeps(pool)

	body := bytes.NewReader([]byte(`{"display_name":"Tenant A IdP","issuer_url":"https://a.example.com","client_id":"a","client_secret":"aaa"}`))
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft", body)
	req = withOrgUserCtx(req, tenantA, userA)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("save draft failed: %d", w.Code)
	}

	tenantB := "tisb_" + tenantA[len("toh_"):]
	ctx := context.Background()
	_, err := pool.Exec(ctx, `INSERT INTO tenants (id, name, edition, status) VALUES ($1, $2, 'enterprise', 'active')`, tenantB, tenantB)
	if err != nil {
		t.Fatalf("insert tenant B: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantB)
	})

	userB := "uisb_" + tenantA[len("toh_"):]
	_, err = pool.Exec(ctx, `INSERT INTO users (id, tenant_id, username, email, password_hash, role, status) VALUES ($1,$2,$3,$4,$5,$6,$7)`, userB, tenantB, userB, userB+"@test.com", "x", "platform_admin", "active")
	if err != nil {
		t.Fatalf("insert user B: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id=$1`, tenantB)
	})

	req2 := httptest.NewRequest(http.MethodGet, "/admin/v1/identity/sources", nil)
	req2 = withOrgUserCtx(req2, tenantB, userB)
	w2 := httptest.NewRecorder()
	GetIdentitySources(deps)(w2, req2)

	var resp map[string]any
	_ = json.Unmarshal(w2.Body.Bytes(), &resp)
	data := resp["data"].([]any)
	if len(data) != 0 {
		t.Fatalf("tenant B should not see tenant A sources: %v", data)
	}
}

func TestCreateIdentityDeptMappingRejectsCrossTenantSource(t *testing.T) {
	pool, tenantA, userA := setupOrgHandlerPool(t)
	deps := buildIdentityDeps(pool)
	ctx := context.Background()

	source := &repository.IdentitySource{
		TenantID: tenantA, DisplayName: "Tenant A IdP",
		IssuerURL: "https://idp-a.example.com", ClientID: "a",
		ClientSecretEnc: "enc:v1:a",
	}
	if err := deps.IdentitySourceRepo.UpsertDraft(ctx, source); err != nil {
		t.Fatal(err)
	}
	tenantB := "tim_" + tenantA[len("toh_"):]
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name, edition, status) VALUES ($1, $2, 'enterprise', 'active')`, tenantB, tenantB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM identity_dept_mappings WHERE tenant_id=$1`, tenantB)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, tenantB)
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/identity/dept-mappings?source_id="+source.ID, bytes.NewReader([]byte(`{"match_value":"rd"}`)))
	u := &repository.User{ID: userA, TenantID: tenantB, Role: "platform_admin", Status: "active"}
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, u))
	w := httptest.NewRecorder()
	CreateIdentityDeptMapping(deps)(w, req)

	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "不属于当前租户") {
		t.Fatalf("cross-tenant source must be rejected clearly, got %d %s", w.Code, w.Body.String())
	}
}

func TestNonAdminForbidden(t *testing.T) {
	pool, tenantID, _ := setupOrgHandlerPool(t)
	deps := buildIdentityDeps(pool)

	devUserID := "udev_" + tenantID[len("toh_"):]
	ctx := context.Background()
	_, err := pool.Exec(ctx, `INSERT INTO users (id, tenant_id, username, email, password_hash, role, status) VALUES ($1,$2,$3,$4,$5,$6,$7)`, devUserID, tenantID, devUserID, devUserID+"@test.com", "x", "developer", "active")
	if err != nil {
		t.Fatalf("insert dev user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, devUserID)
	})

	req := httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft", bytes.NewReader([]byte(`{"display_name":"x","issuer_url":"https://x.com","client_id":"x","client_secret":"x"}`)))
	u := &repository.User{ID: devUserID, TenantID: tenantID, Role: "developer", Status: "active"}
	ctx = context.WithValue(req.Context(), auth.UserKey, u)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d %s", w.Code, w.Body.String())
	}
}

func TestGetIdentityStatus(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	deps := buildRuntimeIdentityDeps(t, pool, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/identity/status", nil)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	GetIdentityStatus(deps)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp identityStatusDTO
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.HasActive {
		t.Fatal("should not have active source")
	}
	if !resp.EmergencyAdmin {
		t.Fatal("emergency admin should be available")
	}
}

func TestNoKeycloakTerminology(t *testing.T) {
	pool, tenantID, userID := setupOrgHandlerPool(t)
	setupIdentitySecretKey(t)
	deps := buildIdentityDeps(pool)

	body := bytes.NewReader([]byte(`{"display_name":"企业 IdP","issuer_url":"https://idp.example.com","client_id":"c","client_secret":"s"}`))
	req := httptest.NewRequest(http.MethodPut, "/admin/v1/identity/sources/draft", body)
	req = withOrgUserCtx(req, tenantID, userID)
	w := httptest.NewRecorder()
	SaveIdentityDraft(deps)(w, req)

	forbidden := []string{"Keycloak", "realm", "client mapper"}
	for _, word := range forbidden {
		if strings.Contains(w.Body.String(), word) {
			t.Fatalf("response contains forbidden term '%s': %s", word, w.Body.String())
		}
	}
}
