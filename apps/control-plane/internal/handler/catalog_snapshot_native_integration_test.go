package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCatalogSnapshotNativeAdmissionAndFailureWithPostgres(t *testing.T) {
	dsn := os.Getenv("MODEL_CATALOG_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("JJD_REQUIRE_MODEL_CATALOG_DB_TESTS") == "1" {
			t.Fatal("MODEL_CATALOG_TEST_DATABASE_URL required")
		}
		t.Skip("controlled PostgreSQL not configured")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "fixture-catalog-encryption-key-not-production")
	encrypted, _, err := secrets.EncryptProviderSecret("fixture-upstream-secret")
	if err != nil {
		t.Fatal(err)
	}
	tenant := fmt.Sprintf("catalog_native_%d", time.Now().UnixNano())
	providerID := tenant + "_p"
	credentialID := tenant + "_c"
	status := http.StatusOK
	imageCalls := 0
	wrongCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-upstream-secret" && r.Header.Get("x-api-key") != "fixture-upstream-secret" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v1/models" {
			fmt.Fprint(w, `{"data":[{"id":"anthropic/claude-fixture","type":"model"}],"has_more":false,"last_id":"anthropic/claude-fixture"}`)
			return
		}
		if r.URL.Path != "/v1/messages" {
			wrongCalls++
			w.WriteHeader(404)
			return
		}
		imageCalls++
		w.WriteHeader(status)
		fmt.Fprint(w, `{"type":"message","content":[{"type":"text","text":"fixture-ok"}],"usage":{"output_tokens":1}}`)
	}))
	defer upstream.Close()
	for _, q := range []struct {
		sql  string
		args []interface{}
	}{
		{`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`, []interface{}{tenant}},
		{`INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES($1,$2,'controlled-native','anthropic',$3,'api_key','active')`, []interface{}{providerID, tenant, upstream.URL}},
		{`INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status) VALUES($1,$2,'fixture',$3,'fixture','active')`, []interface{}{credentialID, providerID, encrypted}},
	} {
		if _, err := db.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, sql := range []string{`DELETE FROM model_catalog_sync_runs WHERE tenant_id=$1`, `DELETE FROM model_catalog_entries WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM model_catalog_sync_state WHERE tenant_id=$1`, `DELETE FROM model_endpoint_capability_facts WHERE tenant_id=$1`, `DELETE FROM models WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM provider_credentials WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM providers WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
			if _, err := db.Exec(ctx, sql, tenant); err != nil {
				t.Error(err)
			}
		}
	}()
	repo := repository.NewModelRepository(db)
	store := repository.NewProviderRepository(db)
	provider, err := store.GetByID(ctx, tenant, providerID)
	if err != nil {
		t.Fatal(err)
	}
	// The local fixture uses an injected catalog transport; production native catalog SSRF checks remain intact.
	deps := &Dependencies{ProviderRepo: store, ModelRepo: repo, CatalogFactory: &MockCatalogFactory{Client: catalog.NewOpenAIClient()}, ModelProber: snapshotHTTPProber{upstream.Client()}}
	sync := func(selected []string) repository.CatalogSnapshotResult {
		result, err := runCatalogSnapshot(ctx, deps, repo, tenant, provider, selected, "manual")
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	result := sync(nil)
	if result.Created != 0 || result.Pending != 0 || result.Skipped != 1 || imageCalls != 0 || wrongCalls != 0 {
		t.Fatalf("inventory made inference calls: %+v images=%d wrong=%d", result, imageCalls, wrongCalls)
	}
	result = sync([]string{"anthropic/claude-fixture"})
	if result.Verified != 1 || result.Pending != 0 || result.VerificationFailed != 0 || imageCalls != 1 || wrongCalls != 0 {
		t.Fatalf("image admission: %+v images=%d wrong=%d", result, imageCalls, wrongCalls)
	}
	var modelID, state string
	if err := db.QueryRow(ctx, `SELECT model_id FROM model_catalog_entries WHERE provider_id=$1`, providerID).Scan(&modelID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(ctx, `SELECT state FROM model_endpoint_capability_effective WHERE model_id=$1 AND endpoint_type='messages'`, modelID).Scan(&state); err != nil || state != "supported" {
		t.Fatal("image evidence", state, err)
	}
	availability, err := repo.ModelAvailability(ctx, tenant)
	if err != nil || !availability[modelID].Callable {
		t.Fatal("image not callable", availability, err)
	}
	if err := repo.UpdateCatalogModelStatus(ctx, tenant, modelID, "disabled"); err != nil {
		t.Fatal(err)
	}
	result = sync([]string{"anthropic/claude-fixture"})
	model, err := repo.GetByID(ctx, modelID)
	if err != nil || model.Status != "disabled" {
		t.Fatal("manual disable lost", model, err)
	}
	if err := repo.UpdateCatalogModelStatus(ctx, tenant, modelID, "active"); err != nil {
		t.Fatal("verified image could not be enabled", err)
	}
	// 有效期内的证据同步时会沿用、不再探测；先让证据过期，才能观察到这次探测失败。
	if _, err := db.Exec(ctx, `UPDATE model_endpoint_capability_facts SET expires_at=NOW()-INTERVAL '1 minute' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	status = 401
	result = sync([]string{"anthropic/claude-fixture"})
	if result.VerificationFailed != 1 || result.VerificationFailures[0].Reason != catalog.ModelProbeErrorUnauthorized {
		t.Fatal("image failure misreported", result)
	}
	availability, err = repo.ModelAvailability(ctx, tenant)
	// 探测失败只是建议：模型仍可调用，带「健康检查异常」建议。
	if err != nil || !availability[modelID].Callable || availability[modelID].Advice != "unhealthy" {
		t.Fatal("failed probe must stay callable with advice", availability, err)
	}
}
