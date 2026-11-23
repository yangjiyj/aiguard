package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 已纳入、且探测证据仍在有效期内（同一渠道配置）的模型，再次勾选同步时不重复做真实推理调用；
// 证据过期、渠道地址变了、或者从未验证过的模型照常探测。
func TestCatalogSnapshotReusesUnexpiredProbeEvidenceWithPostgres(t *testing.T) {
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
	tenant := fmt.Sprintf("catalog_reuse_%d", time.Now().UnixNano())
	providerID := tenant + "_p"
	var chatCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 渠道地址带不带末尾斜杠都要能命中（用例里会改地址来让配置摘要失效）。
		switch path := strings.TrimLeft(r.URL.Path, "/"); path {
		case "v1/models":
			fmt.Fprint(w, `{"data":[{"id":"fixture-a"},{"id":"fixture-b"}]}`)
		case "v1/chat/completions":
			chatCalls.Add(1)
			fmt.Fprint(w, `{"choices":[{"message":{"content":"fixture-ok"}}]}`)
		default:
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()
	for _, q := range []struct {
		sql  string
		args []interface{}
	}{
		{`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`, []interface{}{tenant}},
		{`INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES($1,$2,'controlled-reuse','custom',$3,'api_key','active')`, []interface{}{providerID, tenant, upstream.URL}},
		{`INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status) VALUES($1,$2,'fixture',$3,'fixture','active')`, []interface{}{tenant + "_c", providerID, encrypted}},
	} {
		if _, err := db.Exec(ctx, q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for _, sql := range []string{`DELETE FROM model_route_health_snapshots WHERE tenant_id=$1`, `DELETE FROM model_catalog_sync_runs WHERE tenant_id=$1`, `DELETE FROM model_catalog_entries WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM model_catalog_sync_state WHERE tenant_id=$1`, `DELETE FROM model_endpoint_capability_facts WHERE tenant_id=$1`, `DELETE FROM models WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM provider_credentials WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM providers WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
			if _, err := db.Exec(ctx, sql, tenant); err != nil {
				t.Error(err)
			}
		}
	}()
	repo := repository.NewModelRepository(db)
	providers := repository.NewProviderRepository(db)
	provider, err := providers.GetByID(ctx, tenant, providerID)
	if err != nil {
		t.Fatal(err)
	}
	deps := &Dependencies{ProviderRepo: providers, ModelRepo: repo, ModelProber: snapshotHTTPProber{upstream.Client()}}
	sync := func(selected ...string) repository.CatalogSnapshotResult {
		t.Helper()
		result, err := runCatalogSnapshot(ctx, deps, repo, tenant, provider, selected, "manual")
		if err != nil {
			t.Fatal(err)
		}
		return result
	}

	// 第一次：两个都要真实探测（custom 渠道只探 chat，每个模型 1 次）。
	if r := sync("fixture-a", "fixture-b"); r.Verified != 2 || r.Created != 2 {
		t.Fatalf("first sync: %+v", r)
	}
	if got := chatCalls.Load(); got != 2 {
		t.Fatalf("first sync probe calls=%d, want 2", got)
	}

	// 第二次：证据都还有效，不再调用上游，结果里记为沿用。
	chatCalls.Store(0)
	r := sync("fixture-a", "fixture-b")
	if got := chatCalls.Load(); got != 0 {
		t.Fatalf("unexpired evidence was re-probed: calls=%d", got)
	}
	if r.Reused != 2 || r.Verified != 0 || r.VerificationFailed != 0 {
		t.Fatalf("second sync should reuse both: %+v", r)
	}
	availability, err := repo.ModelAvailability(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	for id, a := range availability {
		if !a.Callable || a.Advice != "" {
			t.Fatalf("reused model %s lost its verified state: %+v", id, a)
		}
	}

	// fixture-a 的证据过期：只重新探测它。
	if _, err := db.Exec(ctx, `UPDATE model_endpoint_capability_facts f SET expires_at=NOW()-INTERVAL '1 minute' FROM models m WHERE m.id=f.model_id AND m.provider_id=$1 AND m.upstream_model_id='fixture-a'`, providerID); err != nil {
		t.Fatal(err)
	}
	chatCalls.Store(0)
	r = sync("fixture-a", "fixture-b")
	if got := chatCalls.Load(); got != 1 || r.Verified != 1 || r.Reused != 1 {
		t.Fatalf("expired evidence must be re-probed alone: calls=%d %+v", got, r)
	}

	// fixture-b 刚探测失败过（健康快照 unhealthy、未过期）：管理员马上重试时要真的重新探测，不能沿用旧证据。
	if _, err := db.Exec(ctx, `UPDATE model_route_health_snapshots h SET state='unhealthy',expires_at=NOW()+INTERVAL '10 minutes' FROM models m WHERE h.provider_id=$1 AND m.provider_id=$1 AND h.model_name=m.model_name AND m.upstream_model_id='fixture-b'`, providerID); err != nil {
		t.Fatal(err)
	}
	chatCalls.Store(0)
	r = sync("fixture-a", "fixture-b")
	if got := chatCalls.Load(); got != 1 || r.Verified != 1 || r.Reused != 1 {
		t.Fatalf("unhealthy model must be re-probed: calls=%d %+v", got, r)
	}

	// 渠道地址变了：旧证据的配置摘要对不上，全部重新探测。
	if _, err := db.Exec(ctx, `UPDATE providers SET base_url=$2 WHERE id=$1`, providerID, upstream.URL+"/"); err != nil {
		t.Fatal(err)
	}
	if provider, err = providers.GetByID(ctx, tenant, providerID); err != nil {
		t.Fatal(err)
	}
	chatCalls.Store(0)
	r = sync("fixture-a", "fixture-b")
	if got := chatCalls.Load(); got != 2 || r.Reused != 0 {
		t.Fatalf("config change must re-probe everything: calls=%d %+v", got, r)
	}
}
