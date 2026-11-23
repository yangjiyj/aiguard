package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/gateway-core/internal/auth"
	"github.com/yangjiyj/aiguard/packages/shared-go/modelcatalog"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestModelsCatalogCurrentSourcesPermissionsAndRemoval(t *testing.T) {
	dsn := os.Getenv("MODEL_CATALOG_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("JJD_REQUIRE_MODEL_CATALOG_DB_TESTS") == "1" {
			t.Fatal("MODEL_CATALOG_TEST_DATABASE_URL is required")
		}
		t.Skip("catalog database fixture not configured")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ctx := context.Background()
	tenant := fmt.Sprintf("gateway_catalog_%d", time.Now().UnixNano())
	project := tenant + "_proj"
	actor := tenant + "_user"
	sqls := []string{
		`INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`,
		`INSERT INTO projects(id,tenant_id,name,status) VALUES($1||'_proj',$1,'fixture','active')`,
		`INSERT INTO users(id,tenant_id,username,role) VALUES($1||'_user',$1,'fixture','tenant_admin')`,
		`INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES($1||'_p1',$1,'first','custom','https://example.invalid','api_key','active'),($1||'_p2',$1,'second','custom','https://example.invalid','api_key','active')`,
		`INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status) VALUES($1||'_c1',$1||'_p1','fixture','fixture','fixture','active'),($1||'_c2',$1||'_p2','fixture','fixture','fixture','active')`,
		`INSERT INTO models(id,provider_id,model_name,status) VALUES($1||'_m1',$1||'_p1','public-model','active'),($1||'_m2',$1||'_p2','public-model','active'),($1||'_denied',$1||'_p1','denied-model','active'),($1||'_unknown',$1||'_p1','unknown-model','active')`,
		`INSERT INTO model_endpoint_capability_overrides(id,tenant_id,model_id,endpoint_type,state,reason,actor_user_id,config_version) SELECT 'ov_'||m.id,$1,m.id,'chat','supported','fixture',$1||'_user',1 FROM models m WHERE m.provider_id IN($1||'_p1',$1||'_p2') AND m.model_name<>'unknown-model'`,
		`INSERT INTO model_policies(id,tenant_id,project_id,scope_type,allow_models_json,deny_models_json) VALUES($1||'_policy',$1,$1||'_proj','project','["public-model","unknown-model"]','["denied-model"]')`,
	}
	for _, sql := range sqls {
		if _, err = db.Exec(ctx, sql, tenant); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, sql := range []string{`DELETE FROM model_policies WHERE tenant_id=$1`, `DELETE FROM model_catalog_entries WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM model_endpoint_capability_overrides WHERE tenant_id=$1`, `DELETE FROM models WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM provider_credentials WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM providers WHERE tenant_id=$1`, `DELETE FROM projects WHERE tenant_id=$1`, `DELETE FROM users WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
			if _, err := db.Exec(context.Background(), sql, tenant); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	})
	handler := NewModelsHandler(db).Handler()
	request := func(name string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		c := context.WithValue(req.Context(), auth.TenantKey, tenant)
		c = context.WithValue(c, auth.ProjectKey, project)
		c = context.WithValue(c, auth.UserKey, actor)
		if name != "" {
			route := chi.NewRouteContext()
			route.URLParams.Add("model", name)
			c = context.WithValue(c, chi.RouteCtxKey, route)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req.WithContext(c))
		return rec
	}
	// 探测结果只做建议：未验证的模型照样发布；只有授权、管理员开关、凭据、上游下架决定是否可见。
	list := func(want ...string) {
		rec := request("")
		if rec.Code != 200 {
			t.Fatal(rec.Code, rec.Body.String())
		}
		var data ModelsResponse
		if err = json.Unmarshal(rec.Body.Bytes(), &data); err != nil || len(data.Data) != len(want) {
			t.Fatal("catalog mismatch", rec.Body.String(), err)
		}
		for i, m := range data.Data {
			found := false
			for _, name := range want {
				found = found || m.ID == name
			}
			if !found {
				t.Fatal("unexpected model published", i, m.ID)
			}
		}
	}
	projection, err := modelcatalog.Load(ctx, db, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if projection[tenant+"_m1"].ProofState != "manual" {
		t.Fatal("manual protocol declaration mislabeled as live verification")
	}
	if u := projection[tenant+"_unknown"]; !u.Callable || u.Advice != "unverified" {
		t.Fatalf("unverified model must stay callable with advice: %+v", u)
	}
	list("public-model", "unknown-model")
	if rec := request("denied-model"); rec.Code != 404 {
		t.Fatal("details bypassed permissions", rec.Code)
	}
	if _, err = db.Exec(ctx, `UPDATE models SET status='upstream_removed' WHERE id=$1||'_m1'`, tenant); err != nil {
		t.Fatal(err)
	}
	list("public-model", "unknown-model")
	if _, err = db.Exec(ctx, `UPDATE provider_credentials SET status='inactive' WHERE provider_id=$1||'_p2'`, tenant); err != nil {
		t.Fatal(err)
	}
	list("unknown-model")
	if rec := request("public-model"); rec.Code != 404 {
		t.Fatal("stale details", rec.Code)
	}
}
