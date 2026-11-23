package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/catalog"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/packages/shared-go/secrets"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This test prober performs real HTTP against the controlled fixture. It is
// confined to tests; the production DNS/IP pinning constructor stays intact.
type snapshotHTTPProber struct{ client *http.Client }

func (p snapshotHTTPProber) Probe(ctx context.Context, r catalog.ModelProbeRequest) catalog.ModelProbeResult {
	path := "/v1/chat/completions"
	if r.Protocol == "responses" {
		path = "/v1/responses"
	} else if r.Protocol == "messages" {
		path = "/v1/messages"
	} else if r.Protocol == "images" {
		path = "/v1/images/generations"
	}
	body, _ := json.Marshal(map[string]any{"model": r.DeploymentName, "messages": []map[string]string{{"role": "user", "content": "fixture"}}})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, r.BaseURL+path, bytes.NewReader(body))
	if r.AuthMode == "x-api-key" {
		req.Header.Set("x-api-key", r.APIKey)
	} else {
		req.Header.Set("Authorization", "Bearer "+r.APIKey)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return catalog.ModelProbeResult{ErrorKind: "timeout"}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	errorKind := "not_deployed"
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		errorKind = "unauthorized"
	}
	return catalog.ModelProbeResult{ErrorKind: errorKind, OK: resp.StatusCode == 200 && strings.Contains(string(raw), "fixture-ok"), PayloadValidated: true, HTTPStatus: resp.StatusCode}
}
func TestCatalogSnapshotHTTPClosureAndFailureFences(t *testing.T) {
	dsn := os.Getenv("MODEL_CATALOG_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("JJD_REQUIRE_MODEL_CATALOG_DB_TESTS") == "1" {
			t.Fatal("MODEL_CATALOG_TEST_DATABASE_URL is required")
		}
		t.Skip("controlled HTTP/PostgreSQL fixture not configured")
	}
	db, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	ctx := context.Background()
	t.Setenv("JJD_PROVIDER_SECRET_KEY", "fixture-catalog-encryption-key-not-production")
	encrypted, _, err := secrets.EncryptProviderSecret("fixture-upstream-secret")
	if err != nil {
		t.Fatal(err)
	}
	tenant := fmt.Sprintf("catalog_http_%d", time.Now().UnixNano())
	providerID := tenant + "_p"
	credentialID := tenant + "_c"
	var mu sync.Mutex
	body := `{"object":"list","data":[{"id":"fixture-model","name":"public-alias"}]}`
	httpStatus := 200
	probeStatus := 200
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-upstream-secret" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/v1/models" {
			mu.Lock()
			b, s := body, httpStatus
			mu.Unlock()
			w.WriteHeader(s)
			w.Write([]byte(b))
			return
		}
		if r.URL.Path == "/v1/chat/completions" {
			mu.Lock()
			status := probeStatus
			mu.Unlock()
			w.WriteHeader(status)
			w.Write([]byte(`{"choices":[{"message":{"content":"fixture-ok"}}],"usage":{"total_tokens":1}}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer upstream.Close()
	_, err = db.Exec(ctx, `INSERT INTO tenants(id,name,edition,status,is_test) VALUES($1,$1,'enterprise','active',true)`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `INSERT INTO providers(id,tenant_id,name,provider_type,base_url,auth_mode,status) VALUES($1,$2,'controlled-http','custom',$3,'api_key','active')`, providerID, tenant, upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(ctx, `INSERT INTO provider_credentials(id,provider_id,credential_name,secret_ciphertext,kms_key_ref,status) VALUES($1,$2,'fixture',$3,'fixture','active')`, credentialID, providerID, encrypted)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, sql := range []string{`DELETE FROM request_logs WHERE tenant_id=$1`, `DELETE FROM model_catalog_sync_runs WHERE tenant_id=$1`, `DELETE FROM model_catalog_entries WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM model_catalog_sync_state WHERE tenant_id=$1`, `DELETE FROM model_endpoint_capability_facts WHERE tenant_id=$1`, `DELETE FROM models WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM provider_credentials WHERE provider_id IN(SELECT id FROM providers WHERE tenant_id=$1)`, `DELETE FROM providers WHERE tenant_id=$1`, `DELETE FROM tenants WHERE id=$1`} {
			if _, err := db.Exec(context.Background(), sql, tenant); err != nil {
				t.Errorf("fixture cleanup: %v", err)
			}
		}
	})
	repo := repository.NewModelRepository(db)
	deps := &Dependencies{ProviderRepo: repository.NewProviderRepository(db), ModelRepo: repo, ModelProber: snapshotHTTPProber{upstream.Client()}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: "fixture-admin", TenantID: tenant, Role: "platform_admin"}))
		if r.Method == http.MethodGet {
			ListModels(deps)(w, r)
		} else {
			SyncModels(deps)(w, r)
		}
	}))
	defer server.Close()
	syncModels := func(selected bool) (int, map[string]any) {
		request := map[string]any{"provider_id": providerID}
		if selected {
			request["catalog_model_ids"] = []string{"fixture-model"}
		}
		raw, _ := json.Marshal(request)
		response, err := server.Client().Post(server.URL, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		result := map[string]any{}
		json.NewDecoder(response.Body).Decode(&result)
		return response.StatusCode, result
	}
	status, result := syncModels(true)
	if status != 200 || result["verified"] != float64(1) || result["created"] != float64(1) {
		t.Fatalf("initial: %d %+v", status, result)
	}
	var modelID string
	db.QueryRow(ctx, `SELECT model_id FROM model_catalog_entries WHERE provider_id=$1 AND upstream_model_id='fixture-model'`, providerID).Scan(&modelID)
	available, err := repo.ModelAvailability(ctx, tenant)
	if err != nil || !available[modelID].Callable {
		t.Fatal("not callable", available, err)
	}
	_, err = db.Exec(ctx, `INSERT INTO request_logs(id,request_id,tenant_id,provider_id,model_id,request_status) VALUES($1,$1,$2,$3,$4,'success')`, tenant+"_history", tenant, providerID, modelID)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []struct {
		status int
		body   string
	}{{401, `{"data":[]}`}, {403, `{}`}, {429, `{}`}, {500, `{}`}, {503, `{}`}, {200, `{}`}, {200, `{"data":null}`}, {200, `{"data":[],"has_more":true}`}, {200, `invalid`}} {
		mu.Lock()
		httpStatus = invalid.status
		body = invalid.body
		mu.Unlock()
		status, _ = syncModels(false)
		if status == 200 {
			t.Fatal("failure accepted", invalid)
		}
		available, err = repo.ModelAvailability(ctx, tenant)
		if err != nil || !available[modelID].Callable {
			t.Fatal("failure removed route", invalid, err)
		}
	}
	// 有效期内的证据同步时会沿用、不再探测；先让证据过期，才能观察到这次探测失败。
	if _, err := db.Exec(ctx, `UPDATE model_endpoint_capability_facts SET expires_at=NOW()-INTERVAL '1 minute' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	httpStatus = 200
	body = `{"data":[{"id":"fixture-model","name":"public-alias"}]}`
	probeStatus = 401
	mu.Unlock()
	status, result = syncModels(true)
	if status != 200 || result["verification_failed"] != float64(1) {
		t.Fatal("probe failure receipt", status, result)
	}
	available, err = repo.ModelAvailability(ctx, tenant)
	// 探测失败只是建议：模型仍可调用，控制台显示「健康检查异常」。
	if err != nil || !available[modelID].Callable || available[modelID].State != "callable" || available[modelID].Advice != "unhealthy" {
		t.Fatal("probe failure must stay callable with advice", available, err)
	}
	var currentStatus string
	db.QueryRow(ctx, `SELECT status FROM models WHERE id=$1`, modelID).Scan(&currentStatus)
	if currentStatus != "active" {
		t.Fatal("temporary probe failure removed inventory", currentStatus)
	}
	mu.Lock()
	probeStatus = 200
	mu.Unlock()
	status, result = syncModels(true)
	if status != 200 || result["verified"] != float64(1) {
		t.Fatal("probe recovery", status, result)
	}
	mu.Lock()
	httpStatus = 200
	body = `{"object":"list","data":[]}`
	mu.Unlock()
	status, result = syncModels(false)
	if status != 200 || result["deactivated"] != float64(1) {
		t.Fatalf("remove: %d %+v", status, result)
	}
	available, err = repo.ModelAvailability(ctx, tenant)
	if err != nil || available[modelID].Callable || available[modelID].State != "upstream_removed" {
		t.Fatal("stale route", available, err)
	}
	status, result = syncModels(false)
	if status != 200 || result["deactivated"] != float64(0) {
		t.Fatal("removal not idempotent", status, result)
	}
	mu.Lock()
	body = `{"data":[{"id":"fixture-model","name":"updated-label"}]}`
	mu.Unlock()
	status, result = syncModels(false)
	if status != 200 || result["reappeared"] != float64(1) {
		t.Fatal("reappearance failed", status, result)
	}
	var name, label string
	db.QueryRow(ctx, `SELECT model_name,model_label FROM models WHERE id=$1`, modelID).Scan(&name, &label)
	if name != "public-alias" || label != "updated-label" {
		t.Fatal("alias lost", name, label)
	}
	available, err = repo.ModelAvailability(ctx, tenant)
	if err != nil || !available[modelID].Callable {
		t.Fatal("reappearance proof lost", err)
	}
	var count int
	db.QueryRow(ctx, `SELECT count(*) FROM request_logs WHERE id=$1`, tenant+"_history").Scan(&count)
	if count != 1 {
		t.Fatal("history deleted")
	}
	state, err := repo.CatalogSyncState(ctx, tenant, providerID)
	if err != nil || state.Status != "success" || state.SuccessAt == nil {
		t.Fatal("sync receipt missing", state, err)
	}
}
