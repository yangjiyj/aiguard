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

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// ---- 单元：缺 tenant 头一律 400（无需 DB） ----

func TestPortalUsageTrendRequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/usage/trend", nil)
	w := httptest.NewRecorder()
	GetPortalUsageTrend(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", w.Code, w.Body.String())
	}
}

func TestPortalUsageByModelRequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/usage/by-model", nil)
	w := httptest.NewRecorder()
	GetPortalUsageByModel(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", w.Code, w.Body.String())
	}
}

func TestPortalUsageSummaryRequiresTenantHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/usage/summary", nil)
	w := httptest.NewRecorder()
	GetPortalUsageSummary(&Dependencies{})(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d %s", w.Code, w.Body.String())
	}
}

// ---- 单元：project_ids → UsageScope 纯逻辑 ----

func TestPortalUsageScopeFromProjectIDs(t *testing.T) {
	// 无 project_ids → 全租户
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/usage/summary", nil)
	scope := portalUsageScope(req, "tenant_default")
	if !scope.FullTenant || len(scope.ProjectIDs) != 0 {
		t.Fatalf("no project_ids should be FullTenant, got %+v", scope)
	}
	// 有 project_ids（含空白/空串）→ 收窄，FullTenant=false
	req2 := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/usage/summary?project_ids=%20p1%20,,%20p2%20", nil)
	scope2 := portalUsageScope(req2, "tenant_default")
	if scope2.FullTenant {
		t.Fatalf("project_ids present must not be FullTenant, got %+v", scope2)
	}
	if len(scope2.ProjectIDs) != 2 || scope2.ProjectIDs[0] != "p1" || scope2.ProjectIDs[1] != "p2" {
		t.Fatalf("expected [p1 p2] trimmed, got %+v", scope2.ProjectIDs)
	}
	if scope2.TenantID != "tenant_default" {
		t.Fatalf("tenant must carry through, got %q", scope2.TenantID)
	}
}

func TestParseCommaProjectIDsDropsEmpties(t *testing.T) {
	got := parseCommaProjectIDs("  , a , ,b,  ")
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("expected [a b], got %+v", got)
	}
	if parseCommaProjectIDs("   ") != nil {
		t.Fatalf("blank should be nil")
	}
}

// ---- 集成（需 CONTENT_LOGS_TEST_DATABASE_URL）：project_ids 服务端过滤生效 ----

type portalUsageFixture struct {
	db         *pgxpool.Pool
	ctx        context.Context
	tenantID   string
	p1, p2     string
	m1id, m2id string
}

func setupPortalUsageFixture(t *testing.T) portalUsageFixture {
	t.Helper()
	databaseURL := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect database: %v", err)
	}
	sfx := time.Now().UnixNano()
	tenantID := fmt.Sprintf("tenant_portal_usage_%d", sfx)
	userID := fmt.Sprintf("user_portal_usage_%d", sfx)
	p1 := fmt.Sprintf("proj_pu_a_%d", sfx)
	p2 := fmt.Sprintf("proj_pu_b_%d", sfx)
	providerID := fmt.Sprintf("prov_pu_%d", sfx)
	m1id := fmt.Sprintf("m1_%d", sfx)
	m2id := fmt.Sprintf("m2_%d", sfx)
	keyAID := fmt.Sprintf("key_a_%d", sfx)
	keyBID := fmt.Sprintf("key_b_%d", sfx)

	t.Cleanup(func() {
		// 删除顺序守外键：request_logs/rollup 引用 models→providers；先子后父。
		for _, stmt := range []string{
			"DELETE FROM request_logs WHERE tenant_id = $1",
			"DELETE FROM usage_rollup_hourly WHERE tenant_id = $1",
			"DELETE FROM models WHERE provider_id IN (SELECT id FROM providers WHERE tenant_id = $1)",
			"DELETE FROM providers WHERE tenant_id = $1",
			"DELETE FROM internal_keys WHERE tenant_id = $1",
			"DELETE FROM projects WHERE tenant_id = $1",
			"DELETE FROM users WHERE tenant_id = $1",
			"DELETE FROM tenants WHERE id = $1",
		} {
			if _, err := db.Exec(ctx, stmt, tenantID); err != nil {
				t.Logf("cleanup %q: %v", stmt, err)
			}
		}
		db.Close()
	})

	mustExec := func(sql string, args ...interface{}) {
		if _, err := db.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("exec %q: %v", sql, err)
		}
	}
	mustExec(`INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1,$2,'enterprise','active',TRUE)`, tenantID, tenantID)
	mustExec(`INSERT INTO users (id, tenant_id, username, role, status) VALUES ($1,$2,$3,'developer','active')`, userID, tenantID, userID)
	mustExec(`INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1,$2,$3,$4,'active')`, p1, tenantID, p1, userID)
	mustExec(`INSERT INTO projects (id, tenant_id, name, owner_user_id, status) VALUES ($1,$2,$3,$4,'active')`, p2, tenantID, p2, userID)
	mustExec(`INSERT INTO providers (id, tenant_id, name, provider_type, status) VALUES ($1,$2,$3,'anthropic','active')`, providerID, tenantID, providerID)
	mustExec(`INSERT INTO models (id, provider_id, model_name, status) VALUES ($1,$2,$1,'active')`, m1id, providerID)
	mustExec(`INSERT INTO models (id, provider_id, model_name, status) VALUES ($1,$2,$1,'active')`, m2id, providerID)

	// The by-key dimension inner-joins internal_keys, so the usage rows below
	// must carry a key id that actually exists for this tenant.
	mustExec(`INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, name, status) VALUES ($1,$2,$3,$4,$5,$6,$6,'active')`, keyAID, tenantID, p1, userID, "hash_"+keyAID, keyAID[len(keyAID)-12:])
	mustExec(`INSERT INTO internal_keys (id, tenant_id, project_id, user_id, key_hash, key_prefix, name, status) VALUES ($1,$2,$3,$4,$5,$6,$6,'active')`, keyBID, tenantID, p2, userID, "hash_"+keyBID, keyBID[len(keyBID)-12:])
	now := time.Now().UTC()
	bucket := now.Truncate(time.Hour)
	// request_logs：P1 两条(模型 m1)、P2 一条(模型 m2)——供 by-model / by-key。
	insReq := func(project, model, client string) {
		rid := fmt.Sprintf("rl_%d", time.Now().UnixNano())
		mustExec(`INSERT INTO request_logs (id, request_id, tenant_id, project_id, user_id, client_id, model_id, endpoint_type, request_status, input_tokens, output_tokens, total_cost, created_at)
			VALUES ($1,$1,$2,$3,$4,$5,$6,'anthropic_messages','success',10,20,0.5,$7)`, rid, tenantID, project, userID, client, model, now)
	}
	insReq(p1, m1id, keyAID)
	insReq(p1, m1id, keyAID)
	insReq(p2, m2id, keyBID)
	// usage_rollup_hourly：P1 request_count=2、P2 request_count=1——供 summary / trend。
	insRoll := func(project, key, model string, reqCount int) {
		mustExec(`INSERT INTO usage_rollup_hourly (tenant_id, bucket_start, project_id, user_id, client_id, provider_id, model_id, request_count, success_count, input_tokens, output_tokens, total_cost)
			VALUES ($1,$2,$3,$4,$5,'',$6,$7,$7,$8,$9,$10)`,
			tenantID, bucket, project, userID, key, model, reqCount, int64(reqCount*10), int64(reqCount*20), float64(reqCount)*0.5)
	}
	insRoll(p1, keyAID, m1id, 2)
	insRoll(p2, keyBID, m2id, 1)

	return portalUsageFixture{db: db, ctx: ctx, tenantID: tenantID, p1: p1, p2: p2, m1id: m1id, m2id: m2id}
}

func portalGet(t *testing.T, h http.HandlerFunc, tenantID, query string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/portal-integration/usage/x"+query, nil)
	req.Header.Set("X-JJDGuard-Tenant-Id", tenantID)
	w := httptest.NewRecorder()
	h(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Code, w.Body.String())
	}
	return w
}

func TestPortalUsageSummaryProjectFilter(t *testing.T) {
	fx := setupPortalUsageFixture(t)
	deps := &Dependencies{UsageDailyRepo: repository.NewUsageDailyRepository(fx.db)}
	h := GetPortalUsageSummary(deps)

	type summary struct {
		Requests int `json:"requests"`
	}
	// 全租户 → 3
	var all summary
	json.Unmarshal(portalGet(t, h, fx.tenantID, "").Body.Bytes(), &all)
	if all.Requests != 3 {
		t.Fatalf("full-tenant summary requests = %d, want 3", all.Requests)
	}
	// project_ids=P1 → 2
	var one summary
	json.Unmarshal(portalGet(t, h, fx.tenantID, "?project_ids="+fx.p1).Body.Bytes(), &one)
	if one.Requests != 2 {
		t.Fatalf("scoped summary requests = %d, want 2", one.Requests)
	}
}

func TestPortalUsageTrendProjectFilter(t *testing.T) {
	fx := setupPortalUsageFixture(t)
	deps := &Dependencies{UsageDailyRepo: repository.NewUsageDailyRepository(fx.db)}
	h := GetPortalUsageTrend(deps)

	type trendResp struct {
		Data []struct {
			Requests int `json:"requests"`
		} `json:"data"`
	}
	sum := func(query string) int {
		var tr trendResp
		json.Unmarshal(portalGet(t, h, fx.tenantID, query).Body.Bytes(), &tr)
		total := 0
		for _, p := range tr.Data {
			total += p.Requests
		}
		return total
	}
	if got := sum(""); got != 3 {
		t.Fatalf("full-tenant trend requests = %d, want 3", got)
	}
	if got := sum("?project_ids=" + fx.p1); got != 2 {
		t.Fatalf("scoped trend requests = %d, want 2", got)
	}
}

func TestPortalUsageByModelProjectFilter(t *testing.T) {
	fx := setupPortalUsageFixture(t)
	deps := &Dependencies{UsageDailyRepo: repository.NewUsageDailyRepository(fx.db)}
	h := GetPortalUsageByModel(deps)

	type row struct {
		ID       string `json:"id"`
		Requests int    `json:"requests"`
	}
	// 全租户 → 2 个模型
	var all []row
	json.Unmarshal(portalGet(t, h, fx.tenantID, "").Body.Bytes(), &all)
	if len(all) != 2 {
		t.Fatalf("full-tenant by-model rows = %d, want 2", len(all))
	}
	// project_ids=P1 → 只剩 m1，requests=2
	var one []row
	json.Unmarshal(portalGet(t, h, fx.tenantID, "?project_ids="+fx.p1).Body.Bytes(), &one)
	if len(one) != 1 || one[0].ID != fx.m1id || one[0].Requests != 2 {
		t.Fatalf("scoped by-model = %+v, want single %s with 2 requests", one, fx.m1id)
	}
}

func TestPortalUsageByKeyProjectFilter(t *testing.T) {
	fx := setupPortalUsageFixture(t)
	deps := &Dependencies{UsageDailyRepo: repository.NewUsageDailyRepository(fx.db)}
	h := GetPortalUsageByKey(deps)

	type row struct {
		Requests int `json:"requests"`
	}
	sum := func(query string) int {
		var rows []row
		json.Unmarshal(portalGet(t, h, fx.tenantID, query).Body.Bytes(), &rows)
		total := 0
		for _, r := range rows {
			total += r.Requests
		}
		return total
	}
	if got := sum(""); got != 3 {
		t.Fatalf("full-tenant by-key requests = %d, want 3", got)
	}
	if got := sum("?project_ids=" + fx.p1); got != 2 {
		t.Fatalf("scoped by-key requests = %d, want 2", got)
	}
}
