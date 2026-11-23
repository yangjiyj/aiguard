package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/go-chi/chi/v5"
)

type egressAuditRepo struct {
	MockSystemRepo
	ops []*repository.AuditOperation
}

func (r *egressAuditRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	r.ops = append(r.ops, op)
	return nil
}

func (r *egressAuditRepo) find(action string) *repository.AuditOperation {
	for _, op := range r.ops {
		if op.ActionType == action {
			return op
		}
	}
	return nil
}

var reverseProxyAdmin = &repository.User{ID: "user_admin", TenantID: "tenant_demo", Role: "platform_admin"}

func TestCreateReverseProxyRouteStoresEgressOverridesAndAuditsEnable(t *testing.T) {
	repo := newMockReverseProxyRouteRepo()
	audit := &egressAuditRepo{}
	deps := &Dependencies{ReverseProxyRouteRepo: repo, SystemRepo: audit}
	body := `{"name":"Local","path_prefix":"/proxy/local","target_url":"http://127.0.0.1:8000","status":"active",
		"egress_overrides":{"allow_loopback":true}}`
	w := httptest.NewRecorder()
	CreateReverseProxyRoute(deps).ServeHTTP(w, reverseProxyTestRequest(http.MethodPost, "/admin/v1/reverse-proxy/routes", body, reverseProxyAdmin))
	if w.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var got ReverseProxyRouteInfo
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.EgressOverrides.AllowLoopback {
		t.Fatalf("response overrides = %+v", got.EgressOverrides)
	}
	op := audit.find("egress_override.enable")
	if op == nil {
		t.Fatalf("no egress_override.enable among %d ops", len(audit.ops))
	}
	if enabled, _ := op.ActionDetail["enabled"].([]string); len(enabled) != 1 || enabled[0] != "allow_loopback" {
		t.Fatalf("audit detail = %+v", op.ActionDetail)
	}
}

func TestCreateReverseProxyRouteRejectsMCPOnlyOverridesAndBadValues(t *testing.T) {
	for _, overrides := range []string{`{"insecure_skip_verify":true}`, `{"allow_same_host_redirect":true}`, `{"trusted_ca_pem":"x"}`, `{"allow_everything":true}`} {
		repo := newMockReverseProxyRouteRepo()
		deps := &Dependencies{ReverseProxyRouteRepo: repo, SystemRepo: &egressAuditRepo{}}
		body := `{"name":"Local","path_prefix":"/proxy/local","target_url":"https://api.example.com","status":"active","egress_overrides":` + overrides + `}`
		w := httptest.NewRecorder()
		CreateReverseProxyRoute(deps).ServeHTTP(w, reverseProxyTestRequest(http.MethodPost, "/admin/v1/reverse-proxy/routes", body, reverseProxyAdmin))
		if w.Code == http.StatusCreated || len(repo.entries) != 0 {
			t.Errorf("%s accepted: status=%d", overrides, w.Code)
		}
	}
}

func TestUpdateReverseProxyRouteKeepsOverridesWhenOmittedAndAuditsNewFlags(t *testing.T) {
	repo := newMockReverseProxyRouteRepo()
	audit := &egressAuditRepo{}
	deps := &Dependencies{ReverseProxyRouteRepo: repo, SystemRepo: audit}
	created := httptest.NewRecorder()
	CreateReverseProxyRoute(deps).ServeHTTP(created, reverseProxyTestRequest(http.MethodPost, "/admin/v1/reverse-proxy/routes",
		`{"name":"Local","path_prefix":"/proxy/local","target_url":"http://127.0.0.1:8000","status":"active","egress_overrides":{"allow_loopback":true}}`, reverseProxyAdmin))
	var route ReverseProxyRouteInfo
	_ = json.Unmarshal(created.Body.Bytes(), &route)
	update := func(body string) *httptest.ResponseRecorder {
		req := reverseProxyTestRequest(http.MethodPut, "/admin/v1/reverse-proxy/routes/"+route.ID, body, reverseProxyAdmin)
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", route.ID)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		w := httptest.NewRecorder()
		UpdateReverseProxyRoute(deps).ServeHTTP(w, req)
		return w
	}
	audit.ops = nil
	if w := update(`{"description":"x"}`); w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !repo.entries[route.ID].EgressOverrides.AllowLoopback || audit.find("egress_override.enable") != nil {
		t.Fatalf("omitted overrides must be kept without a new enable audit: %+v", repo.entries[route.ID].EgressOverrides)
	}
	if w := update(`{"egress_overrides":{"allow_loopback":true,"allow_metadata":true}}`); w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	op := audit.find("egress_override.enable")
	if op == nil {
		t.Fatal("newly enabled metadata override was not audited")
	}
	if enabled, _ := op.ActionDetail["enabled"].([]string); len(enabled) != 1 || enabled[0] != "allow_metadata" {
		t.Fatalf("audit detail = %+v", op.ActionDetail)
	}
}

// mcpPlatformAdminRequest 与 mcpHardeningAdminRequest 相同，但角色是平台管理员。
func mcpPlatformAdminRequest(method, tenant, user, server string, body []byte) *http.Request {
	r := mcpHardeningAdminRequest(method, tenant, user, server, body)
	return r.WithContext(context.WithValue(r.Context(), auth.UserKey, &repository.User{ID: user, TenantID: tenant, Role: "platform_admin"}))
}

func TestMCPServerEgressOverridesDatabaseStoredAndAudited(t *testing.T) {
	db, deps, tenant, user, server := mcpHardeningDatabaseFixture(t)
	body, _ := json.Marshal(map[string]interface{}{"name": "safe", "server_url": "https://mcp.example/rpc", "transport": "streamable_http",
		"egress_overrides": map[string]interface{}{"allow_metadata": true, "allow_same_host_redirect": true}})
	// 租户级角色不能打开出站放宽（D8 只授权平台管理员和平台级安全员）。
	forbidden := httptest.NewRecorder()
	UpdateMCPServer(deps)(forbidden, mcpHardeningAdminRequest(http.MethodPut, tenant, user, server, body))
	if forbidden.Code != http.StatusForbidden {
		t.Fatalf("tenant admin enabling egress overrides: %d %s", forbidden.Code, forbidden.Body.String())
	}
	if stored, _ := deps.MCPServerRepo.Get(context.Background(), tenant, server); stored.EgressOverrides.AllowMetadata {
		t.Fatal("forbidden change was stored")
	}
	w := httptest.NewRecorder()
	UpdateMCPServer(deps)(w, mcpPlatformAdminRequest(http.MethodPut, tenant, user, server, body))
	if w.Code != 200 {
		t.Fatalf("update=%d %s", w.Code, w.Body.String())
	}
	stored, err := deps.MCPServerRepo.Get(context.Background(), tenant, server)
	if err != nil || !stored.EgressOverrides.AllowMetadata || !stored.EgressOverrides.AllowSameHostRedirect {
		t.Fatalf("stored=%+v err=%v", stored, err)
	}
	var count int
	if err := db.QueryRow(context.Background(), `SELECT count(*) FROM audit_operations WHERE user_id=$1 AND target_id=$2 AND action_type='egress_override.enable'`, user, server).Scan(&count); err != nil || count != 1 {
		t.Fatalf("egress_override.enable audit count=%d err=%v", count, err)
	}
	// 省略 egress_overrides（租户级角色编辑其他字段）：允许，保持不变。
	body, _ = json.Marshal(map[string]interface{}{"name": "safe", "server_url": "https://mcp.example/rpc", "transport": "streamable_http"})
	w = httptest.NewRecorder()
	UpdateMCPServer(deps)(w, mcpHardeningAdminRequest(http.MethodPut, tenant, user, server, body))
	stored, _ = deps.MCPServerRepo.Get(context.Background(), tenant, server)
	if w.Code != 200 || !stored.EgressOverrides.AllowMetadata {
		t.Fatalf("omitted overrides changed: code=%d stored=%+v", w.Code, stored.EgressOverrides)
	}
	// 坏的 CA：400，不落库。
	body, _ = json.Marshal(map[string]interface{}{"name": "safe", "server_url": "https://mcp.example/rpc", "transport": "streamable_http",
		"egress_overrides": map[string]interface{}{"trusted_ca_pem": "not a cert"}})
	w = httptest.NewRecorder()
	UpdateMCPServer(deps)(w, mcpHardeningAdminRequest(http.MethodPut, tenant, user, server, body))
	if w.Code != 400 {
		t.Fatalf("invalid CA accepted: %d %s", w.Code, w.Body.String())
	}
}

// egress_overrides 纳入路由指纹（与 allow_private_egress 一致）：打开放行项后路由指纹变化，
// 已批准的服务需要重新批准；缺省值不改变存量指纹。
func TestMCPServerEgressOverridesChangeRouteHashDatabase(t *testing.T) {
	db, deps, tenant, user, server := mcpHardeningDatabaseFixture(t)
	hash := func() string {
		var h string
		if err := db.QueryRow(context.Background(), `SELECT observed_route_hash FROM mcp_servers WHERE tenant_id=$1 AND id=$2`, tenant, server).Scan(&h); err != nil {
			t.Fatal(err)
		}
		return h
	}
	before := hash()
	if _, err := db.Exec(context.Background(), `UPDATE mcp_servers SET egress_overrides='{"allow_loopback":false}'::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, server); err != nil {
		t.Fatal(err)
	}
	if hash() != before {
		t.Fatal("all-false overrides must keep the existing route fingerprint")
	}
	if _, err := db.Exec(context.Background(), `UPDATE mcp_servers SET egress_overrides='{"allow_loopback":true}'::jsonb WHERE tenant_id=$1 AND id=$2`, tenant, server); err != nil {
		t.Fatal(err)
	}
	if hash() == before {
		t.Fatal("enabling an egress override must change the route fingerprint")
	}
	_ = deps
	_ = user
}

func TestEgressLooseningRequiresPlatformRole(t *testing.T) {
	for _, tc := range []struct {
		user *repository.User
		want bool
	}{
		{&repository.User{Role: "platform_admin", TenantID: "tenant_x"}, true},
		{&repository.User{Role: "security_officer", TenantID: semanticConfigTenant}, true},
		{&repository.User{Role: "security_officer", TenantID: "tenant_x"}, false},
		{&repository.User{Role: "tenant_admin", TenantID: semanticConfigTenant}, false},
	} {
		if got := canLoosenEgress(tc.user); got != tc.want {
			t.Errorf("%s/%s = %v want %v", tc.user.Role, tc.user.TenantID, got, tc.want)
		}
	}
	tenantAdmin := &repository.User{Role: "tenant_admin", TenantID: "tenant_x"}
	if !notifyPrivateTargetForbidden(tenantAdmin, map[string]any{}, map[string]any{"allow_private_target": true}) {
		t.Fatal("tenant admin turning on allow_private_target must be forbidden")
	}
	if notifyPrivateTargetForbidden(tenantAdmin, map[string]any{"allow_private_target": true}, map[string]any{"allow_private_target": true}) {
		t.Fatal("keeping an existing value must be allowed")
	}
	if notifyPrivateTargetForbidden(tenantAdmin, map[string]any{"allow_private_target": true}, map[string]any{"allow_private_target": false}) {
		t.Fatal("turning it off must be allowed")
	}
}
