package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/go-chi/chi/v5"
	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity/consolesso"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// 9.3：管理员为本租户账号建立 CAS/企业微信绑定；issuer 由服务端配置决定；
// 越权（跨租户、低权限绑高权限账号、未启用的方式、客户端自带 issuer）一律拒绝。
func TestConsoleSSOBindingsAPI(t *testing.T) {
	pool, tenantID, adminID := setupOrgHandlerPool(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	operatorID, ownerID, foreignTenant, foreignUser := adminID+"_op", adminID+"_own", tenantID+"_x", adminID+"_x"
	exec(`INSERT INTO users (id,tenant_id,username,email,password_hash,role,status) VALUES ($1,$2,$1,$3,'x','operator','active')`, operatorID, tenantID, operatorID+"@t.test")
	exec(`INSERT INTO users (id,tenant_id,username,email,password_hash,role,status) VALUES ($1,$2,$1,$3,'x','tenant_owner','active')`, ownerID, tenantID, ownerID+"@t.test")
	exec(`INSERT INTO tenants (id,name,edition,status,is_test) VALUES ($1,$1,'enterprise','active',TRUE)`, foreignTenant)
	exec(`INSERT INTO users (id,tenant_id,username,email,password_hash,role,status) VALUES ($1,$2,$1,$3,'x','operator','active')`, foreignUser, foreignTenant, foreignUser+"@t.test")
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE tenant_id=$1`, foreignTenant)
		_, _ = pool.Exec(ctx, `DELETE FROM tenants WHERE id=$1`, foreignTenant)
	})

	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	users := repository.NewUserRepository(pool)
	svc := consolesso.New(consolesso.Config{}, rc, consolesso.NewPGSubjectResolver(pool),
		consoleSSOAccounts{users: users}, consoleSSOSessions{}).
		WithCAS(consolesso.CASConfig{BaseURL: "https://cas.example.gov.cn/cas", ServiceURL: "https://console.example.com" + consolesso.CASCallbackPath})
	if issuer, ok := svc.ProviderIssuer(consolesso.ProviderCAS); !ok || issuer != "https://cas.example.gov.cn/cas" {
		t.Fatalf("cas not enabled: %q %v", issuer, ok)
	}
	deps := &Dependencies{UserRepo: users, SystemRepo: &orgTestSystemRepo{}}
	r := chi.NewRouter()
	MountConsoleSSOBindings(r, deps, svc, pool)

	call := func(actorRole, actorTenant, method, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		u := &repository.User{ID: adminID, TenantID: actorTenant, Role: actorRole, Status: "active"}
		req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, u))
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}
	bind := func(role, userID, provider, subject string) *httptest.ResponseRecorder {
		return call(role, tenantID, http.MethodPost, "/admin/v1/identity/console-sso/bindings",
			`{"user_id":"`+userID+`","provider":"`+provider+`","external_subject":"`+subject+`"}`)
	}

	w := bind("tenant_admin", operatorID, "cas", "zhangsan")
	var created consolesso.Binding
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	if w.Code != http.StatusCreated || created.Issuer != "https://cas.example.gov.cn/cas" || created.UserID != operatorID {
		t.Fatalf("create = %d %s", w.Code, w.Body.String())
	}
	if w := bind("tenant_admin", operatorID, "cas", "zhangsan"); w.Code != http.StatusOK {
		t.Fatalf("idempotent create = %d", w.Code)
	}
	// 绑定后 CAS 主体能解析到该账号。
	if _, uid, err := consolesso.NewPGSubjectResolver(pool).(consolesso.ProviderSubjectResolver).
		ResolveProviderSubject(ctx, "cas", "https://cas.example.gov.cn/cas", "zhangsan"); err != nil || uid != operatorID {
		t.Fatalf("resolve after bind: %q %v", uid, err)
	}

	cases := []struct {
		name string
		w    *httptest.ResponseRecorder
		want int
	}{
		{"same CAS user to another account", bind("tenant_admin", ownerID, "cas", "zhangsan"), http.StatusForbidden},
		{"tenant_admin cannot bind tenant_owner", bind("tenant_admin", ownerID, "cas", "wangwu"), http.StatusForbidden},
		{"tenant_admin cannot bind platform_admin", bind("tenant_admin", adminID, "cas", "wangwu"), http.StatusForbidden},
		{"conflict for same user by owner", bind("tenant_owner", ownerID, "cas", "zhangsan"), http.StatusConflict},
		{"cross-tenant target", bind("platform_admin", foreignUser, "cas", "lisi"), http.StatusNotFound},
		{"provider not enabled", bind("platform_admin", operatorID, "wecom", "zhangsan"), http.StatusConflict},
		{"unknown provider", bind("platform_admin", operatorID, "oidc", "zhangsan"), http.StatusBadRequest},
		{"client supplied issuer", call("platform_admin", tenantID, http.MethodPost, "/admin/v1/identity/console-sso/bindings",
			`{"user_id":"`+operatorID+`","provider":"cas","external_subject":"x","issuer":"https://evil/cas"}`), http.StatusBadRequest},
		{"non-admin actor", bind("operator", operatorID, "cas", "lisi"), http.StatusForbidden},
		{"list other tenant user", call("platform_admin", tenantID, http.MethodGet, "/admin/v1/identity/console-sso/bindings?user_id="+foreignUser, ""), http.StatusNotFound},
	}
	for _, tc := range cases {
		if tc.w.Code != tc.want {
			t.Errorf("%s: status %d, want %d (%s)", tc.name, tc.w.Code, tc.want, tc.w.Body.String())
		}
	}

	lw := call("tenant_admin", tenantID, http.MethodGet, "/admin/v1/identity/console-sso/bindings?user_id="+operatorID, "")
	if lw.Code != http.StatusOK || !strings.Contains(lw.Body.String(), created.ID) {
		t.Fatalf("list = %d %s", lw.Code, lw.Body.String())
	}
	// 其他租户的管理员拿着绑定 id 删不掉。
	if dw := call("platform_admin", foreignTenant, http.MethodDelete, "/admin/v1/identity/console-sso/bindings/"+created.ID, ""); dw.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant delete = %d", dw.Code)
	}
	if dw := call("tenant_admin", tenantID, http.MethodDelete, "/admin/v1/identity/console-sso/bindings/"+created.ID, ""); dw.Code != http.StatusNoContent {
		t.Fatalf("delete = %d %s", dw.Code, dw.Body.String())
	}
}
