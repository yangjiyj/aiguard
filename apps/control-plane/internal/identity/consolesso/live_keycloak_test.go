package consolesso

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// live：一次性 Keycloak（生产 realm 模板 + 登记 jjdguard-console 客户端）上走真实
// 授权码 + PKCE + nonce + JWKS 验签。CONSOLE_SSO_LIVE_KC_URL 未设置时跳过。
func TestLiveKeycloakConsoleSSO(t *testing.T) {
	base := os.Getenv("CONSOLE_SSO_LIVE_KC_URL")
	if base == "" {
		t.Skip("CONSOLE_SSO_LIVE_KC_URL is not set")
	}
	issuer := strings.TrimSuffix(base, "/") + "/realms/jjdguard"
	var svcHandler http.Handler
	console := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svcHandler.ServeHTTP(w, r)
	}))
	defer console.Close()

	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rc.Close()
	accounts := &fakeAccounts{accounts: map[string]*Account{
		"u-admin": {ID: "u-admin", TenantID: "t1", Username: "alice", Role: "tenant_admin", Status: "active"},
		"u-dev":   {ID: "u-dev", TenantID: "t1", Username: "bob", Role: "developer", Status: "active"},
	}}
	sessions := &fakeSessions{}
	subjects := fakeSubjects{links: map[string][2]string{
		issuer + "|" + os.Getenv("CONSOLE_SSO_LIVE_ADMIN_SUB"): {"t1", "u-admin"},
		issuer + "|" + os.Getenv("CONSOLE_SSO_LIVE_DEV_SUB"):   {"t1", "u-dev"},
	}}
	cfg := Config{
		Issuer: issuer, AuthorizeURL: issuer + "/protocol/openid-connect/auth",
		TokenURL: issuer + "/protocol/openid-connect/token", JWKSURL: issuer + "/protocol/openid-connect/certs",
		ClientID: "jjdguard-console", ClientSecret: os.Getenv("CONSOLE_SSO_LIVE_SECRET"),
		RedirectURL: console.URL + "/admin/v1/auth/sso/callback", LoginPagePath: "/login",
	}
	svc := New(cfg, rc, subjects, accounts, sessions).WithSessionPolicy(allowAllPolicy{})
	if !svc.Enabled() {
		t.Fatal("live service not enabled")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/auth/sso/login", svc.Login)
	mux.HandleFunc("/admin/v1/auth/sso/callback", svc.Callback)
	mux.HandleFunc("/admin/v1/auth/sso/session", svc.Redeem)
	svcHandler = mux

	run := func(user, pass string) string {
		jar, _ := cookiejar.New(nil)
		browser := &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if strings.HasPrefix(req.URL.Path, "/login") {
				return http.ErrUseLastResponse
			}
			return nil
		}}
		resp, err := browser.Get(console.URL + LoginPath)
		if err != nil {
			t.Fatal(err)
		}
		page, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		m := regexp.MustCompile(`action="([^"]+)"`).FindSubmatch(page)
		if m == nil {
			t.Fatalf("no login form (status %d)", resp.StatusCode)
		}
		action := strings.ReplaceAll(string(m[1]), "&amp;", "&")
		resp, err = browser.PostForm(action, url.Values{"username": {user}, "password": {pass}})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.Header.Get("Location")
	}

	loc := run("alice", "Alice-pass-123")
	if !strings.HasPrefix(loc, "/login#sso_ticket=") {
		t.Fatalf("admin flow ended at %q", loc)
	}
	ticketID, _ := url.QueryUnescape(strings.TrimPrefix(loc, "/login#sso_ticket="))
	h := &harness{svc: svc, accounts: accounts, sessions: sessions}
	if w := redeem(h, ticketID); w.Code != http.StatusOK || len(sessions.created) != 1 || sessions.created[0].ID != "u-admin" {
		t.Fatalf("admin redeem: %d %s", w.Code, w.Body.String())
	}
	if loc := run("bob", "Bob-pass-123"); loc != "/login?sso_error=not_console_user" {
		t.Fatalf("developer flow ended at %q", loc)
	}
}
