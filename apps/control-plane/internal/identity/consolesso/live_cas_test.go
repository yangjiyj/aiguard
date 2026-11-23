package consolesso

import (
	"context"
	"encoding/json"
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

// 一次性 Apereo CAS 容器上的真实协议流程（W9 9.3）：
//
//	CONSOLE_SSO_LIVE_CAS_URL=http://127.0.0.1:<port>/cas
//	CONSOLE_SSO_LIVE_CAS_USER / _PASSWORD（默认 casuser / Mellon）
//
// 测试扮演浏览器：/cas/login → CAS 登录页 → 提交账号密码 → CAS 带 ST 跳回 service
// → /cas/callback 调真实 /p3/serviceValidate → 已绑定账号拿到控制台会话；未绑定账号被拒；
// 同一张 ST 第二次使用被 CAS 拒绝。
func TestLiveCASConsoleLogin(t *testing.T) {
	base := strings.TrimSuffix(os.Getenv("CONSOLE_SSO_LIVE_CAS_URL"), "/")
	if base == "" {
		t.Skip("CONSOLE_SSO_LIVE_CAS_URL is not set")
	}
	user, pass := envOr("CONSOLE_SSO_LIVE_CAS_USER", "casuser"), envOr("CONSOLE_SSO_LIVE_CAS_PASSWORD", "Mellon")

	run := func(t *testing.T, links map[string][2]string) (*Service, *fakeSessions, *httptest.ResponseRecorder, string, string, *http.Cookie) {
		mr := miniredis.RunT(t)
		rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { _ = rc.Close() })
		accounts := &fakeAccounts{accounts: map[string]*Account{
			"u-admin": {ID: "u-admin", TenantID: "t1", Username: user, Role: "tenant_admin", Status: "active"},
		}}
		sessions := &fakeSessions{}
		svc := New(Config{}, rc, fakeSubjects{links: links}, accounts, sessions).WithSessionPolicy(allowAllPolicy{}).WithCAS(CASConfig{
			BaseURL: base, ServiceURL: "http://console.live.test" + CASCallbackPath,
		})
		if svc.cas == nil {
			t.Fatal("cas not mounted")
		}
		lw := httptest.NewRecorder()
		svc.CASLogin(lw, httptest.NewRequest(http.MethodGet, CASLoginPath, nil))
		var binding *http.Cookie
		for _, c := range lw.Result().Cookies() {
			if c.Name == bindingCookie {
				binding = c
			}
		}
		loginURL := lw.Header().Get("Location")
		service, st := casBrowserLogin(t, loginURL, user, pass)
		u, _ := url.Parse(service)
		req := httptest.NewRequest(http.MethodGet, u.RequestURI()+"&ticket="+url.QueryEscape(st), nil)
		req.AddCookie(binding)
		cw := httptest.NewRecorder()
		svc.CASCallback(cw, req)
		return svc, sessions, cw, service, st, binding
	}

	t.Run("bound account gets a session", func(t *testing.T) {
		svc, sessions, cw, service, st, _ := run(t, map[string][2]string{"cas|" + base + "|" + user: {"t1", "u-admin"}})
		loc := cw.Header().Get("Location")
		if !strings.HasPrefix(loc, "/login#sso_ticket=") {
			t.Fatalf("callback = %d %s", cw.Code, loc)
		}
		ticketID, _ := url.QueryUnescape(strings.TrimPrefix(loc, "/login#sso_ticket="))
		body, _ := json.Marshal(map[string]string{"ticket": ticketID})
		rw := httptest.NewRecorder()
		svc.Redeem(rw, httptest.NewRequest(http.MethodPost, "/admin/v1/auth/sso/session", strings.NewReader(string(body))))
		if rw.Code != http.StatusOK || len(sessions.created) != 1 || sessions.created[0].ID != "u-admin" {
			t.Fatalf("redeem = %d %s", rw.Code, rw.Body.String())
		}
		// ST 一次性：直接再校验一次，真实 CAS 必须拒绝。
		if _, err := validateCASTicket(context.Background(), newHTTPClient(), *svc.cas, service, st); err == nil {
			t.Fatal("CAS accepted a reused service ticket")
		}
	})
	t.Run("unbound account is rejected", func(t *testing.T) {
		_, sessions, cw, _, _, _ := run(t, map[string][2]string{})
		if ssoError(cw) != "not_console_user" || len(sessions.created) != 0 {
			t.Fatalf("unbound CAS user accepted: %s", cw.Header().Get("Location"))
		}
	})
	t.Run("ticket for another service is rejected by CAS", func(t *testing.T) {
		svc, _, _, service, _, _ := run(t, map[string][2]string{})
		// 重新登录拿一张新的 ST，但用不同的 service 去校验。
		lw := httptest.NewRecorder()
		svc.CASLogin(lw, httptest.NewRequest(http.MethodGet, CASLoginPath, nil))
		_, st := casBrowserLogin(t, lw.Header().Get("Location"), user, pass)
		if _, err := validateCASTicket(context.Background(), newHTTPClient(), *svc.cas, service, st); err == nil {
			t.Fatal("CAS accepted a ticket issued for a different service URL")
		}
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

var executionPattern = regexp.MustCompile(`name="execution"\s+value="([^"]+)"`)

// casBrowserLogin 扮演浏览器完成 CAS 登录，返回 CAS 重定向回来的 service 与 ST。
func casBrowserLogin(t *testing.T, loginURL, user, pass string) (string, string) {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := browser.Get(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	m := executionPattern.FindSubmatch(page)
	if m == nil {
		t.Fatalf("no execution field on CAS login page (status %d)", resp.StatusCode)
	}
	form := url.Values{"username": {user}, "password": {pass}, "execution": {string(m[1])}, "_eventId": {"submit"}}
	resp, err = browser.PostForm(loginURL, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	// CAS 把 ticket 追加在 service 之后；按字符串截取，保证 service 与登录时逐字相同。
	location := resp.Header.Get("Location")
	i := strings.LastIndex(location, "&ticket=")
	if resp.StatusCode != http.StatusFound || i < 0 {
		t.Fatalf("CAS did not redirect back with a ticket: %d %s", resp.StatusCode, location)
	}
	st, err := url.QueryUnescape(location[i+len("&ticket="):])
	if err != nil {
		t.Fatal(err)
	}
	return location[:i], st
}
