package consolesso

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// ResolveProviderSubject 让测试桩按协议类型查绑定：键为 "<provider>|<issuer>|<subject>"。
func (s fakeSubjects) ResolveProviderSubject(_ context.Context, provider, issuer, subject string) (string, string, error) {
	v, ok := s.links[provider+"|"+issuer+"|"+subject]
	if !ok {
		return "", "", errAccountNotLinked
	}
	return v[0], v[1], nil
}

// fakeCAS 模拟 CAS 3.0 服务端：记录签发的 ST 与其 service，校验时要求 service 逐字相同、票据一次性。
type fakeCAS struct {
	srv  *httptest.Server
	mu   sync.Mutex
	st   map[string]string // ticket -> service
	body func(user string) string
	hits int
}

func newFakeCAS(t *testing.T) *fakeCAS {
	t.Helper()
	f := &fakeCAS{st: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/cas/p3/serviceValidate", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.hits++
		q := r.URL.Query()
		svc, ok := f.st[q.Get("ticket")]
		delete(f.st, q.Get("ticket"))
		w.Header().Set("Content-Type", "application/xml")
		if !ok || svc != q.Get("service") {
			_, _ = fmt.Fprint(w, `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationFailure code="INVALID_TICKET">Ticket not recognized</cas:authenticationFailure>
</cas:serviceResponse>`)
			return
		}
		if f.body != nil {
			_, _ = fmt.Fprint(w, f.body("zhangsan"))
			return
		}
		_, _ = fmt.Fprint(w, `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas">
  <cas:authenticationSuccess>
    <cas:user>zhangsan</cas:user>
    <cas:attributes><cas:dept>d1</cas:dept></cas:attributes>
  </cas:authenticationSuccess>
</cas:serviceResponse>`)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeCAS) base() string { return f.srv.URL + "/cas" }

// issue 模拟用户在 CAS 登录成功：为 service 签发一张 ST。
func (f *fakeCAS) issue(service string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	t := fmt.Sprintf("ST-%d-abcdef", len(f.st)+f.hits+1)
	f.st[t] = service
	return t
}

type casHarness struct {
	cas      *fakeCAS
	svc      *Service
	accounts *fakeAccounts
	sessions *fakeSessions
}

func newCASHarness(t *testing.T, role string, links map[string][2]string) *casHarness {
	t.Helper()
	cas := newFakeCAS(t)
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	accounts := &fakeAccounts{accounts: map[string]*Account{
		"u1": {ID: "u1", TenantID: "t1", Username: "zhangsan", Role: role, Status: "active"},
	}}
	sessions := &fakeSessions{}
	if links == nil {
		links = map[string][2]string{"cas|" + cas.base() + "|zhangsan": {"t1", "u1"}}
	}
	// OIDC 未配置：CAS 可以单独启用。
	svc := New(Config{}, rc, fakeSubjects{links: links}, accounts, sessions).WithSessionPolicy(allowAllPolicy{}).WithCAS(CASConfig{
		BaseURL: cas.base(), ServiceURL: "http://console.test" + CASCallbackPath, DisplayName: "Unified CAS",
	})
	if svc.cas == nil || !svc.Enabled() {
		t.Fatal("cas not mounted")
	}
	return &casHarness{cas: cas, svc: svc, accounts: accounts, sessions: sessions}
}

// casLogin 走 /cas/login，返回 CAS 登录页上的 service 值与浏览器绑定 cookie。
func (h *casHarness) casLogin(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	h.svc.CASLogin(w, httptest.NewRequest(http.MethodGet, CASLoginPath, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("cas login status %d", w.Code)
	}
	loc, _ := url.Parse(w.Header().Get("Location"))
	if loc.Path != "/cas/login" {
		t.Fatalf("redirect = %s", loc)
	}
	service := loc.Query().Get("service")
	if !strings.HasPrefix(service, "http://console.test"+CASCallbackPath+"?s=") {
		t.Fatalf("service = %q", service)
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == bindingCookie {
			return service, c
		}
	}
	t.Fatal("no binding cookie")
	return "", nil
}

// casCallback 模拟 CAS 把浏览器带回 service?ticket=ST-…
func (h *casHarness) casCallback(service, ticket string, binding *http.Cookie) *httptest.ResponseRecorder {
	target := service + "&ticket=" + url.QueryEscape(ticket)
	u, _ := url.Parse(target)
	req := httptest.NewRequest(http.MethodGet, u.RequestURI(), nil)
	if binding != nil {
		req.AddCookie(binding)
	}
	w := httptest.NewRecorder()
	h.svc.CASCallback(w, req)
	return w
}

func ssoError(w *httptest.ResponseRecorder) string {
	u, _ := url.Parse(w.Header().Get("Location"))
	return u.Query().Get("sso_error")
}

func TestCASLoginIssuesSessionForBoundAccount(t *testing.T) {
	h := newCASHarness(t, "tenant_admin", nil)
	service, binding := h.casLogin(t)
	w := h.casCallback(service, h.cas.issue(service), binding)
	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, "/login#sso_ticket=") {
		t.Fatalf("callback = %d %s", w.Code, loc)
	}
	ticketID, _ := url.QueryUnescape(strings.TrimPrefix(loc, "/login#sso_ticket="))
	body, _ := json.Marshal(map[string]string{"ticket": ticketID})
	rw := httptest.NewRecorder()
	h.svc.Redeem(rw, httptest.NewRequest(http.MethodPost, "/admin/v1/auth/sso/session", strings.NewReader(string(body))))
	var got map[string]any
	_ = json.Unmarshal(rw.Body.Bytes(), &got)
	if rw.Code != http.StatusOK || got["sso_provider"] != "cas" || len(h.sessions.created) != 1 || h.sessions.created[0].ID != "u1" {
		t.Fatalf("redeem = %d %v", rw.Code, got)
	}
}

func TestCASRejectsForgedReplayedAndCrossProtocolTickets(t *testing.T) {
	t.Run("ticket not issued by CAS", func(t *testing.T) {
		h := newCASHarness(t, "tenant_admin", nil)
		service, binding := h.casLogin(t)
		if w := h.casCallback(service, "ST-1-forged", binding); ssoError(w) != "invalid_token" {
			t.Fatalf("forged ticket accepted: %s", w.Header().Get("Location"))
		}
	})
	t.Run("ticket issued for a different service", func(t *testing.T) {
		h := newCASHarness(t, "tenant_admin", nil)
		service, binding := h.casLogin(t)
		st := h.cas.issue("https://other-app.example.com/")
		if w := h.casCallback(service, st, binding); ssoError(w) != "invalid_token" {
			t.Fatalf("foreign-service ticket accepted: %s", w.Header().Get("Location"))
		}
	})
	t.Run("state replay", func(t *testing.T) {
		h := newCASHarness(t, "tenant_admin", nil)
		service, binding := h.casLogin(t)
		if w := h.casCallback(service, h.cas.issue(service), binding); w.Code != http.StatusFound || ssoError(w) != "" {
			t.Fatalf("first callback: %s", w.Header().Get("Location"))
		}
		if w := h.casCallback(service, h.cas.issue(service), binding); ssoError(w) != "expired" {
			t.Fatalf("state reused: %s", w.Header().Get("Location"))
		}
	})
	t.Run("other browser", func(t *testing.T) {
		h := newCASHarness(t, "tenant_admin", nil)
		service, _ := h.casLogin(t)
		hits := h.cas.hits
		if w := h.casCallback(service, h.cas.issue(service), &http.Cookie{Name: bindingCookie, Value: "attacker"}); ssoError(w) != "invalid_request" {
			t.Fatalf("login CSRF accepted: %s", w.Header().Get("Location"))
		}
		if h.cas.hits != hits {
			t.Fatal("ticket must not be validated before browser binding check")
		}
	})
	t.Run("proxy ticket", func(t *testing.T) {
		h := newCASHarness(t, "tenant_admin", nil)
		service, binding := h.casLogin(t)
		if w := h.casCallback(service, "PT-1-abc", binding); ssoError(w) != "invalid_request" {
			t.Fatalf("proxy ticket accepted: %s", w.Header().Get("Location"))
		}
	})
	t.Run("proxied authentication", func(t *testing.T) {
		h := newCASHarness(t, "tenant_admin", nil)
		h.cas.body = func(user string) string {
			return `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess>
<cas:user>` + user + `</cas:user><cas:proxies><cas:proxy>https://evil.example.com/pgt</cas:proxy></cas:proxies>
</cas:authenticationSuccess></cas:serviceResponse>`
		}
		service, binding := h.casLogin(t)
		if w := h.casCallback(service, h.cas.issue(service), binding); ssoError(w) != "invalid_token" {
			t.Fatalf("proxied authentication accepted: %s", w.Header().Get("Location"))
		}
	})
	t.Run("oidc state cannot be used on cas callback", func(t *testing.T) {
		h := newCASHarness(t, "tenant_admin", nil)
		binding := "b"
		_ = h.svc.store.putState(context.Background(), "oidc-state", flowState{Provider: ProviderOIDC, BindingHash: hashHex(binding)})
		service := h.svc.cas.serviceFor("oidc-state")
		if w := h.casCallback(service, h.cas.issue(service), &http.Cookie{Name: bindingCookie, Value: binding}); ssoError(w) != "invalid_request" {
			t.Fatalf("cross-protocol state accepted: %s", w.Header().Get("Location"))
		}
	})
}

func TestCASResponseParsing(t *testing.T) {
	cases := map[string]string{
		"both success and failure": `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>a</cas:user></cas:authenticationSuccess><cas:authenticationFailure code="X"/></cas:serviceResponse>`,
		"wrong namespace":          `<cas:serviceResponse xmlns:cas="http://evil.example.com/cas"><cas:authenticationSuccess><cas:user>zhangsan</cas:user></cas:authenticationSuccess></cas:serviceResponse>`,
		"empty user":               `<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>  </cas:user></cas:authenticationSuccess></cas:serviceResponse>`,
		"entity expansion":         `<!DOCTYPE x [<!ENTITY u "zhangsan">]><cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>&u;</cas:user></cas:authenticationSuccess></cas:serviceResponse>`,
		"not xml":                  `{"user":"zhangsan"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = fmt.Fprint(w, body) }))
			defer srv.Close()
			user, err := validateCASTicket(context.Background(), newHTTPClient(), CASConfig{BaseURL: srv.URL}, "svc", "ST-1")
			if err == nil {
				t.Fatalf("accepted user %q", user)
			}
		})
	}
}

func TestCASUnboundOrOIDCBoundIdentityCannotLogin(t *testing.T) {
	// 同一 issuer/subject 只有 OIDC 绑定（没有 cas 绑定）时，CAS 登录必须拒绝。
	h := newCASHarness(t, "tenant_admin", map[string][2]string{})
	h.svc.subjects = fakeSubjects{links: map[string][2]string{h.cas.base() + "|zhangsan": {"t1", "u1"}}}
	service, binding := h.casLogin(t)
	if w := h.casCallback(service, h.cas.issue(service), binding); ssoError(w) != "not_console_user" {
		t.Fatalf("unbound cas identity accepted: %s", w.Header().Get("Location"))
	}
	if len(h.sessions.created) != 0 {
		t.Fatal("session created")
	}
}

func TestCASDisabledAndConfigValidation(t *testing.T) {
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rc.Close()
	svc := New(Config{}, rc, fakeSubjects{}, &fakeAccounts{}, &fakeSessions{})
	for _, bad := range []CASConfig{
		{},
		{BaseURL: "https://cas.example.com/cas"},
		{BaseURL: "ftp://cas.example.com/cas", ServiceURL: "https://c.example.com/cb"},
		{BaseURL: "https://u:p@cas.example.com/cas", ServiceURL: "https://c.example.com/cb"},
		{BaseURL: "https://cas.example.com/cas?x=1", ServiceURL: "https://c.example.com/cb"},
	} {
		if svc.WithCAS(bad); svc.cas != nil {
			t.Fatalf("invalid config mounted: %+v", bad)
		}
	}
	w := httptest.NewRecorder()
	svc.CASLogin(w, httptest.NewRequest(http.MethodGet, CASLoginPath, nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("disabled cas login = %d", w.Code)
	}
	// secure 模式下浏览器侧必须 https。
	secure := New(Config{CookieSecure: true}, rc, fakeSubjects{}, &fakeAccounts{}, &fakeSessions{})
	if secure.WithCAS(CASConfig{BaseURL: "http://cas.example.com/cas", ServiceURL: "https://c.example.com/cb"}); secure.cas != nil {
		t.Fatal("http CAS accepted in secure mode")
	}
	// 共享依赖缺失（无 Redis）时不能挂载。
	bare := New(Config{}, nil, nil, nil, nil)
	if bare.WithCAS(CASConfig{BaseURL: "https://cas.example.com/cas", ServiceURL: "https://c.example.com/cb"}); bare.cas != nil {
		t.Fatal("cas mounted without state store")
	}
}

func TestStatusListsProviders(t *testing.T) {
	h := newCASHarness(t, "tenant_admin", nil)
	w := httptest.NewRecorder()
	h.svc.Status(w, httptest.NewRequest(http.MethodGet, "/admin/v1/auth/sso/status", nil))
	var got struct {
		Enabled   bool                `json:"enabled"`
		LoginURL  string              `json:"login_url"`
		Providers []map[string]string `json:"providers"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if !got.Enabled || got.LoginURL != CASLoginPath || len(got.Providers) != 1 || got.Providers[0]["id"] != "cas" {
		t.Fatalf("status = %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), h.cas.srv.URL) {
		t.Fatal("status must not expose CAS server address")
	}
}
