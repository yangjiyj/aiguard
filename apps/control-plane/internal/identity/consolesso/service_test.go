package consolesso

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func ticketFrom(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	loc := w.Header().Get("Location")
	if w.Code != http.StatusFound || !strings.HasPrefix(loc, "/login#sso_ticket=") {
		t.Fatalf("callback did not issue ticket: %d %s", w.Code, loc)
	}
	v, _ := url.QueryUnescape(strings.TrimPrefix(loc, "/login#sso_ticket="))
	return v
}

func failCode(w *httptest.ResponseRecorder) string {
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/login?sso_error=") {
		return "no-error:" + loc
	}
	return strings.TrimPrefix(loc, "/login?sso_error=")
}

func redeem(h *harness, ticket string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"ticket": ticket})
	w := httptest.NewRecorder()
	h.svc.Redeem(w, httptest.NewRequest(http.MethodPost, "/admin/v1/auth/sso/session", strings.NewReader(string(body))))
	return w
}

func TestStatusReportsDisabledWithoutConfig(t *testing.T) {
	svc := New(Config{}, nil, nil, nil, nil)
	w := httptest.NewRecorder()
	svc.Status(w, httptest.NewRequest(http.MethodGet, "/admin/v1/auth/sso/status", nil))
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if w.Code != 200 || got["enabled"] != false || got["local_login"] != true || got["login_url"] != nil {
		t.Fatalf("status = %d %v", w.Code, got)
	}
	for _, fn := range []http.HandlerFunc{svc.Login, svc.Callback, svc.Redeem} {
		rec := httptest.NewRecorder()
		fn(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("disabled endpoint returned %d", rec.Code)
		}
	}
}

func TestStatusReportsEnabled(t *testing.T) {
	h := newHarness(t, "tenant_admin")
	w := httptest.NewRecorder()
	h.svc.Status(w, httptest.NewRequest(http.MethodGet, "/admin/v1/auth/sso/status", nil))
	var got map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if got["enabled"] != true || got["login_url"] != LoginPath || got["local_login"] != true {
		t.Fatalf("status = %v", got)
	}
	if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), h.idp.srv.URL) {
		t.Fatalf("status leaks idp detail: %s", w.Body.String())
	}
}

func TestFullFlowCreatesSessionForConsoleAdmin(t *testing.T) {
	h := newHarness(t, "tenant_admin")
	state, binding := h.startLogin(t)
	ticket := ticketFrom(t, h.callback(state, "good-code", binding))
	if len(h.sessions.created) != 0 {
		t.Fatal("session must only be created on ticket redemption")
	}
	w := redeem(h, ticket)
	if w.Code != http.StatusOK {
		t.Fatalf("redeem %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Token string `json:"token"`
		User  struct {
			ID   string `json:"id"`
			Role string `json:"role"`
		} `json:"user"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Token != "sess-u1" || resp.User.ID != "u1" || resp.User.Role != "tenant_admin" {
		t.Fatalf("redeem response %s", w.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "session_token" {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookie %+v", cookie)
	}
	if again := redeem(h, ticket); again.Code != http.StatusUnauthorized {
		t.Fatalf("ticket reused: %d", again.Code)
	}
}

func TestCallbackRejectsReplayedState(t *testing.T) {
	h := newHarness(t, "tenant_admin")
	state, binding := h.startLogin(t)
	ticketFrom(t, h.callback(state, "good-code", binding))
	if got := failCode(h.callback(state, "good-code", binding)); got != "expired" {
		t.Fatalf("replayed state: %s", got)
	}
}

func TestCallbackRejectsMissingOrForeignBrowserBinding(t *testing.T) {
	h := newHarness(t, "tenant_admin")
	state, _ := h.startLogin(t)
	if got := failCode(h.callback(state, "good-code", nil)); got != "invalid_request" {
		t.Fatalf("no binding: %s", got)
	}
	state, _ = h.startLogin(t)
	forged := &http.Cookie{Name: bindingCookie, Value: "attacker-browser"}
	if got := failCode(h.callback(state, "good-code", forged)); got != "invalid_request" {
		t.Fatalf("foreign binding: %s", got)
	}
}

func TestCallbackRejectsTokenProblems(t *testing.T) {
	cases := map[string]func(*harness){
		"wrong nonce":    func(h *harness) { h.idp.claims = func(c map[string]any) { c["nonce"] = "other" } },
		"missing nonce":  func(h *harness) { h.idp.claims = func(c map[string]any) { delete(c, "nonce") } },
		"wrong issuer":   func(h *harness) { h.idp.claims = func(c map[string]any) { c["iss"] = "https://evil/realms/x" } },
		"wrong audience": func(h *harness) { h.idp.claims = func(c map[string]any) { c["aud"] = "enterprise-ai-portal" } },
		"multi aud without azp": func(h *harness) {
			h.idp.claims = func(c map[string]any) { c["aud"] = []string{"jjdguard-console", "x"}; c["azp"] = "x" }
		},
		"expired":        func(h *harness) { h.idp.claims = func(c map[string]any) { c["exp"] = 1000 } },
		"alg none":       func(h *harness) { h.idp.header = map[string]any{"alg": "none", "kid": "k1"} },
		"alg HS256":      func(h *harness) { h.idp.header = map[string]any{"alg": "HS256", "kid": "k1"} },
		"unknown kid":    func(h *harness) { h.idp.header = map[string]any{"alg": "RS256", "kid": "k-other"} },
		"crit header":    func(h *harness) { h.idp.header = map[string]any{"alg": "RS256", "kid": "k1", "crit": []string{"x"}} },
		"empty subject":  func(h *harness) { h.idp.claims = func(c map[string]any) { c["sub"] = " " } },
		"iat in future":  func(h *harness) { h.idp.claims = func(c map[string]any) { c["iat"] = 9999999999 } },
		"token endpoint": func(h *harness) { h.idp.tokenStatus = http.StatusBadGateway },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, "tenant_admin")
			mutate(h)
			state, binding := h.startLogin(t)
			w := h.callback(state, "good-code", binding)
			if code := failCode(w); strings.HasPrefix(code, "no-error") {
				t.Fatalf("accepted: %s", w.Header().Get("Location"))
			}
		})
	}
}

func TestCallbackRejectsForgedSignature(t *testing.T) {
	h := newHarness(t, "tenant_admin")
	other := newFakeIdP(t) // 另一把私钥，同 kid
	h.idp.key = other.key
	state, binding := h.startLogin(t)
	if got := failCode(h.callback(state, "good-code", binding)); got != "invalid_token" {
		t.Fatalf("forged signature: %s", got)
	}
}

func TestCallbackRejectsNonConsoleOrUnlinkedAccounts(t *testing.T) {
	// 门户 JIT 账号默认 developer：不能经 SSO 进控制台。
	h := newHarness(t, "developer")
	state, binding := h.startLogin(t)
	if got := failCode(h.callback(state, "good-code", binding)); got != "not_console_user" {
		t.Fatalf("developer: %s", got)
	}
	// 主体未绑定任何控制台账号：不按用户名/邮箱兜底匹配，也不自动建号。
	h = newHarness(t, "tenant_admin")
	h.idp.claims = func(c map[string]any) { c["sub"] = "kc-sub-unlinked"; c["preferred_username"] = "alice" }
	state, binding = h.startLogin(t)
	if got := failCode(h.callback(state, "good-code", binding)); got != "not_console_user" {
		t.Fatalf("unlinked: %s", got)
	}
	h = newHarness(t, "tenant_admin")
	h.accounts.set("u1", func(a *Account) { a.Status = "disabled" })
	state, binding = h.startLogin(t)
	if got := failCode(h.callback(state, "good-code", binding)); got != "account_inactive" {
		t.Fatalf("disabled: %s", got)
	}
}

func TestRedeemRechecksAccountAfterTicketIssued(t *testing.T) {
	h := newHarness(t, "tenant_admin")
	state, binding := h.startLogin(t)
	ticket := ticketFrom(t, h.callback(state, "good-code", binding))
	h.accounts.set("u1", func(a *Account) { a.Role = "developer" })
	if w := redeem(h, ticket); w.Code != http.StatusUnauthorized || len(h.sessions.created) != 0 {
		t.Fatalf("demoted account redeemed: %d", w.Code)
	}
}

func TestIdPErrorReturnsToLoginPage(t *testing.T) {
	h := newHarness(t, "tenant_admin")
	w := httptest.NewRecorder()
	h.svc.Callback(w, httptest.NewRequest(http.MethodGet, "/admin/v1/auth/sso/callback?error=access_denied", nil))
	if got := failCode(w); got != "idp_denied" {
		t.Fatalf("idp error: %s", got)
	}
}

func TestJWKSRefetchIsRateLimited(t *testing.T) {
	h := newHarness(t, "tenant_admin")
	h.idp.header = map[string]any{"alg": "RS256", "kid": "k-rotated"}
	for i := 0; i < 3; i++ {
		state, binding := h.startLogin(t)
		h.callback(state, "good-code", binding)
	}
	if h.idp.jwksHits != 1 {
		t.Fatalf("unknown kid refetched JWKS %d times", h.idp.jwksHits)
	}
}

func TestConfigValidateRequiresHTTPSWhenSecure(t *testing.T) {
	h := newHarness(t, "tenant_admin")
	cfg := h.idp.config()
	cfg.CookieSecure = true
	if cfg.Validate() == nil {
		t.Fatal("http issuer accepted with secure cookies")
	}
	cfg = h.idp.config()
	cfg.LoginPagePath = "//evil.example/login"
	if cfg.Validate() == nil {
		t.Fatal("protocol-relative login page accepted")
	}
	if strings.Contains(cfg.String(), "console-secret") {
		t.Fatal("config String leaks secret")
	}
}
