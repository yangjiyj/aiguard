package consolesso

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

const testCorpID = "ww1234567890abcd"

// fakeWeCom 模拟企业微信 API：gettoken + auth/getuserinfo。
type fakeWeCom struct {
	srv *httptest.Server

	mu          sync.Mutex
	tokenCalls  int
	token       string
	expireNext  bool           // 下一次 getuserinfo 返回 42001（token 过期）
	codes       map[string]any // code -> 响应体
	secretCalls []string
}

func newFakeWeCom(t *testing.T) *fakeWeCom {
	t.Helper()
	f := &fakeWeCom{token: "tok-1", codes: map[string]any{
		"code-member":   map[string]any{"errcode": 0, "errmsg": "ok", "userid": "zhangsan"},
		"code-external": map[string]any{"errcode": 0, "errmsg": "ok", "openid": "o-abc"},
		"code-legacy":   map[string]any{"errcode": 0, "errmsg": "ok", "UserId": "zhangsan"},
		"code-weird":    map[string]any{"errcode": 0, "errmsg": "ok", "userid": "a b<script>"},
	}}
	mux := http.NewServeMux()
	mux.HandleFunc("/cgi-bin/gettoken", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokenCalls++
		f.secretCalls = append(f.secretCalls, r.URL.Query().Get("corpsecret"))
		if r.URL.Query().Get("corpid") != testCorpID || r.URL.Query().Get("corpsecret") != "wecom-secret" {
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 40013, "errmsg": "invalid corpid"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 0, "access_token": f.token, "expires_in": 7200})
	})
	mux.HandleFunc("/cgi-bin/auth/getuserinfo", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.expireNext {
			f.expireNext = false
			f.token = "tok-2"
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 42001, "errmsg": "access_token expired"})
			return
		}
		if r.URL.Query().Get("access_token") != f.token {
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 40014, "errmsg": "invalid access_token"})
			return
		}
		code := r.URL.Query().Get("code")
		resp, ok := f.codes[code]
		delete(f.codes, code) // code 一次性
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"errcode": 40029, "errmsg": "invalid code"})
			return
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

type weComHarness struct {
	api      *fakeWeCom
	svc      *Service
	sessions *fakeSessions
}

func newWeComHarness(t *testing.T) *weComHarness {
	t.Helper()
	api := newFakeWeCom(t)
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	accounts := &fakeAccounts{accounts: map[string]*Account{
		"u1": {ID: "u1", TenantID: "t1", Username: "zhangsan", Role: "tenant_admin", Status: "active"},
	}}
	sessions := &fakeSessions{}
	links := map[string][2]string{"wecom|wecom:" + testCorpID + "|zhangsan": {"t1", "u1"}}
	svc := New(Config{}, rc, fakeSubjects{links: links}, accounts, sessions).WithSessionPolicy(allowAllPolicy{}).WithWeCom(WeComConfig{
		CorpID: testCorpID, AgentID: "1000002", Secret: "wecom-secret",
		RedirectURL:  "http://console.test" + WeComCallbackPath,
		AuthorizeURL: "http://login.wecom.test/wwlogin/sso/login", APIBaseURL: api.srv.URL,
	})
	if svc.wecom == nil {
		t.Fatal("wecom not mounted")
	}
	return &weComHarness{api: api, svc: svc, sessions: sessions}
}

func (h *weComHarness) login(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	h.svc.WeComLogin(w, httptest.NewRequest(http.MethodGet, WeComLoginPath, nil))
	loc, _ := url.Parse(w.Header().Get("Location"))
	q := loc.Query()
	if w.Code != http.StatusFound || loc.Host != "login.wecom.test" || q.Get("appid") != testCorpID ||
		q.Get("agentid") != "1000002" || q.Get("login_type") != "CorpApp" || q.Get("state") == "" {
		t.Fatalf("login redirect = %d %s", w.Code, loc)
	}
	if strings.Contains(loc.String(), "wecom-secret") {
		t.Fatal("secret leaked to browser")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == bindingCookie {
			return q.Get("state"), c
		}
	}
	t.Fatal("no binding cookie")
	return "", nil
}

func (h *weComHarness) callback(state, code string, binding *http.Cookie, extra url.Values) *httptest.ResponseRecorder {
	q := url.Values{"state": {state}, "code": {code}}
	for k, v := range extra {
		q[k] = v
	}
	req := httptest.NewRequest(http.MethodGet, WeComCallbackPath+"?"+q.Encode(), nil)
	if binding != nil {
		req.AddCookie(binding)
	}
	w := httptest.NewRecorder()
	h.svc.WeComCallback(w, req)
	return w
}

func TestWeComLoginIssuesTicketForBoundMember(t *testing.T) {
	h := newWeComHarness(t)
	state, binding := h.login(t)
	w := h.callback(state, "code-member", binding, url.Values{"appid": {testCorpID}})
	if w.Code != http.StatusFound || !strings.HasPrefix(w.Header().Get("Location"), "/login#sso_ticket=") {
		t.Fatalf("callback = %d %s", w.Code, w.Header().Get("Location"))
	}
	// access_token 被缓存：第二次登录不再调 gettoken。
	state2, binding2 := h.login(t)
	h.api.codes["code-member-2"] = map[string]any{"errcode": 0, "userid": "zhangsan"}
	if w := h.callback(state2, "code-member-2", binding2, nil); ssoError(w) != "" {
		t.Fatalf("second login: %s", w.Header().Get("Location"))
	}
	if h.api.tokenCalls != 1 {
		t.Fatalf("gettoken called %d times, want 1 (cached)", h.api.tokenCalls)
	}
}

func TestWeComRefreshesExpiredAccessTokenOnce(t *testing.T) {
	h := newWeComHarness(t)
	state, binding := h.login(t)
	// 先暖一次 token 缓存。
	if _, err := h.svc.wecom.accessToken(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	h.api.expireNext = true
	if w := h.callback(state, "code-member", binding, nil); ssoError(w) != "" {
		t.Fatalf("expired token not refreshed: %s", w.Header().Get("Location"))
	}
	if h.api.tokenCalls != 2 {
		t.Fatalf("gettoken calls = %d, want 2", h.api.tokenCalls)
	}
}

func TestWeComTokenCacheExpiresByClock(t *testing.T) {
	h := newWeComHarness(t)
	now := time.Now()
	h.svc.wecom.now = func() time.Time { return now }
	if _, err := h.svc.wecom.accessToken(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	now = now.Add(7200*time.Second - weComTokenMargin + time.Second)
	if _, err := h.svc.wecom.accessToken(t.Context(), false); err != nil {
		t.Fatal(err)
	}
	if h.api.tokenCalls != 2 {
		t.Fatalf("token not refreshed near expiry: calls=%d", h.api.tokenCalls)
	}
}

func TestWeComRejections(t *testing.T) {
	cases := []struct {
		name  string
		code  string
		extra url.Values
		want  string
	}{
		{"non-member (openid only)", "code-external", nil, "not_console_user"},
		{"invalid code", "code-unknown", nil, "invalid_token"},
		{"malformed userid", "code-weird", nil, "invalid_token"},
		{"other corp appid", "code-member", url.Values{"appid": {"wwotherCorp999"}}, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newWeComHarness(t)
			state, binding := h.login(t)
			if w := h.callback(state, tc.code, binding, tc.extra); ssoError(w) != tc.want {
				t.Fatalf("got %s, want %s", w.Header().Get("Location"), tc.want)
			}
			if len(h.sessions.created) != 0 {
				t.Fatal("session created")
			}
		})
	}
	t.Run("legacy UserId field still accepted", func(t *testing.T) {
		h := newWeComHarness(t)
		state, binding := h.login(t)
		if w := h.callback(state, "code-legacy", binding, nil); ssoError(w) != "" {
			t.Fatalf("legacy field rejected: %s", w.Header().Get("Location"))
		}
	})
	t.Run("login CSRF: other browser", func(t *testing.T) {
		h := newWeComHarness(t)
		state, _ := h.login(t)
		if w := h.callback(state, "code-member", &http.Cookie{Name: bindingCookie, Value: "x"}, nil); ssoError(w) != "invalid_request" {
			t.Fatalf("csrf accepted: %s", w.Header().Get("Location"))
		}
		if h.api.tokenCalls != 0 {
			t.Fatal("code must not be exchanged before browser binding check")
		}
	})
	t.Run("state replay", func(t *testing.T) {
		h := newWeComHarness(t)
		state, binding := h.login(t)
		_ = h.callback(state, "code-member", binding, nil)
		h.api.codes["code-2"] = map[string]any{"errcode": 0, "userid": "zhangsan"}
		if w := h.callback(state, "code-2", binding, nil); ssoError(w) != "expired" {
			t.Fatalf("replayed state accepted: %s", w.Header().Get("Location"))
		}
	})
	t.Run("cas state on wecom callback", func(t *testing.T) {
		h := newWeComHarness(t)
		_ = h.svc.store.putState(t.Context(), "cas-state", flowState{Provider: ProviderCAS, BindingHash: hashHex("b")})
		if w := h.callback("cas-state", "code-member", &http.Cookie{Name: bindingCookie, Value: "b"}, nil); ssoError(w) != "invalid_request" {
			t.Fatalf("cross-protocol state accepted: %s", w.Header().Get("Location"))
		}
	})
}

func TestWeComConfigValidationAndRedaction(t *testing.T) {
	good := WeComConfig{CorpID: testCorpID, AgentID: "1000002", Secret: "s", RedirectURL: "https://c.example.com/cb"}
	if err := good.Validate(true); err != nil {
		t.Fatalf("good config rejected: %v", err)
	}
	for name, mut := range map[string]func(*WeComConfig){
		"no secret":       func(c *WeComConfig) { c.Secret = "" },
		"bad corpid":      func(c *WeComConfig) { c.CorpID = "ww/../x" },
		"bad agentid":     func(c *WeComConfig) { c.AgentID = "abc" },
		"http redirect":   func(c *WeComConfig) { c.RedirectURL = "http://c.example.com/cb" },
		"http api base":   func(c *WeComConfig) { c.APIBaseURL = "http://qyapi.example.com" },
		"userinfo in url": func(c *WeComConfig) { c.RedirectURL = "https://u:p@c.example.com/cb" },
	} {
		c := good
		mut(&c)
		if c.Validate(true) == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if s := good.String(); strings.Contains(s, "Secret:s") || !strings.Contains(s, "[redacted]") {
		t.Fatalf("secret not redacted: %s", s)
	}
}

func TestWeComNetworkErrorDoesNotLeakSecret(t *testing.T) {
	c := newWeComClient(WeComConfig{CorpID: testCorpID, AgentID: "1", Secret: "top-secret-value",
		APIBaseURL: "http://127.0.0.1:1"}, newHTTPClient(), time.Now)
	_, err := c.accessToken(t.Context(), false)
	if err == nil || strings.Contains(err.Error(), "top-secret-value") {
		t.Fatalf("err = %v", err)
	}
}
