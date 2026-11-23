package consolesso

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// fakeIdP 是进程内的 OIDC 提供方：JWKS + token 端点（校验 PKCE 与 client 凭据）。
type fakeIdP struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	kid    string
	issuer string

	mu          sync.Mutex
	challenge   string
	nonce       string
	claims      func(map[string]any) // 签发前改写 claims
	header      map[string]any       // 非空时替换 JWS 头
	jwksHits    int
	tokenStatus int
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, key: key, kid: "k1", tokenStatus: http.StatusOK}
	mux := http.NewServeMux()
	mux.HandleFunc("/certs", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		f.jwksHits++
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{jwk(f.kid, &key.PublicKey)}})
	})
	mux.HandleFunc("/token", f.token)
	f.srv = httptest.NewServer(mux)
	f.issuer = f.srv.URL + "/realms/jjdguard"
	t.Cleanup(f.srv.Close)
	return f
}

func jwk(kid string, pub *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func (f *fakeIdP) config() Config {
	return Config{
		Issuer: f.issuer, AuthorizeURL: f.issuer + "/protocol/openid-connect/auth",
		TokenURL: f.srv.URL + "/token", JWKSURL: f.srv.URL + "/certs",
		ClientID: "jjdguard-console", ClientSecret: "console-secret",
		RedirectURL: "http://console.test/admin/v1/auth/sso/callback", LoginPagePath: "/login",
	}
}

// rememberAuthorize 模拟浏览器到达 IdP：记下 PKCE challenge 与 nonce。
func (f *fakeIdP) rememberAuthorize(authorizeURL string) {
	u, err := url.Parse(authorizeURL)
	if err != nil {
		f.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "jjdguard-console" {
		f.t.Fatalf("bad authorize request: %s", authorizeURL)
	}
	f.mu.Lock()
	f.challenge, f.nonce = q.Get("code_challenge"), q.Get("nonce")
	f.mu.Unlock()
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	user, pass, ok := r.BasicAuth()
	if !ok || user != "jjdguard-console" || pass != "console-secret" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	_ = r.ParseForm()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if base64.RawURLEncoding.EncodeToString(sum[:]) != f.challenge || r.PostForm.Get("code") != "good-code" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if f.tokenStatus != http.StatusOK {
		w.WriteHeader(f.tokenStatus)
		return
	}
	now := time.Now()
	claims := map[string]any{
		"iss": f.issuer, "sub": "kc-sub-1", "aud": "jjdguard-console", "azp": "jjdguard-console",
		"exp": now.Add(5 * time.Minute).Unix(), "iat": now.Unix(), "nonce": f.nonce,
		"sid": "sid-1", "preferred_username": "alice",
	}
	if f.claims != nil {
		f.claims(claims)
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"id_token": f.sign(claims), "token_type": "Bearer"})
}

func (f *fakeIdP) sign(claims map[string]any) string {
	header := f.header
	if header == nil {
		header = map[string]any{"alg": "RS256", "kid": f.kid, "typ": "JWT"}
	}
	return signWith(f.t, f.key, header, claims)
}

func signWith(t *testing.T, key *rsa.PrivateKey, header, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(header)
	c, _ := json.Marshal(claims)
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type fakeSubjects struct{ links map[string][2]string }

func (s fakeSubjects) ResolveConsoleSubject(_ context.Context, issuer, subject string) (string, string, error) {
	v, ok := s.links[issuer+"|"+subject]
	if !ok {
		return "", "", errAccountNotLinked
	}
	return v[0], v[1], nil
}

type fakeAccounts struct {
	mu       sync.Mutex
	accounts map[string]*Account
}

func (a *fakeAccounts) Account(_ context.Context, id string) (*Account, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if v, ok := a.accounts[id]; ok {
		cp := *v
		return &cp, nil
	}
	return nil, nil
}

func (a *fakeAccounts) set(id string, fn func(*Account)) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fn(a.accounts[id])
}

type fakeSessions struct {
	created []Account
	opts    []SessionOptions
	result  SessionResult // 非零时作为返回的时长
}

func (s *fakeSessions) CreateSession(_ context.Context, a Account, opts SessionOptions) (SessionResult, error) {
	s.created = append(s.created, a)
	s.opts = append(s.opts, opts)
	res := s.result
	res.ID = "sess-" + a.ID
	return res, nil
}

// allowAllPolicy 让既有的流程测试不被登录加固干扰；加固本身在 service_hardening_test.go 里单独测。
type allowAllPolicy struct{}

func (allowAllPolicy) Authorize(context.Context, *http.Request, Account, string) (Decision, error) {
	return Decision{Outcome: OutcomeAllow}, nil
}

type harness struct {
	idp      *fakeIdP
	svc      *Service
	accounts *fakeAccounts
	sessions *fakeSessions
}

func newHarness(t *testing.T, role string) *harness {
	t.Helper()
	idp := newFakeIdP(t)
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	accounts := &fakeAccounts{accounts: map[string]*Account{
		"u1": {ID: "u1", TenantID: "t1", Username: "alice", Role: role, Status: "active"},
	}}
	sessions := &fakeSessions{}
	subjects := fakeSubjects{links: map[string][2]string{idp.issuer + "|kc-sub-1": {"t1", "u1"}}}
	svc := New(idp.config(), rc, subjects, accounts, sessions).WithSessionPolicy(allowAllPolicy{})
	if !svc.Enabled() {
		t.Fatal("service not enabled")
	}
	return &harness{idp: idp, svc: svc, accounts: accounts, sessions: sessions}
}

// startLogin 走 /login，返回 state 与浏览器绑定 cookie。
func (h *harness) startLogin(t *testing.T) (string, *http.Cookie) {
	t.Helper()
	w := httptest.NewRecorder()
	h.svc.Login(w, httptest.NewRequest(http.MethodGet, LoginPath, nil))
	if w.Code != http.StatusFound {
		t.Fatalf("login status %d", w.Code)
	}
	loc := w.Header().Get("Location")
	h.idp.rememberAuthorize(loc)
	u, _ := url.Parse(loc)
	var binding *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == bindingCookie {
			binding = c
		}
	}
	if binding == nil || !binding.HttpOnly || binding.Path != bindingPath {
		t.Fatalf("binding cookie missing or weak: %+v", binding)
	}
	return u.Query().Get("state"), binding
}

func (h *harness) callback(state, code string, binding *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/admin/v1/auth/sso/callback?"+
		url.Values{"state": {state}, "code": {code}}.Encode(), nil)
	if binding != nil {
		req.AddCookie(binding)
	}
	w := httptest.NewRecorder()
	h.svc.Callback(w, req)
	return w
}
