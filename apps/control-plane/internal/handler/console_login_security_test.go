package handler

// W3 控制台登录安全：依赖 W3 新增接口的测试（密码历史、定期改密、TOTP、登录安全设置、门户基线）。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/portalbaseline"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

func (e *consoleLoginEnv) withConsoleSecurity() *repository.ConsoleUserSecurityRepository {
	repo := repository.NewConsoleUserSecurityRepository(e.pool)
	e.deps.ConsoleSecurity = repo
	return repo
}

func withActor(req *http.Request, user *repository.User, session *repository.Session) *http.Request {
	ctx := context.WithValue(req.Context(), auth.UserKey, user)
	if session != nil {
		ctx = context.WithValue(ctx, auth.SessionKey, session)
	}
	return req.WithContext(ctx)
}

// 3.3：不与最近 5 次相同（当前密码算其中一次）。
func TestChangePasswordRejectsRecentPasswords(t *testing.T) {
	env := newConsoleLoginEnv(t)
	env.withConsoleSecurity()
	user := env.createUser("platform_admin", "active", "History-Pass-00")
	passwords := []string{"History-Pass-00", "History-Pass-01", "History-Pass-02", "History-Pass-03", "History-Pass-04"}
	for i := 1; i < len(passwords); i++ {
		if rec := changeOwnPassword(env, user, passwords[i-1], passwords[i]); rec.Code != http.StatusOK {
			t.Fatalf("rotation %d: %d %s", i, rec.Code, rec.Body.String())
		}
	}
	// 当前是 04；00..03 都在最近 5 次之内。
	for _, old := range passwords[:4] {
		rec := changeOwnPassword(env, user, passwords[4], old)
		if rec.Code != http.StatusBadRequest || decodeConsoleError(t, rec).Error.Code != "password_reused" {
			t.Fatalf("reusing %q must be rejected, got %d: %s", old, rec.Code, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), `"history_count":5`) {
			t.Fatalf("policy error must carry the configured rule values: %s", rec.Body.String())
		}
	}
	if rec := changeOwnPassword(env, user, passwords[4], "History-Pass-05"); rec.Code != http.StatusOK {
		t.Fatalf("rotation 5: %d %s", rec.Code, rec.Body.String())
	}
	// 当前 05，最近 5 次为 05..01；00 已滑出窗口，可以再用。
	if rec := changeOwnPassword(env, user, "History-Pass-05", passwords[0]); rec.Code != http.StatusOK {
		t.Fatalf("password older than the history window must be allowed, got %d: %s", rec.Code, rec.Body.String())
	}
	var kept int
	if err := env.pool.QueryRow(context.Background(), `SELECT count(*) FROM user_password_history WHERE user_id = $1`, user.ID).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if kept > 5 {
		t.Fatalf("password history must be trimmed to the configured count, got %d rows", kept)
	}
}

// 3.3：超过 90 天未改密，登录后强制改密。
func TestConsoleLoginForcesChangeWhenPasswordExpired(t *testing.T) {
	env := newConsoleLoginEnv(t)
	env.withConsoleSecurity()
	user := env.createUser("platform_admin", "active", "Correct-Horse-42")
	if _, err := env.pool.Exec(context.Background(), `UPDATE users SET password_changed_at = NOW() - INTERVAL '91 days' WHERE id = $1`, user.ID); err != nil {
		t.Fatal(err)
	}
	rec := env.login(user.Username, user.Password, "192.0.2.80", nil)
	loginToken(t, rec)
	var body struct {
		PasswordChangeRequired bool `json:"password_change_required"`
		PasswordExpired        bool `json:"password_expired"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if !body.PasswordChangeRequired || !body.PasswordExpired {
		t.Fatalf("expired password must force a change: %s", rec.Body.String())
	}
	dbUser, _ := env.deps.UserRepo.GetByID(context.Background(), user.ID)
	if dbUser == nil || !dbUser.MustChangePassword {
		t.Fatal("must_change_password must be persisted so the middleware restricts the session")
	}

	// 改密后计时重置，再登录不再要求改密。
	if rec := changeOwnPassword(env, user, user.Password, "Rotated-Horse-43"); rec.Code != http.StatusOK {
		t.Fatalf("change password: %d %s", rec.Code, rec.Body.String())
	}
	rec = env.login(user.Username, "Rotated-Horse-43", "192.0.2.80", nil)
	loginToken(t, rec)
	body.PasswordChangeRequired, body.PasswordExpired = false, false
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if body.PasswordChangeRequired || body.PasswordExpired {
		t.Fatalf("fresh password must not be treated as expired: %s", rec.Body.String())
	}
}

func setupTOTPForUser(t *testing.T, env *consoleLoginEnv, user consoleTestUser) string {
	t.Helper()
	setupIdentitySecretKey(t)
	secret, err := generateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	enc, err := encryptTOTPSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.deps.ConsoleSecurity.SetTOTP(context.Background(), user.ID, enc, true); err != nil {
		t.Fatal(err)
	}
	return secret
}

// 3.5：已绑定 TOTP 的账号必须提供正确验证码；错码计入锁定；同一验证码不能重放。
func TestConsoleLoginRequiresTOTPWhenEnabled(t *testing.T) {
	env := newConsoleLoginEnv(t)
	env.withConsoleSecurity()
	user := env.createUser("platform_admin", "active", "Correct-Horse-42")
	secret := setupTOTPForUser(t, env, user)

	rec := env.login(user.Username, user.Password, "192.0.2.90", nil)
	if rec.Code != http.StatusUnauthorized || decodeConsoleError(t, rec).Error.Code != "totp_required" {
		t.Fatalf("missing code must return totp_required, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = env.login(user.Username, user.Password, "192.0.2.90", map[string]string{"totp_code": "000000"})
	if rec.Code != http.StatusUnauthorized || decodeConsoleError(t, rec).Error.Code != "unauthorized" {
		t.Fatalf("wrong code must fail generically, got %d: %s", rec.Code, rec.Body.String())
	}
	code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
	loginToken(t, env.login(user.Username, user.Password, "192.0.2.90", map[string]string{"totp_code": code}))
	rec = env.login(user.Username, user.Password, "192.0.2.90", map[string]string{"totp_code": code})
	if rec.Code == http.StatusOK {
		t.Fatal("the same TOTP code must not be accepted twice")
	}
}

// 3.5：要求管理员启用双因素但尚未绑定时，只签发绑定专用会话；绑定后解除限制。
func TestConsoleLoginIssuesEnrollmentOnlySessionWhenAdminTOTPRequired(t *testing.T) {
	env := newConsoleLoginEnv(t)
	env.withConsoleSecurity()
	setupIdentitySecretKey(t)
	env.sys.values["console_admin_totp_required"] = "true"
	user := env.createUser("platform_admin", "active", "Correct-Horse-42")

	rec := env.login(user.Username, user.Password, "192.0.2.91", nil)
	token := loginToken(t, rec)
	if !strings.Contains(rec.Body.String(), `"totp_setup_required":true`) {
		t.Fatalf("login must signal enrollment: %s", rec.Body.String())
	}
	session, _ := env.sessions.Get(context.Background(), token)
	if session == nil || !session.TOTPSetupPending {
		t.Fatal("session must be enrollment-only")
	}
	dbUser, _ := env.deps.UserRepo.GetByID(context.Background(), user.ID)

	setupRec := httptest.NewRecorder()
	SetupMyTOTP(env.deps).ServeHTTP(setupRec, withActor(httptest.NewRequest(http.MethodPost, "/admin/v1/me/totp/setup", nil), dbUser, session))
	if setupRec.Code != http.StatusOK || setupRec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("setup: %d %s", setupRec.Code, setupRec.Body.String())
	}
	var setup struct {
		Secret     string `json:"secret"`
		OtpauthURI string `json:"otpauth_uri"`
	}
	_ = json.Unmarshal(setupRec.Body.Bytes(), &setup)
	if setup.Secret == "" || !strings.HasPrefix(setup.OtpauthURI, "otpauth://totp/") {
		t.Fatalf("setup response incomplete: %s", setupRec.Body.String())
	}
	code, _ := totpCodeAt(setup.Secret, uint64(time.Now().Unix()/totpPeriod))
	enableRec := httptest.NewRecorder()
	EnableMyTOTP(env.deps).ServeHTTP(enableRec, withActor(httptest.NewRequest(http.MethodPost, "/admin/v1/me/totp/enable", strings.NewReader(`{"code":"`+code+`"}`)), dbUser, session))
	if enableRec.Code != http.StatusOK {
		t.Fatalf("enable: %d %s", enableRec.Code, enableRec.Body.String())
	}
	session, _ = env.sessions.Get(context.Background(), token)
	if session == nil || session.TOTPSetupPending {
		t.Fatal("enrollment restriction must be lifted after enabling TOTP")
	}
	sec, _ := env.deps.ConsoleSecurity.Get(context.Background(), user.ID)
	if !sec.TOTPEnabled {
		t.Fatal("TOTP must be enabled in the database")
	}
}

// 管理员解锁与重置双因素。
func TestConsoleAdminCanUnlockAndResetTOTP(t *testing.T) {
	env := newConsoleLoginEnv(t)
	env.withConsoleSecurity()
	admin := env.createUser("platform_admin", "active", "Correct-Horse-42")
	target := env.createUser("tenant_admin", "active", "Target-Horse-42")
	setupTOTPForUser(t, env, target)
	for i := 0; i < 5; i++ {
		env.login(target.Username, "wrong", "192.0.2.92", nil)
	}
	if rec := env.login(target.Username, target.Password, "192.0.2.92", nil); rec.Code != http.StatusLocked {
		t.Fatalf("precondition: target must be locked, got %d", rec.Code)
	}
	adminUser, _ := env.deps.UserRepo.GetByID(context.Background(), admin.ID)
	route := func(h http.HandlerFunc, path string) *httptest.ResponseRecorder {
		rctx := chi.NewRouteContext()
		rctx.URLParams.Add("id", target.ID)
		req := httptest.NewRequest(http.MethodPost, path, nil)
		req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, withActor(req, adminUser, nil))
		return rec
	}
	if rec := route(UnlockUserLogin(env.deps), "/admin/v1/users/x/unlock-login"); rec.Code != http.StatusOK {
		t.Fatalf("unlock: %d %s", rec.Code, rec.Body.String())
	}
	if rec := route(ResetUserTOTP(env.deps), "/admin/v1/users/x/reset-totp"); rec.Code != http.StatusOK {
		t.Fatalf("reset totp: %d %s", rec.Code, rec.Body.String())
	}
	loginToken(t, env.login(target.Username, target.Password, "192.0.2.92", nil))
	if len(env.sys.audits) < 2 {
		t.Fatalf("admin actions must be audited, got %d", len(env.sys.audits))
	}
}

// 登录安全设置：范围校验、空闲 ≤ 绝对、白名单防自锁、写入后立即生效。
func TestUpdateConsoleLoginSecurityValidatesInput(t *testing.T) {
	sys := newConsoleTestSystemRepo()
	deps := &Dependencies{SystemRepo: sys}
	admin := &repository.User{ID: "u-admin", Role: "platform_admin", Status: "active"}
	valid := settingsFromPolicy(DefaultConsoleLoginPolicy())
	put := func(mut func(*consoleLoginSecuritySettings), user *repository.User, ip string) *httptest.ResponseRecorder {
		in := valid
		if mut != nil {
			mut(&in)
		}
		raw, _ := json.Marshal(in)
		req := httptest.NewRequest(http.MethodPut, "/admin/v1/system/login-security", strings.NewReader(string(raw)))
		req.RemoteAddr = ip + ":5555"
		rec := httptest.NewRecorder()
		UpdateConsoleLoginSecurity(deps).ServeHTTP(rec, withActor(req, user, nil))
		return rec
	}
	bad := map[string]func(*consoleLoginSecuritySettings){
		"threshold_zero":   func(s *consoleLoginSecuritySettings) { s.LockoutThreshold = 0 },
		"short_password":   func(s *consoleLoginSecuritySettings) { s.PasswordMinLength = 6 },
		"idle_over_abs":    func(s *consoleLoginSecuritySettings) { s.SessionIdleMinutes = 120; s.SessionAbsoluteHours = 1 },
		"invalid_cidr":     func(s *consoleLoginSecuritySettings) { s.AdminIPAllowlist = "10.0.0.0/33" },
		"excludes_current": func(s *consoleLoginSecuritySettings) { s.AdminIPAllowlist = "10.0.0.0/8" },
	}
	for name, mut := range bad {
		if rec := put(mut, admin, "192.0.2.1"); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: expected 400, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec := put(nil, &repository.User{ID: "u-t", Role: "tenant_admin"}, "192.0.2.1"); rec.Code != http.StatusForbidden {
		t.Fatalf("non platform admin must be rejected, got %d", rec.Code)
	}
	rec := put(func(s *consoleLoginSecuritySettings) {
		s.LockoutThreshold = 3
		s.AdminIPAllowlist = "192.0.2.0/24"
		s.AdminTOTPRequired = true
	}, admin, "192.0.2.1")
	if rec.Code != http.StatusOK {
		t.Fatalf("valid update: %d %s", rec.Code, rec.Body.String())
	}
	p := LoadConsoleLoginPolicy(context.Background(), sys)
	if p.LockoutThreshold != 3 || !p.AdminTOTPRequired || len(p.AdminIPAllowlist) != 1 {
		t.Fatalf("settings not applied: %+v", p)
	}
	if len(sys.audits) != 1 {
		t.Fatalf("settings change must be audited, got %d", len(sys.audits))
	}
}

// 读取时非法值回退默认，防止误配置把控制台锁死或放开。
func TestLoadConsoleLoginPolicyFallsBackOnInvalidValues(t *testing.T) {
	sys := newConsoleTestSystemRepo()
	sys.values[settingLockoutThreshold] = "0"
	sys.values[settingPasswordMinLength] = "abc"
	sys.values[settingSessionIdleMinutes] = "15"
	p := LoadConsoleLoginPolicy(context.Background(), sys)
	d := DefaultConsoleLoginPolicy()
	if p.LockoutThreshold != d.LockoutThreshold || p.PasswordMinLength != d.PasswordMinLength {
		t.Fatalf("invalid values must fall back to defaults: %+v", p)
	}
	if p.SessionIdleMinutes != 15 {
		t.Fatalf("valid override ignored: %+v", p)
	}
}

// RFC 6238 附录 B 的 SHA1 测试向量（取 6 位）。
func TestTOTPMatchesRFC6238Vectors(t *testing.T) {
	secret := totpEncoding.EncodeToString([]byte("12345678901234567890"))
	vectors := map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471", 1234567890: "005924", 2000000000: "279037"}
	for ts, want := range vectors {
		got, err := totpCodeAt(secret, uint64(ts/totpPeriod))
		if err != nil || got != want {
			t.Fatalf("t=%d: got %s want %s (%v)", ts, got, want, err)
		}
		if _, ok := verifyTOTP(secret, want, time.Unix(ts, 0)); !ok {
			t.Fatalf("t=%d: verify failed", ts)
		}
	}
	if _, ok := verifyTOTP(secret, "287082", time.Unix(59+3*totpPeriod, 0)); ok {
		t.Fatal("codes outside the skew window must be rejected")
	}
}

func TestIPAllowedMatchesCIDRAndSingleAddress(t *testing.T) {
	list := []string{"10.0.0.0/8", "192.0.2.7", "2001:db8::/32"}
	for ip, want := range map[string]bool{"10.1.2.3": true, "192.0.2.7": true, "192.0.2.8": false, "2001:db8::1": true, "not-an-ip": false} {
		if got := ipAllowed(list, ip); got != want {
			t.Fatalf("%s: got %v want %v", ip, got, want)
		}
	}
	if !ipAllowed(nil, "203.0.113.1") {
		t.Fatal("empty allowlist must not restrict")
	}
}

type fakePortalFetcher struct {
	realm map[string]any
	err   error
}

func (f fakePortalFetcher) FetchRealm(context.Context) (map[string]any, error) { return f.realm, f.err }

// 3.8：控制台只读检查门户基线。
func TestGetPortalLoginBaselineReportsStatus(t *testing.T) {
	admin := &repository.User{ID: "u", Role: "platform_admin", Status: "active"}
	call := func(f portalbaseline.Fetcher) portalbaseline.Report {
		rec := httptest.NewRecorder()
		GetPortalLoginBaseline(&Dependencies{PortalBaselineFetcher: f}).ServeHTTP(rec, withActor(httptest.NewRequest(http.MethodGet, "/admin/v1/system/portal-login-baseline", nil), admin, nil))
		var report portalbaseline.Report
		if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
			t.Fatalf("decode: %v %s", err, rec.Body.String())
		}
		return report
	}
	if r := call(nil); r.Status != "unavailable" {
		t.Fatalf("no fetcher: %+v", r)
	}
	if r := call(fakePortalFetcher{err: errors.New("down")}); r.Status != "unavailable" {
		t.Fatalf("fetch error: %+v", r)
	}
	legacy := map[string]any{"sslRequired": "none", "bruteForceProtected": true}
	if r := call(fakePortalFetcher{realm: legacy}); r.Status != "not_compliant" || r.ApplyHint == "" {
		t.Fatalf("legacy realm: %+v", r)
	}
	compliant := map[string]any{}
	for k, v := range portalbaseline.Target {
		compliant[k] = v
	}
	if r := call(fakePortalFetcher{realm: compliant}); r.Status != "compliant" {
		t.Fatalf("compliant realm: %+v", r)
	}
}
