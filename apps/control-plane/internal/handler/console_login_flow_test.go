package handler

// W3 控制台登录安全：端到端登录流程测试（真库 + miniredis）。
//
// 本文件只用基线（3b8a624d）已有的导出面：Login / Logout / ChangeCurrentPassword、
// Dependencies 的既有字段、repository 既有构造函数。因此可以原样拷到基线树上跑，
// 作为“修前失败、修后通过”的负样本。
//
// 需要 CONSOLE_LOGIN_TEST_DATABASE_URL 指向已跑完全部迁移的一次性库。

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/auth"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
)

// consoleTestSystemRepo 内存版系统设置：登录安全参数按测试隔离，不污染共享库的 system_settings。
type consoleTestSystemRepo struct {
	mu     sync.Mutex
	values map[string]string
	audits []*repository.AuditOperation
}

func newConsoleTestSystemRepo() *consoleTestSystemRepo {
	return &consoleTestSystemRepo{values: map[string]string{}}
}

func (s *consoleTestSystemRepo) Get(_ context.Context, key string) (*repository.SystemSetting, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.values[key]
	if !ok {
		return nil, nil
	}
	return &repository.SystemSetting{Key: key, Value: v}, nil
}

func (s *consoleTestSystemRepo) GetAll(context.Context) ([]*repository.SystemSetting, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*repository.SystemSetting, 0, len(s.values))
	for k, v := range s.values {
		out = append(out, &repository.SystemSetting{Key: k, Value: v})
	}
	return out, nil
}

func (s *consoleTestSystemRepo) Set(_ context.Context, key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = value
	return nil
}

func (s *consoleTestSystemRepo) SetMultiple(_ context.Context, settings map[string]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range settings {
		s.values[k] = v
	}
	return nil
}

func (s *consoleTestSystemRepo) CreateAuditOperation(_ context.Context, op *repository.AuditOperation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audits = append(s.audits, op)
	return nil
}

func (s *consoleTestSystemRepo) ListAuditOperations(context.Context, int, int, string) ([]*repository.AuditOperation, int, error) {
	return nil, 0, nil
}

func (s *consoleTestSystemRepo) GetBool(_ context.Context, key string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.values[key] == "true", nil
}

type consoleLoginEnv struct {
	t        *testing.T
	pool     *pgxpool.Pool
	mr       *miniredis.Miniredis
	redis    *redis.Client
	sys      *consoleTestSystemRepo
	sessions *repository.SessionRepository
	deps     *Dependencies
	tenantID string
}

var consoleLoginSeq atomic.Int64

func newConsoleLoginEnv(t *testing.T) *consoleLoginEnv {
	t.Helper()
	databaseURL := os.Getenv("CONSOLE_LOGIN_TEST_DATABASE_URL")
	if databaseURL == "" {
		if os.Getenv("JJD_REQUIRE_CONSOLE_LOGIN_DB_TESTS") == "1" {
			t.Fatal("CONSOLE_LOGIN_TEST_DATABASE_URL is required when JJD_REQUIRE_CONSOLE_LOGIN_DB_TESTS=1")
		}
		t.Skip("CONSOLE_LOGIN_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	tenantID := fmt.Sprintf("tcl_%d_%d", time.Now().UnixNano(), consoleLoginSeq.Add(1))
	if _, err := pool.Exec(ctx, `INSERT INTO tenants (id, name, edition, status, is_test) VALUES ($1, $1, 'enterprise', 'active', TRUE)`, tenantID); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM user_login_history WHERE user_id IN (SELECT id FROM users WHERE tenant_id = $1)`, tenantID)
		_, _ = pool.Exec(c, `DELETE FROM user_login_history WHERE attempted_username LIKE $1`, tenantID+"%")
		_, _ = pool.Exec(c, `DELETE FROM users WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(c, `DELETE FROM tenants WHERE id = $1`, tenantID)
	})

	sys := newConsoleTestSystemRepo()
	sessions := repository.NewSessionRepository(client)
	deps := &Dependencies{
		RedisClient:            client,
		UserRepo:               repository.NewUserRepository(pool),
		UserIdentityLinkLookup: repository.NewUserIdentityLinkRepository(pool),
		SessionRepo:            sessions,
		SystemRepo:             sys,
		LoginHistoryRepo:       repository.NewUserLoginHistoryRepository(pool),
	}
	return &consoleLoginEnv{t: t, pool: pool, mr: mr, redis: client, sys: sys, sessions: sessions, deps: deps, tenantID: tenantID}
}

type consoleTestUser struct {
	ID       string
	Username string
	Password string
}

// createUser 插入一个控制台账号。password 为空表示未设置密码。
func (e *consoleLoginEnv) createUser(role, status, password string) consoleTestUser {
	e.t.Helper()
	n := consoleLoginSeq.Add(1)
	u := consoleTestUser{ID: fmt.Sprintf("%s_u%d", e.tenantID, n), Username: fmt.Sprintf("%s_user%d", e.tenantID, n), Password: password}
	hash := ""
	if password != "" {
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		if err != nil {
			e.t.Fatal(err)
		}
		hash = string(h)
	}
	if _, err := e.pool.Exec(context.Background(),
		`INSERT INTO users (id, tenant_id, username, email, password_hash, role, status) VALUES ($1, $2, $3, $4, NULLIF($5, ''), $6, $7)`,
		u.ID, e.tenantID, u.Username, u.ID+"@test.invalid", hash, role, status); err != nil {
		e.t.Fatalf("insert user: %v", err)
	}
	return u
}

func (e *consoleLoginEnv) login(username, password, ip string, extra map[string]string) *httptest.ResponseRecorder {
	e.t.Helper()
	captchaID := fmt.Sprintf("cap-%d", consoleLoginSeq.Add(1))
	if err := e.redis.Set(context.Background(), captchaRedisKey(captchaID), captchaDigest("ABCD"), time.Minute).Err(); err != nil {
		e.t.Fatal(err)
	}
	body := map[string]string{"username": username, "password": password, "captcha_id": captchaID, "captcha_code": "ABCD"}
	for k, v := range extra {
		body[k] = v
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/login", strings.NewReader(string(raw)))
	req.RemoteAddr = ip + ":40123"
	req.Header.Set("User-Agent", "w3-console-login-test")
	rec := httptest.NewRecorder()
	Login(e.deps).ServeHTTP(rec, req)
	return rec
}

type consoleErrorBody struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeConsoleError(t *testing.T, rec *httptest.ResponseRecorder) consoleErrorBody {
	t.Helper()
	var body consoleErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode error body %q: %v", rec.Body.String(), err)
	}
	return body
}

func loginToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Token == "" {
		t.Fatalf("login response without token: %s", rec.Body.String())
	}
	return body.Token
}

func (e *consoleLoginEnv) countHistory(where string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), `SELECT count(*) FROM user_login_history WHERE `+where, args...).Scan(&n); err != nil {
		e.t.Fatalf("count login history: %v", err)
	}
	return n
}

// 3.1：连续 5 次失败锁定；锁定期间正确密码也拒绝。
func TestConsoleLoginLocksAccountAfterRepeatedFailures(t *testing.T) {
	env := newConsoleLoginEnv(t)
	user := env.createUser("platform_admin", "active", "Correct-Horse-42")

	for i := 1; i <= 4; i++ {
		rec := env.login(user.Username, "wrong-password", "192.0.2.10", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}
	rec := env.login(user.Username, "wrong-password", "192.0.2.10", nil)
	if rec.Code != http.StatusLocked {
		t.Fatalf("5th failure must lock the account, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := decodeConsoleError(t, rec).Error.Code; got != "account_locked" {
		t.Fatalf("expected account_locked, got %q", got)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("locked response must carry Retry-After")
	}

	rec = env.login(user.Username, user.Password, "192.0.2.10", nil)
	if rec.Code != http.StatusLocked {
		t.Fatalf("correct password during lock must still be rejected, got %d: %s", rec.Code, rec.Body.String())
	}
	if n := env.countHistory(`user_id = $1 AND success = FALSE`, user.ID); n < 6 {
		t.Fatalf("expected every failed/locked attempt recorded, got %d rows", n)
	}
}

// 3.1：按账号维度计数，换来源 IP 不能绕过。
func TestConsoleLoginLockCountsAccountAcrossSourceIPs(t *testing.T) {
	env := newConsoleLoginEnv(t)
	user := env.createUser("platform_admin", "active", "Correct-Horse-42")
	var rec *httptest.ResponseRecorder
	for i := 1; i <= 5; i++ {
		rec = env.login(user.Username, "wrong-password", fmt.Sprintf("198.51.100.%d", i), nil)
	}
	if rec.Code != http.StatusLocked {
		t.Fatalf("distributed failures must lock the account, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec = env.login(user.Username, user.Password, "203.0.113.99", nil); rec.Code != http.StatusLocked {
		t.Fatalf("lock must apply to every source address, got %d", rec.Code)
	}
}

// 3.1：阈值与锁定时长来自系统设置；到期自动解锁。
func TestConsoleLoginLockoutFollowsSystemSettings(t *testing.T) {
	env := newConsoleLoginEnv(t)
	env.sys.values["console_login_lockout_threshold"] = "2"
	env.sys.values["console_login_lockout_minutes"] = "1"
	user := env.createUser("platform_admin", "active", "Correct-Horse-42")

	if rec := env.login(user.Username, "wrong", "192.0.2.20", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("first failure: expected 401, got %d", rec.Code)
	}
	if rec := env.login(user.Username, "wrong", "192.0.2.20", nil); rec.Code != http.StatusLocked {
		t.Fatalf("threshold=2 must lock on 2nd failure, got %d: %s", rec.Code, rec.Body.String())
	}
	env.mr.FastForward(61 * time.Second)
	if rec := env.login(user.Username, user.Password, "192.0.2.20", nil); rec.Code != http.StatusOK {
		t.Fatalf("lock must expire after configured minutes, got %d: %s", rec.Code, rec.Body.String())
	}
}

// 3.1：成功登录清零计数。
func TestConsoleLoginSuccessResetsFailureCounter(t *testing.T) {
	env := newConsoleLoginEnv(t)
	user := env.createUser("platform_admin", "active", "Correct-Horse-42")
	for i := 0; i < 4; i++ {
		env.login(user.Username, "wrong", "192.0.2.30", nil)
	}
	loginToken(t, env.login(user.Username, user.Password, "192.0.2.30", nil))
	for i := 1; i <= 4; i++ {
		if rec := env.login(user.Username, "wrong", "192.0.2.30", nil); rec.Code != http.StatusUnauthorized {
			t.Fatalf("counter must restart after success; attempt %d got %d", i, rec.Code)
		}
	}
}

// 3.6：不存在 / 未激活 / 无密码 / 密码错误对外完全一致。
func TestConsoleLoginFailuresUseGenericResponse(t *testing.T) {
	env := newConsoleLoginEnv(t)
	active := env.createUser("platform_admin", "active", "Correct-Horse-42")
	inactive := env.createUser("platform_admin", "disabled", "Correct-Horse-42")
	noPassword := env.createUser("platform_admin", "active", "")

	cases := map[string][2]string{
		"unknown_user":   {env.tenantID + "_nobody", "Correct-Horse-42"},
		"inactive_user":  {inactive.Username, "Correct-Horse-42"},
		"no_password":    {noPassword.Username, "Correct-Horse-42"},
		"wrong_password": {active.Username, "wrong"},
	}
	var reference string
	for name, c := range cases {
		rec := env.login(c[0], c[1], "192.0.2.40", nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d: %s", name, rec.Code, rec.Body.String())
		}
		body := decodeConsoleError(t, rec)
		got := body.Error.Code + "|" + body.Error.Message
		if reference == "" {
			reference = got
		}
		if got != reference || body.Error.Message != "invalid credentials" {
			t.Fatalf("%s: response %q differs from generic %q", name, got, reference)
		}
	}
}

// 3.2：成功、失败、不存在账号、登出全部落库。
func TestConsoleLoginRecordsHistoryForEveryOutcome(t *testing.T) {
	env := newConsoleLoginEnv(t)
	user := env.createUser("platform_admin", "active", "Correct-Horse-42")

	env.login(user.Username, "wrong", "192.0.2.50", nil)
	token := loginToken(t, env.login(user.Username, user.Password, "192.0.2.50", nil))
	unknown := env.tenantID + "_ghost"
	env.login(unknown, "whatever", "192.0.2.51", nil)

	if n := env.countHistory(`user_id = $1 AND success = TRUE AND ip = '192.0.2.50' AND user_agent = 'w3-console-login-test'`, user.ID); n != 1 {
		t.Fatalf("expected 1 success row with ip/ua, got %d", n)
	}
	if n := env.countHistory(`user_id = $1 AND success = FALSE AND COALESCE(failure_reason, '') <> ''`, user.ID); n != 1 {
		t.Fatalf("expected 1 failure row with reason, got %d", n)
	}
	if n := env.countHistory(`user_id IS NULL AND attempted_username = $1 AND success = FALSE`, unknown); n != 1 {
		t.Fatalf("expected unknown-account attempt recorded, got %d", n)
	}

	session, err := env.sessions.Get(context.Background(), token)
	if err != nil || session == nil {
		t.Fatalf("session missing after login: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/logout", nil)
	req.RemoteAddr = "192.0.2.50:40123"
	req = req.WithContext(context.WithValue(req.Context(), auth.SessionKey, session))
	rec := httptest.NewRecorder()
	Logout(env.deps).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if n := env.countHistory(`user_id = $1 AND event = 'logout'`, user.ID); n != 1 {
		t.Fatalf("expected logout recorded, got %d", n)
	}
}

// 3.4：空闲 30 分钟过期。
func TestConsoleLoginSessionExpiresWhenIdle(t *testing.T) {
	env := newConsoleLoginEnv(t)
	user := env.createUser("platform_admin", "active", "Correct-Horse-42")
	token := loginToken(t, env.login(user.Username, user.Password, "192.0.2.60", nil))
	if s, _ := env.sessions.Get(context.Background(), token); s == nil {
		t.Fatal("session must exist right after login")
	}
	env.mr.FastForward(31 * time.Minute)
	if s, _ := env.sessions.Get(context.Background(), token); s != nil {
		t.Fatal("session must expire after 30 idle minutes")
	}
}

// 3.4：并发会话上限，超出时踢掉最旧的会话。
func TestConsoleLoginLimitsConcurrentSessions(t *testing.T) {
	env := newConsoleLoginEnv(t)
	env.sys.values["console_session_max_concurrent"] = "2"
	user := env.createUser("platform_admin", "active", "Correct-Horse-42")
	first := loginToken(t, env.login(user.Username, user.Password, "192.0.2.70", nil))
	second := loginToken(t, env.login(user.Username, user.Password, "192.0.2.70", nil))
	third := loginToken(t, env.login(user.Username, user.Password, "192.0.2.70", nil))
	ctx := context.Background()
	if s, _ := env.sessions.Get(ctx, first); s != nil {
		t.Fatal("oldest session must be evicted when the limit is exceeded")
	}
	for _, token := range []string{second, third} {
		if s, _ := env.sessions.Get(ctx, token); s == nil {
			t.Fatalf("recent session %s must survive", token)
		}
	}
}

// 3.7：管理员账号来源 IP 白名单；普通账号不受影响。
func TestConsoleLoginEnforcesAdminIPAllowlist(t *testing.T) {
	env := newConsoleLoginEnv(t)
	env.sys.values["console_admin_ip_allowlist"] = "10.0.0.0/8, 192.0.2.99"
	admin := env.createUser("platform_admin", "active", "Correct-Horse-42")
	employeeEnv, member, _ := chatLoginFixture(t)
	employeeEnv.sys.values["console_admin_ip_allowlist"] = env.sys.values["console_admin_ip_allowlist"]

	rec := env.login(admin.Username, admin.Password, "203.0.113.5", nil)
	if rec.Code != http.StatusForbidden || decodeConsoleError(t, rec).Error.Code != "login_ip_not_allowed" {
		t.Fatalf("admin from outside allowlist must be rejected, got %d: %s", rec.Code, rec.Body.String())
	}
	loginToken(t, env.login(admin.Username, admin.Password, "10.20.30.40", nil))
	loginToken(t, env.login(admin.Username, admin.Password, "192.0.2.99", nil))
	if got := employeeEnv.employeeLogin(member.Username, member.Password, "203.0.113.5", nil); got.Code != http.StatusOK {
		t.Fatalf("employee outside admin allowlist status=%d", got.Code)
	}
}

func changeOwnPassword(env *consoleLoginEnv, user consoleTestUser, current, next string) *httptest.ResponseRecorder {
	env.t.Helper()
	dbUser, err := env.deps.UserRepo.GetByID(context.Background(), user.ID)
	if err != nil || dbUser == nil {
		env.t.Fatalf("load user: %v", err)
	}
	raw, _ := json.Marshal(map[string]string{"current_password": current, "new_password": next})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/me/change-password", strings.NewReader(string(raw)))
	req = req.WithContext(context.WithValue(req.Context(), auth.UserKey, dbUser))
	rec := httptest.NewRecorder()
	ChangeCurrentPassword(env.deps).ServeHTTP(rec, req)
	return rec
}

// 3.3：≥12 位、三类字符、不含用户名。
func TestChangePasswordEnforcesComplexity(t *testing.T) {
	env := newConsoleLoginEnv(t)
	user := env.createUser("platform_admin", "active", "Correct-Horse-42")
	weak := map[string]string{
		"Sh0rt-pass":                            "password_too_short",
		"alllowercaseletters":                   "password_too_few_classes",
		"ALLUPPER123456":                        "password_too_few_classes",
		"Xy9-" + strings.ToUpper(user.Username): "password_contains_username",
	}
	for pw, code := range weak {
		rec := changeOwnPassword(env, user, user.Password, pw)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("weak password %q must be rejected, got %d: %s", pw, rec.Code, rec.Body.String())
		}
		if got := decodeConsoleError(t, rec).Error.Code; got != code {
			t.Fatalf("password %q: expected %s, got %s", pw, code, got)
		}
	}
	if rec := changeOwnPassword(env, user, user.Password, "Brand-New-Pass-77"); rec.Code != http.StatusOK {
		t.Fatalf("strong password must be accepted, got %d: %s", rec.Code, rec.Body.String())
	}
}

func (s *consoleTestSystemRepo) GetByKeys(ctx context.Context, keys []string) ([]*repository.SystemSetting, error) {
	return systemSettingsByKeysVia(ctx, s.Get, keys)
}
