package handler

// SoD 项：三员（security_officer、auditor）按三员分立设计本就是控制台角色，必须能登录控制台。
// 942eecff9 把登录边界收窄成只剩管理员角色，三员有菜单、路由、seed 权限、SoD 类别却登录不进来。
// 放开登录必须同时证明：验证码、锁定、强制改密、IP 白名单、强制 TOTP、会话签发对新放行的角色同样生效，
// 没有出现任何更弱的登录路径；员工/业务角色仍然登录不了。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity/consolesso"
)

// loginWithCaptcha 用指定的验证码标识与答案登录（不预置有效验证码），用来验证验证码校验不可绕过。
func (e *consoleLoginEnv) loginWithCaptcha(username, password, ip, captchaID, captchaCode string) *httptest.ResponseRecorder {
	e.t.Helper()
	raw, _ := json.Marshal(map[string]string{"username": username, "password": password, "captcha_id": captchaID, "captcha_code": captchaCode})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/login", strings.NewReader(string(raw)))
	req.RemoteAddr = ip + ":40123"
	rec := httptest.NewRecorder()
	Login(e.deps).ServeHTTP(rec, req)
	return rec
}

var threeOfficers = []string{"security_officer", "auditor"}

func TestThreeOfficersCanSignInToTheConsole(t *testing.T) {
	for _, role := range threeOfficers {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			user := env.createUser(role, "active", "Correct-Horse-42")
			rec := env.login(user.Username, user.Password, "192.0.2.10", nil)
			token := loginToken(t, rec)
			if !strings.Contains(rec.Body.String(), `"role":"`+role+`"`) {
				t.Fatalf("登录响应应带真实角色 %s: %s", role, rec.Body.String())
			}
			session, _ := env.sessions.Get(context.Background(), token)
			if session == nil || session.Role != role || session.TOTPSetupPending {
				t.Fatalf("应签发该角色的正常控制台会话: %+v", session)
			}
		})
	}
}

// 员工/业务角色仍然登录不了控制台，且不签发任何会话（与 942eecff9 的隔离目标一致）。
func TestNonConsoleRolesStillCannotSignInToTheConsole(t *testing.T) {
	for _, role := range []string{"chat_user", "developer", "viewer", "dept_manager", "operator", "platform_connector"} {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			user := env.createUser(role, "active", "Correct-Horse-42")
			rec := env.login(user.Username, user.Password, "192.0.2.10", nil)
			if rec.Code != http.StatusForbidden || decodeConsoleError(t, rec).Error.Code != "console_role_required" {
				t.Fatalf("%s 必须 403 console_role_required: %d %s", role, rec.Code, rec.Body.String())
			}
			keys, err := env.redis.Keys(context.Background(), "session:*").Result()
			if err != nil || len(keys) != 0 {
				t.Fatalf("被拒绝的角色不得产生会话: %d %v", len(keys), err)
			}
		})
	}
}

// 失败锁定对三员同样生效。
func TestThreeOfficersAreSubjectToLoginLockout(t *testing.T) {
	for _, role := range threeOfficers {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			user := env.createUser(role, "active", "Correct-Horse-42")
			for i := 1; i <= 4; i++ {
				if rec := env.login(user.Username, "wrong-password", "192.0.2.20", nil); rec.Code != http.StatusUnauthorized {
					t.Fatalf("第 %d 次错误应 401: %d", i, rec.Code)
				}
			}
			if rec := env.login(user.Username, "wrong-password", "192.0.2.20", nil); rec.Code != http.StatusLocked {
				t.Fatalf("第 5 次错误应锁定: %d", rec.Code)
			}
			if rec := env.login(user.Username, user.Password, "192.0.2.20", nil); rec.Code != http.StatusLocked {
				t.Fatalf("锁定期间即使密码正确也必须拒绝: %d", rec.Code)
			}
		})
	}
}

// 验证码对三员同样生效：缺失或错误的验证码在认证之前就被拒绝，不签发会话。
func TestThreeOfficersCannotBypassTheCaptcha(t *testing.T) {
	for _, role := range threeOfficers {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			user := env.createUser(role, "active", "Correct-Horse-42")
			rec := env.loginWithCaptcha(user.Username, user.Password, "192.0.2.21", "no-such-captcha", "ABCD")
			if rec.Code == http.StatusOK {
				t.Fatalf("无效验证码不得登录成功: %s", rec.Body.String())
			}
			rec = env.loginWithCaptcha(user.Username, user.Password, "192.0.2.21", "", "")
			if rec.Code == http.StatusOK {
				t.Fatalf("缺失验证码不得登录成功: %s", rec.Body.String())
			}
			keys, _ := env.redis.Keys(context.Background(), "session:*").Result()
			if len(keys) != 0 {
				t.Fatalf("验证码失败不得产生会话: %d", len(keys))
			}
		})
	}
}

// 管理员来源 IP 白名单对三员同样生效。
func TestThreeOfficersAreSubjectToTheAdminIPAllowlist(t *testing.T) {
	for _, role := range threeOfficers {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			env.sys.values["console_admin_ip_allowlist"] = "10.0.0.0/8"
			user := env.createUser(role, "active", "Correct-Horse-42")
			rec := env.login(user.Username, user.Password, "203.0.113.5", nil)
			if rec.Code != http.StatusForbidden || decodeConsoleError(t, rec).Error.Code != "login_ip_not_allowed" {
				t.Fatalf("白名单之外必须拒绝: %d %s", rec.Code, rec.Body.String())
			}
			loginToken(t, env.login(user.Username, user.Password, "10.20.30.40", nil))
		})
	}
}

// 强制 TOTP：策略要求管理员启用双因素时，三员只拿到「绑定专用」会话；绑定前其他接口一律受限。
func TestThreeOfficersGetEnrollmentOnlySessionWhenTOTPIsRequired(t *testing.T) {
	for _, role := range threeOfficers {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			env.withConsoleSecurity()
			setupIdentitySecretKey(t)
			env.sys.values["console_admin_totp_required"] = "true"
			user := env.createUser(role, "active", "Correct-Horse-42")
			rec := env.login(user.Username, user.Password, "192.0.2.22", nil)
			token := loginToken(t, rec)
			if !strings.Contains(rec.Body.String(), `"totp_setup_required":true`) {
				t.Fatalf("必须提示绑定双因素: %s", rec.Body.String())
			}
			session, _ := env.sessions.Get(context.Background(), token)
			if session == nil || !session.TOTPSetupPending {
				t.Fatalf("三员必须只拿绑定专用会话，不能绕过强制 TOTP: %+v", session)
			}
		})
	}
}

// 已绑定 TOTP 的三员：缺码返回 totp_required，错码拒绝，正确码通过且同一码不能复用。
func TestThreeOfficersMustPassTOTPWhenEnabled(t *testing.T) {
	for _, role := range threeOfficers {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			env.withConsoleSecurity()
			user := env.createUser(role, "active", "Correct-Horse-42")
			secret := setupTOTPForUser(t, env, user)
			if rec := env.login(user.Username, user.Password, "192.0.2.23", nil); rec.Code != http.StatusUnauthorized || decodeConsoleError(t, rec).Error.Code != "totp_required" {
				t.Fatalf("缺码应 totp_required: %d %s", rec.Code, rec.Body.String())
			}
			if rec := env.login(user.Username, user.Password, "192.0.2.23", map[string]string{"totp_code": "000000"}); rec.Code == http.StatusOK {
				t.Fatal("错误的 TOTP 不得通过")
			}
			code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
			loginToken(t, env.login(user.Username, user.Password, "192.0.2.23", map[string]string{"totp_code": code}))
			if rec := env.login(user.Username, user.Password, "192.0.2.23", map[string]string{"totp_code": code}); rec.Code == http.StatusOK {
				t.Fatal("同一 TOTP 码不得复用（防重放）")
			}
		})
	}
}

// 强制改密：must_change_password 的三员登录后会话被限制在改密接口，中间件拦截其他接口。
func TestThreeOfficersMustChangePasswordBeforeAnythingElse(t *testing.T) {
	for _, role := range threeOfficers {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			user := env.createUser(role, "active", "Correct-Horse-42")
			if _, err := env.pool.Exec(context.Background(), "UPDATE users SET must_change_password=TRUE WHERE id=$1", user.ID); err != nil {
				t.Fatal(err)
			}
			rec := env.login(user.Username, user.Password, "192.0.2.24", nil)
			loginToken(t, rec)
			if !strings.Contains(rec.Body.String(), `"password_change_required":true`) {
				t.Fatalf("必须要求先改密: %s", rec.Body.String())
			}
		})
	}
}

// 禁用账号、无密码账号对三员同样拒绝，且提示不泄露账号状态（与其他角色一致）。
func TestInactiveThreeOfficerCannotSignIn(t *testing.T) {
	for _, role := range threeOfficers {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			user := env.createUser(role, "disabled", "Correct-Horse-42")
			if rec := env.login(user.Username, user.Password, "192.0.2.25", nil); rec.Code != http.StatusUnauthorized {
				t.Fatalf("禁用账号必须 401: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// 员工入口（Chat 个人入口）的行为不变：三员走员工入口仍只拿一次性 chat_ticket，不产生管理会话。
func TestThreeOfficersEmployeeEntryStillIssuesNoManagementSession(t *testing.T) {
	for _, role := range threeOfficers {
		t.Run(role, func(t *testing.T) {
			e, u, _ := chatLoginFixture(t)
			if _, err := e.pool.Exec(context.Background(), "UPDATE users SET role=$2 WHERE id=$1", u.ID, role); err != nil {
				t.Fatal(err)
			}
			e.withConsoleSecurity()
			secret := setupTOTPForUser(t, e, u)
			code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
			response := e.employeeLogin(u.Username, u.Password, "192.0.2.26", map[string]string{"totp_code": code})
			if response.Code != 200 || strings.Contains(response.Body.String(), `"token":"`) && !strings.Contains(response.Body.String(), `"token":""`) {
				t.Fatalf("员工入口只应发 chat_ticket、不发管理 token: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

// 兑现本文件开头「不产生更弱的登录路径」：同一账号、同一策略下，SSO 与本地密码登录对 IP 白名单与 TOTP 给出同一结论。
// SSO 侧的完整加固用例见 console_sso_hardening_test.go。
func TestThreeOfficersSSOAndLocalLoginAgreeOnIPAllowlistAndTOTP(t *testing.T) {
	for _, role := range threeOfficers {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			env.withConsoleSecurity()
			env.sys.values["console_admin_ip_allowlist"] = "10.0.0.0/8"
			user := env.createUser(role, "active", "Correct-Horse-42")
			secret := setupTOTPForUser(t, env, user)
			sso := consoleSSOPolicy{deps: env.deps}
			acct := ssoAccount(user, role, env.tenantID)
			ctx := context.Background()

			// 白名单之外：两条路径都拒绝
			local := env.login(user.Username, user.Password, "203.0.113.5", nil)
			d, _ := sso.Authorize(ctx, ssoRequest("203.0.113.5"), acct, "")
			if local.Code != http.StatusForbidden || d.Outcome != consolesso.OutcomeIPNotAllowed {
				t.Fatalf("IP 白名单两条路径必须一致: local=%d sso=%v", local.Code, d.Outcome)
			}
			// 白名单之内、缺验证码：两条路径都要求 TOTP
			local = env.login(user.Username, user.Password, "10.1.1.1", nil)
			d, _ = sso.Authorize(ctx, ssoRequest("10.1.1.1"), acct, "")
			if local.Code != http.StatusUnauthorized || d.Outcome != consolesso.OutcomeTOTPRequired {
				t.Fatalf("缺验证码两条路径必须一致: local=%d sso=%v", local.Code, d.Outcome)
			}
			// 正确验证码：两条路径都放行（各用不同的时间步，避免防重放互相影响）
			code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
			if d, _ = sso.Authorize(ctx, ssoRequest("10.1.1.1"), acct, code); d.Outcome != consolesso.OutcomeAllow {
				t.Fatalf("SSO 正确验证码应放行: %v", d.Outcome)
			}
		})
	}
}
