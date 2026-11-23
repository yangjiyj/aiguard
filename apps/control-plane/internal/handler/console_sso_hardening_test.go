package handler

// M-2：SSO 不能是比本地登录更弱的登录路径。SSO 在签发控制台会话前必须走与本地登录同一套加固：
// 管理员来源 IP 白名单、已绑定 TOTP 的校验与防重放、要求启用但未绑定时的绑定专用会话、失败锁定，
// 以及按策略设置的会话绝对/空闲时长与并发上限。本文件用真库把 console_login_three_officers_test.go 里
// 「不产生更弱的登录路径」的断言延伸到 SSO。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity/consolesso"
)

func ssoAccount(u consoleTestUser, role, tenant string) consolesso.Account {
	return consolesso.Account{ID: u.ID, TenantID: tenant, Username: u.Username, Role: role, Status: "active"}
}

func ssoRequest(ip string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/admin/v1/auth/sso/session", nil)
	r.RemoteAddr = ip + ":4000"
	return r
}

var ssoConsoleRoles = []string{"platform_admin", "security_officer", "auditor", "tenant_admin"}

func TestSSOPolicyAppliesTheAdminIPAllowlistToEveryConsoleRole(t *testing.T) {
	for _, role := range ssoConsoleRoles {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			env.sys.values["console_admin_ip_allowlist"] = "10.0.0.0/8"
			u := env.createUser(role, "active", "Correct-Horse-42")
			p := consoleSSOPolicy{deps: env.deps}
			d, err := p.Authorize(context.Background(), ssoRequest("203.0.113.5"), ssoAccount(u, role, env.tenantID), "")
			if err != nil || d.Outcome != consolesso.OutcomeIPNotAllowed {
				t.Fatalf("白名单之外必须拒绝: %+v %v", d, err)
			}
			d, err = p.Authorize(context.Background(), ssoRequest("10.20.30.40"), ssoAccount(u, role, env.tenantID), "")
			if err != nil || d.Outcome != consolesso.OutcomeAllow {
				t.Fatalf("白名单之内应放行: %+v %v", d, err)
			}
			if n := env.countHistory(`user_id = $1 AND success = FALSE AND failure_reason = $2`, u.ID, loginFailIPNotAllowed); n != 1 {
				t.Fatalf("IP 拒绝必须与本地登录一样留下登录历史，实际 %d 条", n)
			}
		})
	}
}

func TestSSOPolicyRequiresAndValidatesTOTPAndBlocksReplay(t *testing.T) {
	for _, role := range ssoConsoleRoles {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			env.withConsoleSecurity()
			u := env.createUser(role, "active", "Correct-Horse-42")
			secret := setupTOTPForUser(t, env, u)
			p := consoleSSOPolicy{deps: env.deps}
			acct := ssoAccount(u, role, env.tenantID)
			ctx := context.Background()
			if d, _ := p.Authorize(ctx, ssoRequest("192.0.2.30"), acct, ""); d.Outcome != consolesso.OutcomeTOTPRequired {
				t.Fatalf("已绑定 TOTP 的账号缺验证码应 totp_required: %+v", d)
			}
			if d, _ := p.Authorize(ctx, ssoRequest("192.0.2.30"), acct, "000000"); d.Outcome != consolesso.OutcomeTOTPInvalid {
				t.Fatalf("错误验证码: %+v", d)
			}
			code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
			if d, _ := p.Authorize(ctx, ssoRequest("192.0.2.30"), acct, code); d.Outcome != consolesso.OutcomeAllow {
				t.Fatalf("正确验证码应放行: %+v", d)
			}
			if d, _ := p.Authorize(ctx, ssoRequest("192.0.2.30"), acct, code); d.Outcome == consolesso.OutcomeAllow {
				t.Fatal("同一验证码不得复用（防重放）")
			}
		})
	}
}

func TestSSOPolicyIssuesEnrollmentOnlySessionWhenTOTPIsRequiredButNotEnrolled(t *testing.T) {
	for _, role := range ssoConsoleRoles {
		t.Run(role, func(t *testing.T) {
			env := newConsoleLoginEnv(t)
			env.withConsoleSecurity()
			setupIdentitySecretKey(t)
			env.sys.values["console_admin_totp_required"] = "true"
			u := env.createUser(role, "active", "Correct-Horse-42")
			d, err := consoleSSOPolicy{deps: env.deps}.Authorize(context.Background(), ssoRequest("192.0.2.31"), ssoAccount(u, role, env.tenantID), "")
			if err != nil || d.Outcome != consolesso.OutcomeAllow || !d.TOTPSetupPending {
				t.Fatalf("强制 TOTP 但未绑定：只能拿绑定专用会话: %+v %v", d, err)
			}
		})
	}
}

func TestSSOPolicyLocksTheAccountAfterRepeatedInvalidTOTP(t *testing.T) {
	env := newConsoleLoginEnv(t)
	env.withConsoleSecurity()
	u := env.createUser("security_officer", "active", "Correct-Horse-42")
	secret := setupTOTPForUser(t, env, u)
	p := consoleSSOPolicy{deps: env.deps}
	acct := ssoAccount(u, "security_officer", env.tenantID)
	ctx := context.Background()
	var last consolesso.Decision
	for i := 0; i < 5; i++ {
		last, _ = p.Authorize(ctx, ssoRequest("192.0.2.32"), acct, "000000")
	}
	if last.Outcome != consolesso.OutcomeLocked || last.RetryAfter <= 0 {
		t.Fatalf("第 5 次错误验证码应触发锁定: %+v", last)
	}
	code, _ := totpCodeAt(secret, uint64(time.Now().Unix()/totpPeriod))
	if d, _ := p.Authorize(ctx, ssoRequest("192.0.2.32"), acct, code); d.Outcome != consolesso.OutcomeLocked {
		t.Fatalf("锁定期间即使验证码正确也必须拒绝: %+v", d)
	}
	// 与本地登录共用同一把锁：本地密码登录也被拒绝
	if rec := env.login(u.Username, u.Password, "192.0.2.32", nil); rec.Code != http.StatusLocked {
		t.Fatalf("SSO 触发的锁定应同样锁住本地登录: %d", rec.Code)
	}
}

// 非控制台角色即使走到策略也不适用管理员加固（它们根本不该拿到控制台会话，角色关卡在 Redeem 里先拒绝）。
func TestSSOPolicyDoesNotTreatEmployeeRolesAsConsoleAdministrators(t *testing.T) {
	env := newConsoleLoginEnv(t)
	env.sys.values["console_admin_ip_allowlist"] = "10.0.0.0/8"
	u := env.createUser("developer", "active", "Correct-Horse-42")
	d, _ := consoleSSOPolicy{deps: env.deps}.Authorize(context.Background(), ssoRequest("203.0.113.5"), ssoAccount(u, "developer", env.tenantID), "")
	if d.Outcome == consolesso.OutcomeIPNotAllowed {
		t.Fatalf("管理员 IP 白名单只针对控制台角色")
	}
}

// 会话时长与并发上限来自登录策略，与本地登录一致。
func TestSSOSessionsFollowTheConsoleSessionPolicy(t *testing.T) {
	env := newConsoleLoginEnv(t)
	env.sys.values["console_session_absolute_hours"] = "6"
	env.sys.values["console_session_idle_minutes"] = "20"
	env.sys.values["console_session_max_concurrent"] = "2"
	u := env.createUser("auditor", "active", "Correct-Horse-42")
	s := consoleSSOSessions{sessions: env.deps.SessionRepo, system: env.deps.SystemRepo}
	ctx := context.Background()
	acct := ssoAccount(u, "auditor", env.tenantID)
	var first string
	for i := 0; i < 3; i++ {
		res, err := s.CreateSession(ctx, acct, consolesso.SessionOptions{ClientIP: "192.0.2.40", TOTPSetupPending: i == 2})
		if err != nil {
			t.Fatal(err)
		}
		if res.AbsoluteHours != 6 || res.IdleSeconds != 20*60 {
			t.Fatalf("时长应来自策略: %+v", res)
		}
		if i == 0 {
			first = res.ID
		}
	}
	ids, _ := env.sessions.ActiveSessionIDs(ctx, u.ID)
	if len(ids) > 2 {
		t.Fatalf("并发上限 2 应被执行，实际 %d 个会话", len(ids))
	}
	if sess, _ := env.sessions.Get(ctx, first); sess != nil {
		t.Fatalf("最旧的会话应被挤掉")
	}
	var last string
	for _, id := range ids {
		sess, _ := env.sessions.Get(ctx, id)
		if sess != nil && sess.TOTPSetupPending {
			last = id
			if sess.IP != "192.0.2.40" || sess.IdleTimeoutSeconds != 20*60 || sess.AbsoluteExpiresAt.IsZero() {
				t.Fatalf("会话字段应完整: %+v", sess)
			}
		}
	}
	if last == "" {
		t.Fatal("绑定专用标记必须写入会话")
	}
}

// 装配检查：NewConsoleSSO 必须挂上会话策略，否则 Redeem 会 fail-closed（503）。
func TestNewConsoleSSOWiresTheSessionPolicy(t *testing.T) {
	env := newConsoleLoginEnv(t)
	svc := NewConsoleSSO(env.deps, consolesso.Config{}, nil)
	if !svc.HasSessionPolicy() {
		t.Fatal("NewConsoleSSO 必须挂载会话策略")
	}
}
