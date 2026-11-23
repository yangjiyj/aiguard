package consolesso

// M-2：SSO 是一条更弱的登录路径。原先：
//   - 角色表 consoleRoles 含 dept_manager、team_owner、operator，缺 security_officer，与本地登录的 roles.CanLoginConsole 不一致；
//   - Redeem 签发会话前不做管理员来源 IP 白名单、强制/已绑 TOTP、失败锁定，也不按策略设置会话的绝对/空闲时长与并发上限。
// 现在：角色判定与本地登录同一份清单（roles.CanLoginConsole）；签发前走 SessionPolicy，与本地登录同一套加固。

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

func ssoLoginTicket(t *testing.T, h *harness) string {
	t.Helper()
	state, binding := h.startLogin(t)
	return ticketFrom(t, h.callback(state, "good-code", binding))
}

func redeemWith(h *harness, ticket, totp string) *httptest.ResponseRecorder {
	body := map[string]string{"ticket": ticket}
	if totp != "" {
		body["totp_code"] = totp
	}
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/auth/sso/session", bytes.NewReader(raw))
	req.RemoteAddr = "203.0.113.9:4000"
	w := httptest.NewRecorder()
	h.svc.Redeem(w, req)
	return w
}

// 角色清单与本地登录一致：三员与租户管理员可以，员工与业务角色不行。
func TestSSORoleListMatchesLocalLoginConsoleRoles(t *testing.T) {
	all := []string{"platform_admin", "admin", "security_officer", "auditor", "tenant_admin", "tenant_owner",
		"dept_manager", "team_owner", "operator", "developer", "viewer", "chat_user", "project_owner", "platform_connector", ""}
	for _, role := range all {
		h := newHarness(t, role)
		state, binding := h.startLogin(t)
		w := h.callback(state, "good-code", binding)
		got := failCode(w) // 成功时 failCode 返回 no-error 前缀
		allowed := !strings.HasPrefix(got, "not_console_user")
		if allowed != roles.CanLoginConsole(role) {
			t.Fatalf("角色 %q：SSO 放行=%v，本地登录放行=%v，两条路径必须同一份清单", role, allowed, roles.CanLoginConsole(role))
		}
	}
}

func TestSSOTicketRedeemRejectsNonConsoleRolesEvenIfTheTicketWasIssuedEarlier(t *testing.T) {
	for _, role := range []string{"dept_manager", "team_owner", "operator"} {
		h := newHarness(t, "tenant_admin")
		ticket := ssoLoginTicket(t, h)
		h.accounts.set("u1", func(a *Account) { a.Role = role })
		if w := redeemWith(h, ticket, ""); w.Code != http.StatusUnauthorized || len(h.sessions.created) != 0 {
			t.Fatalf("%s 不得兑换出控制台会话: %d", role, w.Code)
		}
	}
}

// 没有会话策略时 fail-closed：绝不退回「不加固就发会话」。
func TestRedeemFailsClosedWithoutASessionPolicy(t *testing.T) {
	h := newHarness(t, "security_officer")
	h.svc.policy = nil
	ticket := ssoLoginTicket(t, h)
	w := redeemWith(h, ticket, "")
	if w.Code != http.StatusServiceUnavailable || len(h.sessions.created) != 0 {
		t.Fatalf("无会话策略必须拒绝并不发会话: %d %s", w.Code, w.Body.String())
	}
}

type scriptedPolicy struct {
	decisions []Decision
	calls     []policyCall
}
type policyCall struct {
	account Account
	totp    string
	ip      string
}

func (p *scriptedPolicy) Authorize(_ context.Context, r *http.Request, a Account, totp string) (Decision, error) {
	p.calls = append(p.calls, policyCall{a, totp, r.RemoteAddr})
	d := p.decisions[0]
	if len(p.decisions) > 1 {
		p.decisions = p.decisions[1:]
	}
	return d, nil
}

func TestRedeemEnforcesTheSessionPolicyDecision(t *testing.T) {
	type tc struct {
		name    string
		d       Decision
		status  int
		code    string
		session bool
	}
	for _, c := range []tc{
		{"IP 不在白名单", Decision{Outcome: OutcomeIPNotAllowed}, http.StatusForbidden, "login_ip_not_allowed", false},
		{"需要 TOTP", Decision{Outcome: OutcomeTOTPRequired}, http.StatusUnauthorized, "totp_required", false},
		{"TOTP 错误", Decision{Outcome: OutcomeTOTPInvalid}, http.StatusUnauthorized, "unauthorized", false},
		{"账号被锁定", Decision{Outcome: OutcomeLocked, RetryAfter: 90 * time.Second}, http.StatusLocked, "account_locked", false},
		{"放行", Decision{Outcome: OutcomeAllow}, http.StatusOK, "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			h := newHarness(t, "security_officer")
			h.svc.WithSessionPolicy(&scriptedPolicy{decisions: []Decision{c.d}})
			w := redeemWith(h, ssoLoginTicket(t, h), "")
			if w.Code != c.status {
				t.Fatalf("status=%d want %d body=%s", w.Code, c.status, w.Body.String())
			}
			if c.code != "" && !strings.Contains(w.Body.String(), c.code) {
				t.Fatalf("应返回 %s: %s", c.code, w.Body.String())
			}
			if (len(h.sessions.created) == 1) != c.session {
				t.Fatalf("会话签发=%d 与决策不一致", len(h.sessions.created))
			}
			if c.d.Outcome == OutcomeLocked && w.Header().Get("Retry-After") == "" {
				t.Fatal("锁定响应必须带 Retry-After")
			}
		})
	}
}

// 需要 TOTP 时票据不被消耗：带上验证码重试同一张票据即可；TOTP 错误则票据作废（必须重新走 SSO）。
func TestTOTPRequiredKeepsTheTicketButInvalidTOTPBurnsIt(t *testing.T) {
	h := newHarness(t, "auditor")
	policy := &scriptedPolicy{decisions: []Decision{{Outcome: OutcomeTOTPRequired}, {Outcome: OutcomeAllow}}}
	h.svc.WithSessionPolicy(policy)
	ticket := ssoLoginTicket(t, h)
	if w := redeemWith(h, ticket, ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("第一次应要求 TOTP: %d", w.Code)
	}
	w := redeemWith(h, ticket, "123456")
	if w.Code != http.StatusOK || len(h.sessions.created) != 1 {
		t.Fatalf("带验证码重试应成功: %d %s", w.Code, w.Body.String())
	}
	if policy.calls[1].totp != "123456" {
		t.Fatalf("验证码必须原样交给策略校验: %+v", policy.calls)
	}

	h2 := newHarness(t, "auditor")
	h2.svc.WithSessionPolicy(&scriptedPolicy{decisions: []Decision{{Outcome: OutcomeTOTPInvalid}, {Outcome: OutcomeAllow}}})
	ticket2 := ssoLoginTicket(t, h2)
	if w := redeemWith(h2, ticket2, "000000"); w.Code != http.StatusUnauthorized {
		t.Fatalf("错误验证码: %d", w.Code)
	}
	if w := redeemWith(h2, ticket2, "000000"); w.Code != http.StatusUnauthorized || len(h2.sessions.created) != 0 {
		t.Fatalf("TOTP 错误后票据必须作废，不能在同一张票据上继续猜验证码: %d", w.Code)
	}
}

// 要求管理员启用双因素但尚未绑定：只签发绑定专用会话，响应提示 totp_setup_required。
func TestEnrollmentOnlySessionWhenTOTPIsRequiredButNotEnrolled(t *testing.T) {
	h := newHarness(t, "security_officer")
	h.svc.WithSessionPolicy(&scriptedPolicy{decisions: []Decision{{Outcome: OutcomeAllow, TOTPSetupPending: true}}})
	w := redeemWith(h, ssoLoginTicket(t, h), "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"totp_setup_required":true`) {
		t.Fatalf("应提示绑定双因素: %d %s", w.Code, w.Body.String())
	}
	if len(h.sessions.created) != 1 || !h.sessions.opts[0].TOTPSetupPending {
		t.Fatalf("会话必须是绑定专用: %+v", h.sessions.opts)
	}
}

// 来源 IP 以及账号信息要交给会话创建，用于白名单之外的会话记录与时长策略。
func TestRedeemPassesClientIPAndAccountToThePolicyAndSession(t *testing.T) {
	h := newHarness(t, "auditor")
	policy := &scriptedPolicy{decisions: []Decision{{Outcome: OutcomeAllow}}}
	h.svc.WithSessionPolicy(policy)
	redeemWith(h, ssoLoginTicket(t, h), "")
	if len(policy.calls) != 1 || policy.calls[0].account.Role != "auditor" || !strings.HasPrefix(policy.calls[0].ip, "203.0.113.9") {
		t.Fatalf("策略应拿到账号与来源 IP: %+v", policy.calls)
	}
	if len(h.sessions.opts) != 1 || !strings.HasPrefix(h.sessions.opts[0].ClientIP, "203.0.113.9") {
		t.Fatalf("会话创建应拿到来源 IP: %+v", h.sessions.opts)
	}
}

// 响应里的 cookie 有效期来自策略的绝对时长，而不是写死的 24h。
func TestRedeemCookieLifetimeFollowsThePolicyAbsoluteHours(t *testing.T) {
	h := newHarness(t, "auditor")
	h.svc.WithSessionPolicy(&scriptedPolicy{decisions: []Decision{{Outcome: OutcomeAllow}}})
	h.sessions.result = SessionResult{AbsoluteHours: 12, IdleSeconds: 1800}
	w := redeemWith(h, ssoLoginTicket(t, h), "")
	if w.Code != http.StatusOK {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
	var maxAge int
	for _, c := range w.Result().Cookies() {
		if c.Name == "session_token" {
			maxAge = c.MaxAge
		}
	}
	if maxAge != 12*3600 || !strings.Contains(w.Body.String(), `"expires":"12h"`) {
		t.Fatalf("cookie MaxAge=%d body=%s，应跟随策略的 12h", maxAge, w.Body.String())
	}
}
