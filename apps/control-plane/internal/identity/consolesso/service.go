package consolesso

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

const (
	bindingCookie   = "console_sso_binding"
	bindingPath     = "/admin/v1/auth/sso"
	LoginPath       = "/admin/v1/auth/sso/login"
	maxTicketLength = 128
)

// consoleRole 判定账号角色能否经 SSO 进入控制台。与本地登录使用同一份清单 roles.CanLoginConsole：
// 三员（系统管理员、安全保密管理员、审计员）与租户管理员及其历史别名。
// 历史：d67df07da（2026-09-30）当时控制台对所有非 chat_user 角色开放，这里手写了一份「管理类角色」表，含 dept_manager、
// team_owner、operator，却漏了同日建立的 security_officer；942eecff9（10-12）把本地登录收窄为管理员档之后，这份表没有同步，
// 于是 SSO 比本地登录既宽（那三个角色拿到的会话会被鉴权中间件 403）又窄（安全员进不来）。现在不再维护第二份清单。
// 员工门户 JIT 建出的账号默认是 developer，只能用门户。
func consoleRole(role string) bool { return roles.CanLoginConsole(role) }

// Account 是控制台账号的最小视图（由 handler 层适配 repository.User）。
type Account struct {
	ID, TenantID, Username, Role, Status string
	MustChangePassword                   bool
}

type Accounts interface {
	Account(ctx context.Context, userID string) (*Account, error)
}

// SessionOptions 是签发会话时由登录加固决定的参数。
type SessionOptions struct {
	ClientIP         string
	TOTPSetupPending bool // 要求启用双因素但尚未绑定：只签发绑定专用会话
}

// SessionResult 是创建出的会话及其生效时长（来自登录策略，与本地登录一致）。
type SessionResult struct {
	ID            string
	AbsoluteHours int // 绝对有效期（小时），用于 cookie MaxAge 与响应的 expires
	IdleSeconds   int
}

// Sessions 创建与本地登录同一种控制台会话，SSO 与本地登录共用鉴权中间件。
// 会话的绝对/空闲时长与并发上限必须与本地登录一致（由实现按登录策略设置）。
type Sessions interface {
	CreateSession(ctx context.Context, a Account, opts SessionOptions) (SessionResult, error)
}

// Outcome 是会话签发前登录加固的结论。
type Outcome int

const (
	OutcomeAllow Outcome = iota
	OutcomeIPNotAllowed
	OutcomeTOTPRequired
	OutcomeTOTPInvalid
	OutcomeLocked
)

// Decision 是 SessionPolicy 对一次兑换的裁决。
type Decision struct {
	Outcome          Outcome
	TOTPSetupPending bool          // OutcomeAllow 时有效：只发绑定专用会话
	RetryAfter       time.Duration // OutcomeLocked 时有效
	// ClientIP 是策略按本地登录同一口径（含可信代理）解析出的来源地址；非空时用于会话记录。
	ClientIP string
}

// SessionPolicy 让 SSO 与本地登录共用同一套登录加固：管理员来源 IP 白名单、已绑定 TOTP 的校验与防重放、
// 要求启用但未绑定时的绑定专用会话、失败锁定。没有策略时 Redeem fail-closed，绝不退回「不加固就发会话」。
type SessionPolicy interface {
	Authorize(ctx context.Context, r *http.Request, a Account, totpCode string) (Decision, error)
}

type Service struct {
	cfg      Config
	enabled  bool // OIDC 已配置
	ready    bool // 共享依赖（Redis/账号/会话/主体解析）齐备，CAS/企业微信可挂载
	store    store
	cas      *CASConfig
	wecom    *weComClient
	keys     keySource
	http     *http.Client
	subjects SubjectResolver
	accounts Accounts
	sessions Sessions
	policy   SessionPolicy
	now      func() time.Time
}

// New 在配置不完整时返回 enabled=false 的 Service：status 如实报告关闭，
// login/callback 返回 404，本地管理员登录不受影响。
func New(cfg Config, redisClient *redis.Client, subjects SubjectResolver, accounts Accounts, sessions Sessions) *Service {
	client := newHTTPClient()
	s := &Service{cfg: cfg, http: client, subjects: subjects, accounts: accounts, sessions: sessions, now: time.Now}
	if redisClient == nil || subjects == nil || accounts == nil || sessions == nil {
		return s
	}
	s.ready = true
	s.store = newRedisStore(redisClient)
	if cfg.Validate() != nil {
		return s
	}
	s.enabled = true
	s.keys = newJWKSCache(cfg.JWKSURL, client, s.now)
	return s
}

// WithSessionPolicy 挂载会话签发前的登录加固。必须挂载，否则 Redeem 返回 503（fail-closed）。
func (s *Service) WithSessionPolicy(p SessionPolicy) *Service {
	if s != nil {
		s.policy = p
	}
	return s
}

// HasSessionPolicy 报告会话策略是否已挂载（装配检查与测试用）。
func (s *Service) HasSessionPolicy() bool { return s != nil && s.policy != nil }

// WithCAS（W9 9.3）挂载 CAS 登录。配置不完整或共享依赖缺失时不挂载，入口保持 404。
func (s *Service) WithCAS(c CASConfig) *Service {
	if s != nil && s.ready && c.Validate(s.cfg.CookieSecure) == nil {
		cp := c
		s.cas = &cp
	}
	return s
}

// WithWeCom（W9 9.3）挂载企业微信登录。
func (s *Service) WithWeCom(c WeComConfig) *Service {
	if s != nil && s.ready && c.Validate(s.cfg.CookieSecure) == nil {
		s.wecom = newWeComClient(c, s.http, s.now)
	}
	return s
}

// Enabled 表示至少有一种 SSO 方式可用。
func (s *Service) Enabled() bool { return s != nil && (s.enabled || s.cas != nil || s.wecom != nil) }

// Status GET /admin/v1/auth/sso/status（公开）。只报告是否可用与入口，不暴露 IdP 细节。
func (s *Service) Status(w http.ResponseWriter, _ *http.Request) {
	resp := map[string]any{"enabled": s.Enabled(), "local_login": true}
	providers := []map[string]string{}
	if s != nil && s.enabled {
		providers = append(providers, map[string]string{"id": ProviderOIDC, "login_url": LoginPath})
	}
	if s != nil && s.cas != nil {
		providers = append(providers, map[string]string{"id": ProviderCAS, "login_url": CASLoginPath, "display_name": s.cas.DisplayName})
	}
	if s != nil && s.wecom != nil {
		providers = append(providers, map[string]string{"id": ProviderWeCom, "login_url": WeComLoginPath})
	}
	if len(providers) > 0 {
		// login_url 保持 9.1 语义（首选入口）；providers 列出全部可用方式。
		resp["login_url"] = providers[0]["login_url"]
	}
	resp["providers"] = providers
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, resp)
}

// Login GET /admin/v1/auth/sso/login：生成 state/nonce/PKCE，绑定浏览器后 302 到 IdP。
func (s *Service) Login(w http.ResponseWriter, r *http.Request) {
	if s == nil || !s.enabled {
		http.NotFound(w, r)
		return
	}
	state, nonce, verifier, binding := randomToken(), randomToken(), randomToken(), randomToken()
	if err := s.store.putState(r.Context(), state, flowState{
		Provider: ProviderOIDC, Nonce: nonce, CodeVerifier: verifier, BindingHash: hashHex(binding),
	}); err != nil {
		log.Print("component=console_sso stage=login error_code=state_store_unavailable")
		s.fail(w, r, "unavailable")
		return
	}
	s.setBinding(w, binding)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, s.cfg.authorizeURL(state, nonce, verifier), http.StatusFound)
}

// Callback GET /admin/v1/auth/sso/callback：校验 state+浏览器绑定 → 换码 → 验 id_token
// → 按绑定关系找已有控制台账号 → 签一次性票据，302 回登录页（票据放 fragment，不进日志/Referer）。
func (s *Service) Callback(w http.ResponseWriter, r *http.Request) {
	if s == nil || !s.enabled {
		http.NotFound(w, r)
		return
	}
	s.clearBinding(w)
	q := r.URL.Query()
	if q.Get("error") != "" {
		s.fail(w, r, "idp_denied")
		return
	}
	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" || len(state) > 256 || len(code) > 4096 {
		s.fail(w, r, "invalid_request")
		return
	}
	flow, ok := s.takeBoundFlow(w, r, state, ProviderOIDC)
	if !ok {
		return
	}
	idToken, err := exchangeCode(r.Context(), s.http, s.cfg, code, flow.CodeVerifier)
	if err != nil {
		log.Printf("component=console_sso stage=token error_code=exchange_failed err=%v", err)
		s.fail(w, r, "idp_unavailable")
		return
	}
	claims, err := verifyIDToken(r.Context(), s.keys, idToken, verifyOptions{
		issuer: s.cfg.Issuer, audience: s.cfg.ClientID, nonce: flow.Nonce, now: s.now(),
	})
	if err != nil {
		log.Printf("component=console_sso stage=verify error_code=invalid_id_token err=%v", err)
		s.fail(w, r, "invalid_token")
		return
	}
	s.completeLogin(w, r, ProviderOIDC, claims.Issuer, claims.Subject)
}

// takeBoundFlow 一次性取出 state，并校验它属于本协议、且由同一浏览器发起。
// 不同协议的 state 不能互换（防止把 OIDC 的 state 拿到 CAS 回调里用，反之亦然）。
func (s *Service) takeBoundFlow(w http.ResponseWriter, r *http.Request, state, provider string) (flowState, bool) {
	flow, err := s.store.takeState(r.Context(), state)
	if err != nil {
		s.fail(w, r, "expired")
		return flowState{}, false
	}
	got := flow.Provider
	if got == "" {
		got = ProviderOIDC // 9.1 时期写入的 state 没有 provider 字段
	}
	if got != provider {
		log.Printf("component=console_sso provider=%s stage=callback error_code=state_provider_mismatch", provider)
		s.fail(w, r, "invalid_request")
		return flowState{}, false
	}
	c, cerr := r.Cookie(bindingCookie)
	if cerr != nil || subtle.ConstantTimeCompare([]byte(hashHex(c.Value)), []byte(flow.BindingHash)) != 1 {
		log.Printf("component=console_sso provider=%s stage=callback error_code=browser_binding_mismatch", provider)
		s.fail(w, r, "invalid_request")
		return flowState{}, false
	}
	return flow, true
}

func (s *Service) takeBoundState(w http.ResponseWriter, r *http.Request, state, provider string) bool {
	_, ok := s.takeBoundFlow(w, r, state, provider)
	return ok
}

func (s *Service) setBinding(w http.ResponseWriter, binding string) {
	http.SetCookie(w, &http.Cookie{
		Name: bindingCookie, Value: binding, Path: bindingPath, MaxAge: int(stateTTL.Seconds()),
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

// completeLogin 是各协议共用的收尾：按绑定关系找已有控制台账号 → 一次性票据 → 回登录页。
func (s *Service) completeLogin(w http.ResponseWriter, r *http.Request, provider, issuer, subject string) {
	account, reason := s.resolveAccount(r.Context(), provider, issuer, subject)
	if reason != "" {
		log.Printf("component=console_sso provider=%s stage=resolve error_code=%s", provider, reason)
		s.fail(w, r, reason)
		return
	}
	ticketID := randomToken()
	if err := s.store.putTicket(r.Context(), ticketID, ticket{
		UserID: account.ID, TenantID: account.TenantID, Subject: subject, Provider: provider,
	}); err != nil {
		s.fail(w, r, "unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, s.cfg.loginPage()+"#sso_ticket="+url.QueryEscape(ticketID), http.StatusFound)
}

func (s *Service) resolveAccount(ctx context.Context, provider, issuer, subject string) (*Account, string) {
	var (
		tenantID, userID string
		err              error
	)
	if provider == ProviderOIDC {
		tenantID, userID, err = s.subjects.ResolveConsoleSubject(ctx, issuer, subject)
	} else if pr, ok := s.subjects.(ProviderSubjectResolver); ok {
		tenantID, userID, err = pr.ResolveProviderSubject(ctx, provider, issuer, subject)
	} else {
		err = errAccountNotLinked
	}
	if errors.Is(err, errAccountNotLinked) || errors.Is(err, errAccountAmbiguous) {
		return nil, "not_console_user"
	}
	if err != nil {
		return nil, "unavailable"
	}
	a, err := s.accounts.Account(ctx, userID)
	if err != nil {
		return nil, "unavailable"
	}
	if a == nil || a.TenantID != tenantID || !consoleRole(a.Role) {
		return nil, "not_console_user"
	}
	if a.Status != "active" {
		return nil, "account_inactive"
	}
	return a, ""
}

// Redeem POST /admin/v1/auth/sso/session：用一次性票据换控制台会话，响应与本地登录同形。
// 兑换时重新读取账号，票据签发后被停用/改角色的账号拿不到会话；随后走与本地登录同一套登录加固（SessionPolicy）。
// 请求体可带 totp_code：账号已绑定 TOTP 时必须提供。
func (s *Service) Redeem(w http.ResponseWriter, r *http.Request) {
	if !s.Enabled() {
		http.NotFound(w, r)
		return
	}
	var req struct {
		Ticket   string `json:"ticket"`
		TOTPCode string `json:"totp_code"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil ||
		req.Ticket == "" || len(req.Ticket) > maxTicketLength || len(req.TOTPCode) > 16 {
		writeError(w, http.StatusBadRequest, "invalid_request", "invalid sso ticket")
		return
	}
	// 没有会话策略时拒绝：不能退回「不加固就发会话」。票据不消耗。
	if s.policy == nil {
		log.Print("component=console_sso stage=redeem error_code=session_policy_missing")
		writeError(w, http.StatusServiceUnavailable, "unavailable", "login policy unavailable")
		return
	}
	ticketID := strings.TrimSpace(req.Ticket)
	t, err := s.store.takeTicket(r.Context(), ticketID)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized", "sso ticket is invalid or expired")
		return
	}
	a, err := s.accounts.Account(r.Context(), t.UserID)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "unavailable", "account lookup failed")
		return
	}
	if a == nil || a.TenantID != t.TenantID || !consoleRole(a.Role) || a.Status != "active" {
		writeError(w, http.StatusUnauthorized, "unauthorized", "account is not allowed to sign in")
		return
	}
	decision, err := s.policy.Authorize(r.Context(), r, *a, strings.TrimSpace(req.TOTPCode))
	if err != nil {
		log.Print("component=console_sso stage=redeem error_code=policy_unavailable")
		writeError(w, http.StatusServiceUnavailable, "unavailable", "login policy unavailable")
		return
	}
	switch decision.Outcome {
	case OutcomeAllow:
	case OutcomeIPNotAllowed:
		writeError(w, http.StatusForbidden, "login_ip_not_allowed", "login from this address is not allowed for this account")
		return
	case OutcomeTOTPRequired:
		// 还没有验证码：票据不消耗，带上验证码重试同一张票据即可。
		_ = s.store.putTicket(r.Context(), ticketID, t)
		writeError(w, http.StatusUnauthorized, "totp_required", "two-factor verification code required")
		return
	case OutcomeLocked:
		if decision.RetryAfter > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(decision.RetryAfter.Seconds()))))
		}
		writeError(w, http.StatusLocked, "account_locked", "account temporarily locked after repeated failed logins")
		return
	default: // OutcomeTOTPInvalid 及未知结论：票据作废，不能在同一张票据上继续猜验证码。
		writeError(w, http.StatusUnauthorized, "unauthorized", "sso ticket is invalid or expired")
		return
	}
	res, err := s.sessions.CreateSession(r.Context(), *a, SessionOptions{
		ClientIP: firstNonEmpty(decision.ClientIP, clientIP(r)), TOTPSetupPending: decision.TOTPSetupPending,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", "failed to create session")
		return
	}
	hours := res.AbsoluteHours
	if hours <= 0 {
		hours = 24 // 实现没有给出时长时的保守兜底（与历史行为一致）
	}
	http.SetCookie(w, &http.Cookie{
		Name: "session_token", Value: res.ID, Path: "/", MaxAge: hours * 3600,
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode,
	})
	w.Header().Set("Cache-Control", "no-store")
	resp := map[string]any{
		"token": res.ID,
		"user": map[string]any{
			"id": a.ID, "username": a.Username, "role": a.Role, "tenant_id": a.TenantID,
			"password_change_required": a.MustChangePassword,
		},
		"expires":                  strconv.Itoa(hours) + "h",
		"password_change_required": a.MustChangePassword,
		"auth_method":              "sso",
		"sso_provider":             ticketProvider(t),
	}
	if decision.TOTPSetupPending {
		resp["totp_setup_required"] = true
	}
	if res.IdleSeconds > 0 {
		resp["idle_timeout_seconds"] = res.IdleSeconds
	}
	writeJSON(w, http.StatusOK, resp)
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// clientIP 取直连地址的主机部分。登录页走同源反向代理，真实来源由上游代理写入 X-Forwarded-For 的部署
// 在 handler 层的实现里按本地登录同一口径（requestClientIP）解析并覆盖。
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func ticketProvider(t ticket) string {
	if t.Provider == "" {
		return ProviderOIDC
	}
	return t.Provider
}

func (s *Service) clearBinding(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: bindingCookie, Value: "", Path: bindingPath, MaxAge: -1,
		HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

// fail 跳回登录页并带稳定错误码；登录页据此展示提示并保留本地登录。
func (s *Service) fail(w http.ResponseWriter, r *http.Request, code string) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, s.cfg.loginPage()+"?sso_error="+url.QueryEscape(code), http.StatusFound)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{"error": map[string]string{"code": code, "message": message}})
}

// ProviderIssuer 返回已启用的 CAS/企业微信在绑定关系中使用的 issuer；未启用返回 false。
// 绑定接口只用这里的值，不接受客户端传入 issuer。
func (s *Service) ProviderIssuer(provider string) (string, bool) {
	switch {
	case s == nil:
		return "", false
	case provider == ProviderCAS && s.cas != nil:
		return s.cas.issuer(), true
	case provider == ProviderWeCom && s.wecom != nil:
		return s.wecom.cfg.Issuer(), true
	}
	return "", false
}
