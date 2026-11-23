package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/identity/consolesso"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/repository"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
)

// W9 9.1：控制台 SSO。与本地管理员登录并存（本地登录是兜底，不受 SSO 配置影响），
// SSO 成功后创建与本地登录同一种会话，鉴权中间件无需区分来源。

type consoleSSOAccounts struct{ users *repository.UserRepository }

func (a consoleSSOAccounts) Account(ctx context.Context, userID string) (*consolesso.Account, error) {
	u, err := a.users.GetByID(ctx, userID)
	if err != nil || u == nil {
		return nil, err
	}
	return &consolesso.Account{
		ID: u.ID, TenantID: u.TenantID, Username: u.Username, Role: u.Role,
		Status: u.Status, MustChangePassword: u.MustChangePassword,
	}, nil
}

// consoleSSOSessions 按登录策略创建会话：绝对/空闲时长、并发上限与本地登录一致。
type consoleSSOSessions struct {
	sessions SessionStore
	history  *repository.UserLoginHistoryRepository
	system   SystemRepo
}

func (s consoleSSOSessions) CreateSession(ctx context.Context, a consolesso.Account, opts consolesso.SessionOptions) (consolesso.SessionResult, error) {
	policy := LoadConsoleLoginPolicy(ctx, s.system)
	if limiter, ok := s.sessions.(consoleSessionLimiter); ok {
		if _, err := limiter.EnforceMaxConcurrent(ctx, a.ID, policy.SessionMaxConcurrent); err != nil {
			return consolesso.SessionResult{}, err
		}
	}
	id := uuid.New().String()
	if err := s.sessions.Create(ctx, &repository.Session{
		ID: id, UserID: a.ID, Username: a.Username, Role: a.Role, TenantID: a.TenantID,
		AbsoluteExpiresAt:  time.Now().Add(time.Duration(policy.SessionAbsoluteHours) * time.Hour),
		IdleTimeoutSeconds: policy.SessionIdleMinutes * 60,
		IP:                 opts.ClientIP,
		TOTPSetupPending:   opts.TOTPSetupPending,
	}); err != nil {
		return consolesso.SessionResult{}, err
	}
	if s.history != nil {
		_ = s.history.Insert(ctx, a.ID, opts.ClientIP, "console-sso", true, "")
		_ = s.history.UpdateUserLastLogin(ctx, a.ID)
	}
	return consolesso.SessionResult{ID: id, AbsoluteHours: policy.SessionAbsoluteHours, IdleSeconds: policy.SessionIdleMinutes * 60}, nil
}

// consoleSSOPolicy 让 SSO 在签发会话前走与本地登录同一套加固（M-2）：失败锁定、管理员来源 IP 白名单、
// 已绑定 TOTP 的校验与防重放、要求启用但未绑定时的绑定专用会话。SSO 没有本地密码，所以不做密码相关步骤。
type consoleSSOPolicy struct{ deps *Dependencies }

func (p consoleSSOPolicy) Authorize(ctx context.Context, r *http.Request, a consolesso.Account, totpCode string) (consolesso.Decision, error) {
	deps := p.deps
	policy := LoadConsoleLoginPolicy(ctx, deps.SystemRepo)
	ip := requestClientIP(r)
	dec := consolesso.Decision{ClientIP: ip}
	attempt := repository.LoginAttempt{
		UserID: a.ID, AttemptedUsername: a.Username, IP: ip, UserAgent: "console-sso", Event: repository.LoginEventLogin,
	}
	guard := newLoginGuard(deps.RedisClient, policy)
	remaining, err := guard.lockedFor(ctx, a.Username, ip)
	if err != nil {
		return dec, err // 守卫不可用：fail-closed（调用方返回 503）
	}
	if remaining > 0 {
		attempt.FailureReason = loginFailLocked
		recordConsoleLoginEvent(r, deps, attempt)
		dec.Outcome, dec.RetryAfter = consolesso.OutcomeLocked, remaining
		return dec, nil
	}
	hardened := roles.RequiresLoginHardening(a.Role)
	if hardened && !ipAllowed(policy.AdminIPAllowlist, ip) {
		attempt.FailureReason = loginFailIPNotAllowed
		recordConsoleLoginEvent(r, deps, attempt)
		dec.Outcome = consolesso.OutcomeIPNotAllowed
		return dec, nil
	}
	var security repository.ConsoleUserSecurity
	if deps.ConsoleSecurity != nil {
		security, err = deps.ConsoleSecurity.Get(ctx, a.ID)
		if err != nil {
			return dec, err
		}
	}
	if security.TOTPEnabled && security.TOTPSecretEnc != "" {
		if totpCode == "" {
			attempt.FailureReason = loginFailTOTPRequired
			recordConsoleLoginEvent(r, deps, attempt)
			dec.Outcome = consolesso.OutcomeTOTPRequired
			return dec, nil
		}
		secret, derr := decryptTOTPSecret(security.TOTPSecretEnc)
		counter, ok := verifyTOTP(secret, totpCode, time.Now())
		if derr == nil && ok {
			ok, err = consumeTOTPStep(ctx, deps.RedisClient, a.ID, counter)
			if err != nil {
				return dec, err
			}
		}
		if derr != nil || !ok {
			attempt.FailureReason = loginFailTOTPInvalid
			recordConsoleLoginEvent(r, deps, attempt)
			dec.Outcome = consolesso.OutcomeTOTPInvalid
			if locked, gerr := guard.recordFailure(ctx, a.Username, ip); gerr == nil && locked {
				recordConsoleLoginEvent(r, deps, repository.LoginAttempt{
					UserID: a.ID, AttemptedUsername: a.Username, IP: ip, UserAgent: "console-sso",
					FailureReason: loginFailLockTriggered, Event: repository.LoginEventLocked,
				})
				dec.Outcome, dec.RetryAfter = consolesso.OutcomeLocked, guard.window()
			}
			return dec, nil
		}
	} else if hardened && policy.AdminTOTPRequired && deps.ConsoleSecurity != nil {
		dec.TOTPSetupPending = true
	}
	guard.reset(ctx, a.Username, ip)
	return dec, nil
}

// NewConsoleSSO 装配控制台 SSO。依赖缺失时返回关闭状态的 Service。
func NewConsoleSSO(deps *Dependencies, cfg consolesso.Config, subjects consolesso.SubjectResolver) *consolesso.Service {
	if deps == nil || deps.UserRepo == nil || deps.SessionRepo == nil {
		return consolesso.New(cfg, nil, nil, nil, nil)
	}
	return consolesso.New(cfg, deps.RedisClient, subjects,
		consoleSSOAccounts{users: deps.UserRepo},
		consoleSSOSessions{sessions: deps.SessionRepo, history: deps.LoginHistoryRepo, system: deps.SystemRepo}).
		WithSessionPolicy(consoleSSOPolicy{deps: deps})
}

// ConsoleSSOStatus GET /admin/v1/auth/sso/status（公开，W3 登录页据此显示 SSO 按钮）。
func ConsoleSSOStatus(svc *consolesso.Service) http.HandlerFunc { return svc.Status }

// ConsoleSSOLogin GET /admin/v1/auth/sso/login（公开，浏览器整页跳转）。
func ConsoleSSOLogin(svc *consolesso.Service) http.HandlerFunc { return svc.Login }

// ConsoleSSOCallback GET /admin/v1/auth/sso/callback（公开，IdP 回调）。
func ConsoleSSOCallback(svc *consolesso.Service) http.HandlerFunc { return svc.Callback }

// ConsoleSSOSession POST /admin/v1/auth/sso/session（公开，一次性票据换会话）。
func ConsoleSSOSession(svc *consolesso.Service) http.HandlerFunc { return svc.Redeem }

// MountConsoleSSOProviders（W9 9.3）挂载 CAS / 企业微信公开入口。未配置的方式入口返回 404。
func MountConsoleSSOProviders(r chi.Router, svc *consolesso.Service, cas consolesso.CASConfig, wecom consolesso.WeComConfig) {
	svc.WithCAS(cas).WithWeCom(wecom)
	r.Get(consolesso.CASLoginPath, svc.CASLogin)
	r.Get(consolesso.CASCallbackPath, svc.CASCallback)
	r.Get(consolesso.WeComLoginPath, svc.WeComLogin)
	r.Get(consolesso.WeComCallbackPath, svc.WeComCallback)
}

// MountConsoleSSOBindings（W9 9.3）在已鉴权路由组内挂载账号绑定管理接口。
func MountConsoleSSOBindings(r chi.Router, deps *Dependencies, svc *consolesso.Service, db *pgxpool.Pool) {
	d := ConsoleSSOBindingDeps{Service: svc, Store: consolesso.NewBindingStore(db), Audit: deps}
	if deps != nil {
		d.Users = deps.UserRepo
	}
	r.Get("/admin/v1/identity/console-sso/bindings", ListConsoleSSOBindings(d))
	r.Post("/admin/v1/identity/console-sso/bindings", CreateConsoleSSOBinding(d))
	r.Delete("/admin/v1/identity/console-sso/bindings/{id}", DeleteConsoleSSOBinding(d))
}
