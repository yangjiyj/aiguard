package handler

import (
	"context"
	"errors"
	"os"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/proxywhitelist"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"github.com/jackc/pgx/v5/pgxpool"
)

type WhitelistChecker struct {
	db              *pgxpool.Pool
	controlPlaneURL string
	cache           sync.Map
	cacheExpiry     time.Duration
	store           WhitelistStore
	tenantID        string
	failMode        string
	// settingsValues 返回控制台的正向代理设置（未登记目标、白名单读取失败的处置）；
	// nil 或缺键时回落到部署环境变量与默认（拒绝）。
	settingsValues func(context.Context) map[string]string
}

type WhitelistEntry struct {
	HostPattern  string
	TenantID     string
	AuditEnabled bool
}

func NewWhitelistChecker(db *pgxpool.Pool, controlPlaneURL string) *WhitelistChecker {
	return NewWhitelistCheckerWithPolicy(db, controlPlaneURL, os.Getenv("PROXY_DEFAULT_TENANT_ID"), os.Getenv("PROXY_WHITELIST_FAIL_MODE"))
}

func NewWhitelistCheckerWithPolicy(db *pgxpool.Pool, controlPlaneURL, tenantID, failMode string) *WhitelistChecker {
	w := &WhitelistChecker{db: db, controlPlaneURL: controlPlaneURL, cacheExpiry: 5 * time.Minute, tenantID: proxywhitelist.Tenant(tenantID), failMode: failMode}
	if db != nil {
		w.store = &dbWhitelistStore{db: db, tenantID: w.tenantID}
	}
	return w
}

type whitelistDecision struct {
	Outcome  securityexit.Outcome
	Audit    bool
	TenantID string
	Reason   string
}

func (w *WhitelistChecker) decide(ctx context.Context, host string, port int, mode securityexit.Mode) whitelistDecision {
	tenantID := "tenant_default"
	if w != nil {
		tenantID = proxywhitelist.Tenant(w.tenantID)
	}
	d := whitelistDecision{Audit: true, TenantID: tenantID}
	var rules []WhitelistRule
	var err error
	if w == nil || w.store == nil {
		err = errors.New("proxy whitelist store unavailable")
	} else {
		rules, err = w.loadRules(ctx)
	}
	if err != nil {
		d.Outcome = securityexit.DecideWithPolicy(mode, "block", securityexit.DetectionFailure, securityexit.Policy{FailClosedOnDetectionFailure: w.runtimeFailureMode(ctx) == egresspolicy.FailClosed})
		d.Reason = "proxy_whitelist_unavailable"
		return d
	}
	matched, count := proxywhitelist.Match(rules, tenantID, host, port)
	if count == 0 {
		d.Outcome = securityexit.DecideWithPolicy(mode, "audit", securityexit.DetectionFailure, securityexit.Policy{})
		d.Reason = "proxy_whitelist_empty"
		return d
	}
	if matched != nil {
		d.Audit = matched.AuditEnabled
		d.Outcome = securityexit.DecideWithPolicy(mode, "allow", securityexit.ToolPolicy, securityexit.Policy{})
		return d
	}
	d.Reason = "proxy_whitelist_unlisted"
	if egresspolicy.UnlistedAction(w.consoleValues(ctx), "") == egresspolicy.UnlistedAllowAudit {
		// 控制台把未登记目标设为放行审计：不拦，记一条缺口。
		d.Outcome = securityexit.DecideWithPolicy(mode, "audit", securityexit.DetectionFailure, securityexit.Policy{})
		return d
	}
	d.Outcome = securityexit.DecideWithPolicy(mode, "block", securityexit.ToolPolicy, securityexit.Policy{})
	return d
}

func (w *WhitelistChecker) consoleValues(ctx context.Context) map[string]string {
	if w == nil || w.settingsValues == nil {
		return nil
	}
	return w.settingsValues(ctx)
}

// runtimeFailureMode 是白名单读取失败的处置：控制台设置（proxy_whitelist_fail_mode）优先；
// 库里没有该键时才用部署环境变量 PROXY_WHITELIST_FAIL_MODE 作初值；默认 closed。
func (w *WhitelistChecker) runtimeFailureMode(ctx context.Context) string {
	mode := os.Getenv("PROXY_WHITELIST_FAIL_MODE")
	if w != nil && w.failMode != "" {
		mode = w.failMode
	}
	return egresspolicy.WhitelistFailMode(w.consoleValues(ctx), mode)
}

// Check preserves the administrative checker API; request handlers supply the
// effective audit-only mode through decide before interrupting traffic.
func (w *WhitelistChecker) Check(target string) (bool, bool, string) {
	host, port := proxywhitelist.Target(target, 443)
	d := w.decide(context.Background(), host, port, securityexit.Protect)
	return !d.Outcome.Enforce, d.Audit, d.TenantID
}

func (w *WhitelistChecker) matchPattern(pattern, host string) bool {
	return proxywhitelist.MatchesHost(pattern, host)
}

type WhitelistRule = proxywhitelist.Rule
type WhitelistStore interface {
	ListRules(ctx context.Context) ([]WhitelistRule, error)
}
type whitelistCacheEntry struct {
	rules     []WhitelistRule
	expiresAt time.Time
}

const whitelistRulesCacheKey = "__whitelist_rules__"

func (w *WhitelistChecker) loadRules(ctx context.Context) ([]WhitelistRule, error) {
	cacheKey := whitelistRulesCacheKey + ":" + proxywhitelist.Tenant(w.tenantID)
	if cached, ok := w.cache.Load(cacheKey); ok {
		entry := cached.(*whitelistCacheEntry)
		if time.Now().Before(entry.expiresAt) {
			return entry.rules, nil
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	rules, err := w.store.ListRules(ctx)
	if err != nil {
		return nil, err
	}
	w.cache.Store(cacheKey, &whitelistCacheEntry{rules: rules, expiresAt: time.Now().Add(w.cacheExpiry)})
	return rules, nil
}

type dbWhitelistStore struct {
	db       *pgxpool.Pool
	tenantID string
}

func (s *dbWhitelistStore) ListRules(ctx context.Context) ([]WhitelistRule, error) {
	return (proxywhitelist.Store{DB: s.db}).ListRules(ctx, s.tenantID)
}
