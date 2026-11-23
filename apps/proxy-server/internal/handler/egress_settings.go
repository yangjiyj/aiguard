package handler

import (
	"context"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/yangjiyj/aiguard/packages/shared-go/egresspolicy"
	"github.com/yangjiyj/aiguard/packages/shared-go/proxywhitelist"
	"github.com/yangjiyj/aiguard/packages/shared-go/securityexit"
	"github.com/jackc/pgx/v5/pgxpool"
)

// egressSettingsTTL 与文件 DLP 开关一致：控制台保存后 10 秒内生效。
const egressSettingsTTL = 10 * time.Second

// egressSettingsReadTimeout 是一次读库的上限（与调用方的请求无关）。
const egressSettingsReadTimeout = 2 * time.Second

// EgressSettingsReader 从 system_settings 读正向代理出站设置（egresspolicy.Keys），带只读缓存。
// 读路径不加锁：缓存过期时先返回上一次的值，同时只发起一次后台刷新；从没读到过时等这次刷新。
// 读库失败时沿用上一次读到的值；从没读到过时返回 nil（开关全部拒绝，处置回落到部署环境变量）。
type EgressSettingsReader struct {
	load func(context.Context) (map[string]string, error)
	ttl  time.Duration

	cache atomic.Pointer[egressSettingsSnapshot]

	mu         sync.Mutex
	refreshing chan struct{} // 刷新进行中时非空，刷新结束时关闭（同一时刻只有一次刷新）
}

type egressSettingsSnapshot struct {
	values   map[string]string
	expireAt time.Time
}

// NewEgressSettingsReaderFromPool 用控制平面库构造读取器；db 为 nil 时返回 nil。
func NewEgressSettingsReaderFromPool(db *pgxpool.Pool) *EgressSettingsReader {
	if db == nil {
		return nil
	}
	return &EgressSettingsReader{ttl: egressSettingsTTL, load: func(ctx context.Context) (map[string]string, error) {
		rows, err := db.Query(ctx, `SELECT key, value FROM system_settings WHERE key = ANY($1)`, egresspolicy.Keys)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		values := map[string]string{}
		for rows.Next() {
			var key, value string
			if err := rows.Scan(&key, &value); err != nil {
				return nil, err
			}
			values[key] = value
		}
		return values, rows.Err()
	}}
}

// Values 返回当前设置；nil 读取器返回 nil。
func (r *EgressSettingsReader) Values(ctx context.Context) map[string]string {
	if r == nil || r.load == nil {
		return nil
	}
	snapshot := r.cache.Load()
	if snapshot != nil && time.Now().Before(snapshot.expireAt) {
		return snapshot.values
	}
	done := r.refresh(ctx)
	if snapshot != nil {
		return snapshot.values
	}
	select {
	case <-done:
	case <-ctx.Done():
	}
	if snapshot = r.cache.Load(); snapshot != nil {
		return snapshot.values
	}
	return nil
}

// refresh 发起一次后台读库（已有刷新在跑时复用它），返回刷新结束时关闭的通道。读库用独立的 ctx：
// 调用方的请求结束或取消不打断它，最多 egressSettingsReadTimeout。
func (r *EgressSettingsReader) refresh(ctx context.Context) <-chan struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.refreshing != nil {
		return r.refreshing
	}
	done := make(chan struct{})
	r.refreshing = done
	readCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), egressSettingsReadTimeout)
	go func() {
		defer cancel()
		values, err := r.load(readCtx)
		next := &egressSettingsSnapshot{values: values, expireAt: time.Now().Add(r.ttl)}
		if err != nil {
			log.Printf("Forward proxy egress settings unavailable, keeping previous values: %v", err)
			next.values = nil
			if previous := r.cache.Load(); previous != nil {
				next.values = previous.values
			}
		}
		r.cache.Store(next)
		r.mu.Lock()
		r.refreshing = nil
		r.mu.Unlock()
		close(done)
	}()
	return done
}

// Settings 解析防跳板出站设置；某个键的值格式不对时只丢这个键（按默认拒绝），其余照常。
func (r *EgressSettingsReader) Settings(ctx context.Context) egresspolicy.Settings {
	settings, err := egresspolicy.FromValues(r.Values(ctx))
	if err != nil {
		log.Printf("Forward proxy egress settings partly invalid, the bad keys stay at their defaults: %v", err)
	}
	return settings
}

// WithEgressSettings 把出站设置接到出站守卫和白名单判定上（cmd/server 装配时调用）。
func (h *ProxyHandler) WithEgressSettings(reader *EgressSettingsReader) *ProxyHandler {
	if reader == nil {
		return h
	}
	h.currentEgressGuard().SetSettingsSource(reader.Settings)
	if h.whitelistChecker != nil {
		h.whitelistChecker.settingsValues = reader.Values
	}
	return h
}

// guardEgressTarget 在建隧道、转发前按防跳板出站设置预检目标：拒绝时记安全事件并回 403
// （观察留痕也照拒，与拨号时的判定一致）；因设置放行内部地址时记一条放行事件。启用上层
// 出网代理时目标由上层代理解析，这里不预检（拨号时只校验代理那一跳）。DNS 失败不在这里
// 处理，留给拨号报原来的错误。返回 false 表示已写响应。
func (h *ProxyHandler) guardEgressTarget(w http.ResponseWriter, r *http.Request, targetHost string, defaultPort int, tenantID string) bool {
	guard := h.currentEgressGuard()
	if guard.upstreamProxy != nil {
		return true
	}
	address := targetHost
	if _, _, err := net.SplitHostPort(targetHost); err != nil {
		address = net.JoinHostPort(proxywhitelist.Host(targetHost), strconv.Itoa(defaultPort))
	}
	target, err := guard.Resolve(r.Context(), address)
	if err != nil {
		if !isBlockedEgress(err) {
			return true
		}
		h.recordWhitelistAudit(r, targetHost, whitelistDecision{
			TenantID: tenantID, Audit: true, Reason: egresspolicy.ReasonInternalEgressDenied,
			Outcome: securityexit.Outcome{Enforce: true, Action: "block"},
		})
		http.Error(w, "egress target not allowed", http.StatusForbidden)
		return false
	}
	if target.ViaSetting {
		h.recordWhitelistAudit(r, targetHost, whitelistDecision{
			TenantID: tenantID, Audit: true, Reason: egresspolicy.ReasonInternalEgressAllowed,
			Outcome: securityexit.Outcome{Action: "audit"},
		})
	}
	return true
}
