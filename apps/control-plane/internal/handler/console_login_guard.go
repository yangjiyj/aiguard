package handler

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

// 登录失败锁定（等保三级 3.1）：
//   - 按「账号」和「账号+来源IP」两个维度计数，任一达到阈值即锁定账号（账号维度防分布式爆破，
//     账号+IP 维度保证单一来源也被计入）；
//   - 计数窗口 = 锁定时长；锁定期间即使密码正确也拒绝，且不再消耗 bcrypt；
//   - 登录成功清零两类计数。
//
// 计数 key 存 Redis，账号名统一小写，不存在的账号同样计数（避免借锁定行为枚举账号）。
const (
	loginFailAccountPrefix   = "login_fail:acct:"
	loginFailAccountIPPrefix = "login_fail:acctip:"
	loginLockPrefix          = "login_lock:"
	loginFailIPPrefix        = "login_fail:ip:"
	loginLockIPPrefix        = "login_lock:ip:"
	totpUsedPrefix           = "totp_used:"
)

// 统一对外的登录失败提示（3.6：不区分账号不存在/未激活/无密码/密码错）。
const genericLoginFailureMessage = "invalid credentials"

func normalizeLoginName(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// requestClientIP 取客户端地址。control-plane 在 chi middleware.RealIP 之后，
// 且只经 web-console nginx（设置 X-Real-IP）访问，所以 RemoteAddr 已是真实来源。

type loginTransportPeerKey struct{}

// CaptureLoginTransportPeer preserves the socket peer before general proxy
// attribution middleware. Only the fixed service exit allowlist can supply XFF.
func CaptureLoginTransportPeer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), loginTransportPeerKey{}, r.RemoteAddr)))
	})
}
func requestClientIP(r *http.Request) string {
	if strings.TrimSpace(os.Getenv("JJD_CHAT_LOGIN_TRUSTED_PROXY_IPS")) == "" && strings.TrimSpace(os.Getenv("JJD_CHAT_LOGIN_TRUSTED_PROXY_HOSTS")) == "" {
		if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			return host
		}
		return strings.TrimSpace(r.RemoteAddr)
	}
	peer := r.RemoteAddr
	if original, ok := r.Context().Value(loginTransportPeerKey{}).(string); ok {
		peer = original
	}
	if host, _, err := net.SplitHostPort(peer); err == nil {
		peer = host
	}
	peer = strings.TrimSpace(peer)
	trusted := map[string]bool{}
	for _, raw := range strings.Split(os.Getenv("JJD_CHAT_LOGIN_TRUSTED_PROXY_IPS"), ",") {
		if ip := net.ParseIP(strings.TrimSpace(raw)); ip != nil {
			trusted[ip.String()] = true
		}
	}

	// Fixed Docker service names resolve to their current exact exit IPs; no
	// CIDR or arbitrary forwarded value grants trust.
	for _, raw := range strings.Split(os.Getenv("JJD_CHAT_LOGIN_TRUSTED_PROXY_HOSTS"), ",") {
		host := strings.TrimSpace(raw)
		if host == "" || strings.ContainsAny(host, "/:@ *") {
			continue
		}
		for _, ip := range cachedLoginProxyIPs(r.Context(), host) {
			trusted[ip] = true
		}

	}
	parsed := net.ParseIP(peer)
	if parsed == nil || !trusted[parsed.String()] {
		return peer
	}
	raw := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	key := strings.TrimSpace(os.Getenv("JJD_LOGIN_IP_FORWARD_SECRET"))
	timestamp := r.Header.Get("X-JJD-Client-IP-Time")
	stamp, err := strconv.ParseInt(timestamp, 10, 64)
	given, decodeErr := hex.DecodeString(r.Header.Get("X-JJD-Client-IP-Signature"))
	if key == "" || err != nil || decodeErr != nil || time.Since(time.Unix(stamp, 0)) > 90*time.Second || time.Until(time.Unix(stamp, 0)) > 90*time.Second || net.ParseIP(raw) == nil {
		return peer
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte("v1\n" + raw + "\n" + timestamp))
	if !hmac.Equal(given, mac.Sum(nil)) {
		return peer
	}
	return net.ParseIP(raw).String()
}

type loginProxyDNSResult struct {
	ips     []string
	expires time.Time
}

var loginProxyDNSCache = struct {
	sync.Mutex
	hosts map[string]loginProxyDNSResult
}{hosts: map[string]loginProxyDNSResult{}}
var loginProxyLookup = net.DefaultResolver.LookupIPAddr

func cachedLoginProxyIPs(ctx context.Context, host string) []string {
	loginProxyDNSCache.Lock()
	defer loginProxyDNSCache.Unlock()
	now := time.Now()
	if cached, ok := loginProxyDNSCache.hosts[host]; ok && now.Before(cached.expires) {
		return cached.ips
	}
	lookupCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	addresses, err := loginProxyLookup(lookupCtx, host)
	ips := []string{}
	if err == nil {
		for _, address := range addresses {
			ips = append(ips, address.IP.String())
		}
	}
	loginProxyDNSCache.hosts[host] = loginProxyDNSResult{ips: ips, expires: now.Add(time.Minute)}
	return ips
}

type loginGuard struct {
	client *redis.Client
	policy ConsoleLoginPolicy
}

func newLoginGuard(client *redis.Client, policy ConsoleLoginPolicy) *loginGuard {
	return &loginGuard{client: client, policy: policy}
}

func (g *loginGuard) window() time.Duration {
	return time.Duration(g.policy.LockoutMinutes) * time.Minute
}

// lockedFor returns remaining lock time for the account (0 = not locked).
func (g *loginGuard) lockedFor(ctx context.Context, username string, ips ...string) (time.Duration, error) {
	if g.client == nil {
		return 0, nil
	}
	for _, ip := range ips {
		ttl, err := g.client.PTTL(ctx, loginLockIPPrefix+ip).Result()
		if err != nil {
			return 0, err
		}
		if ttl > 0 {
			return ttl, nil
		}
	}
	ttl, err := g.client.PTTL(ctx, loginLockPrefix+normalizeLoginName(username)).Result()
	if err != nil {
		return 0, err
	}
	if ttl > 0 {
		return ttl, nil
	}
	return 0, nil
}

// recordFailure increments counters; returns true when this failure triggered a new lock.
func (g *loginGuard) recordFailure(ctx context.Context, username, ip string) (bool, error) {
	if g.client == nil {
		return false, nil
	}
	name := normalizeLoginName(username)
	window := g.window()
	acctKey := loginFailAccountPrefix + name
	acctIPKey := loginFailAccountIPPrefix + name + "|" + ip
	pipe := g.client.TxPipeline()
	acct := pipe.Incr(ctx, acctKey)
	acctIP := pipe.Incr(ctx, acctIPKey)
	sourceIP := pipe.Incr(ctx, loginFailIPPrefix+ip)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, err
	}
	// 窗口从第一次失败起算：只在计数为 1 时设置过期。
	if acct.Val() == 1 {
		_ = g.client.Expire(ctx, acctKey, window).Err()
	}
	if acctIP.Val() == 1 {
		_ = g.client.Expire(ctx, acctIPKey, window).Err()
	}
	if sourceIP.Val() == 1 {
		_ = g.client.Expire(ctx, loginFailIPPrefix+ip, window).Err()
	}
	threshold := int64(g.policy.LockoutThreshold)
	ipThreshold := threshold * 10
	if ipThreshold < 50 {
		ipThreshold = 50
	}
	if sourceIP.Val() >= ipThreshold {
		_, err := g.client.SetNX(ctx, loginLockIPPrefix+ip, "1", window).Result()
		if err != nil {
			return false, err
		}
	}
	if acct.Val() >= threshold || acctIP.Val() >= threshold {
		set, err := g.client.SetNX(ctx, loginLockPrefix+name, "1", window).Result()
		if err != nil {
			return false, err
		}
		return set, nil
	}
	return false, nil
}

func (g *loginGuard) reset(ctx context.Context, username, ip string) {
	if g.client == nil {
		return
	}
	name := normalizeLoginName(username)
	_ = g.client.Del(ctx, loginFailAccountPrefix+name, loginFailAccountIPPrefix+name+"|"+ip).Err()
}

// Unlock clears lock and counters (admin action).
func (g *loginGuard) Unlock(ctx context.Context, username string, tenants ...string) error {
	if g.client == nil {
		return nil
	}
	name := normalizeLoginName(username)
	names := []string{name}
	for _, tenant := range tenants {
		names = append(names, "employee:"+tenant+"\x00"+name)
	}
	escape := strings.NewReplacer("\\", "\\\\", "*", "\\*", "?", "\\?", "[", "\\[", "]", "\\]")
	for _, n := range names {
		patterns := []string{loginFailAccountIPPrefix + escape.Replace(n) + "|*", loginFailAccountPrefix + escape.Replace(n) + "|source:*", loginLockPrefix + escape.Replace(n) + "|source:*"}
		for _, pattern := range patterns {
			var cursor uint64
			for {
				keys, next, err := g.client.Scan(ctx, cursor, pattern, 100).Result()
				if err != nil {
					return err
				}
				if len(keys) > 0 {
					if err = g.client.Del(ctx, keys...).Err(); err != nil {
						return err
					}
				}
				cursor = next
				if cursor == 0 {
					break
				}
			}
		}
		if err := g.client.Del(ctx, loginLockPrefix+n, loginFailAccountPrefix+n).Err(); err != nil {
			return err
		}
	}
	return nil
}

// consumeTOTPStep prevents replaying the same code within its validity window.
func consumeTOTPStep(ctx context.Context, client *redis.Client, userID string, counter uint64) (bool, error) {
	if client == nil {
		return true, nil
	}
	key := totpUsedPrefix + userID
	prev, err := client.Get(ctx, key).Uint64()
	if err != nil && err != redis.Nil {
		return false, err
	}
	if err == nil && counter <= prev {
		return false, nil
	}
	return true, client.Set(ctx, key, counter, time.Duration(totpPeriod*(2*totpSkew+2))*time.Second).Err()
}

var (
	dummyBcryptOnce sync.Once
	dummyBcryptHash []byte
)

// equalizeBcryptCost 在账号不存在/不可用时执行一次同成本的 bcrypt 比对，消除计时差异（3.6）。
func equalizeBcryptCost(password string) {
	dummyBcryptOnce.Do(func() {
		dummyBcryptHash, _ = bcrypt.GenerateFromPassword([]byte("jjdguard-timing-equalizer"), bcrypt.DefaultCost)
	})
	_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
}

// isConsoleAdminRole：IP 白名单与强制双因素对所有能登录控制台的角色生效（含三员）——
// 放宽登录边界不能产生更弱的登录路径。注意它不是授权判定；授权档见 roles.IsConsoleAdministrator。
func isConsoleAdminRole(role string) bool { return roles.RequiresLoginHardening(role) }

// ipAllowed：空列表 = 不限制。非法条目在写入时已拒绝；读取时忽略。
func ipAllowed(allowlist []string, ip string) bool {
	if len(allowlist) == 0 {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, entry := range allowlist {
		if !strings.Contains(entry, "/") {
			if other := net.ParseIP(entry); other != nil && other.Equal(parsed) {
				return true
			}
			continue
		}
		if _, network, err := net.ParseCIDR(entry); err == nil && network.Contains(parsed) {
			return true
		}
	}
	return false
}
