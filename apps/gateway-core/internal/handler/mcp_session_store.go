package handler

// Streamable HTTP 上游的 Mcp-Session-Id 归属绑定（验收缺陷 D3）。
//
// 背景：Streamable 路径原样转发客户端带来的 Mcp-Session-Id，网关不知道这个 id 是不是上游签发的、
// 是不是这个调用方的。恶意或出错的客户端可以伪造/猜测他人的会话 id，借此接入别人在上游的会话状态。
//
// 做法：网关在 initialize 响应里「见到」上游签发的 Mcp-Session-Id 时，把它和
// (租户, server, 主体, 路由指纹) 绑定登记；之后任何带会话 id 的请求都必须命中登记且归属一致，
// 否则按规范回 404（客户端据此重新 initialize），不转发，审计 execution_forwarded=false。
//
// 存储：
//   - 默认进程内存（单副本）：总量、单主体、空闲 TTL、绝对寿命都有界；进程重启即清空，旧会话 404。
//   - 多副本：设置 MCP_SESSION_STORE=redis 改用共享 Redis（网关本来就依赖 Redis），key 为
//     (租户,server,会话id) 的 SHA-256，会话 id 不明文落库；带 TTL，绝对寿命在值里校验。
//     内存表在多副本下不够：initialize 落在副本 A、后续请求被负载均衡到副本 B 会被误判为未知会话。
//   - 校验后端出错一律 fail-closed（503，不转发），不放行未经验证的 id。

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// errMCPSessionTableFull 表示会话登记表已满且没有可回收的空闲会话，拒绝新登记。
var errMCPSessionTableFull = errors.New("MCP 会话登记表已满，已拒绝新会话")

const (
	mcpSessionMaxTotal        = 4096
	mcpSessionMaxPerPrincipal = 64
	mcpSessionIdleTTL         = 30 * time.Minute
	mcpSessionMaxLifetime     = 24 * time.Hour
	mcpSessionRedisPrefix     = "mcp:sess:v1:"
)

// mcpSessionBinding 是一条已登记会话的归属信息。
type mcpSessionBinding struct {
	Principal string    `json:"p"`
	RouteHash string    `json:"r"`
	CreatedAt time.Time `json:"c"`
}

// mcpSessionStore 抽象会话登记表；实现必须并发安全。
type mcpSessionStore interface {
	Put(ctx context.Context, tenantID, serverID, sessionID string, b mcpSessionBinding) error
	// Get 命中时同时刷新空闲计时；过期/不存在返回 ok=false。
	Get(ctx context.Context, tenantID, serverID, sessionID string) (mcpSessionBinding, bool, error)
	Delete(ctx context.Context, tenantID, serverID, sessionID string) error
}

type memSessionEntry struct {
	binding  mcpSessionBinding
	lastSeen time.Time
	// seq 是登记顺序号：淘汰「最旧」按它判定。不能用时间戳——同一时钟刻度内登记的多条会话时间相同，
	// 配合 map 遍历的随机顺序会淘汰错误的一条。
	seq uint64
}

// mcpMemorySessionStore 是进程内的有界实现。
type mcpMemorySessionStore struct {
	mu              sync.Mutex
	entries         map[string]*memSessionEntry
	nextSeq         uint64
	now             func() time.Time
	maxTotal        int
	maxPerPrincipal int
	idleTTL         time.Duration
	maxLifetime     time.Duration
}

func newMCPMemorySessionStore() *mcpMemorySessionStore {
	return &mcpMemorySessionStore{
		entries: map[string]*memSessionEntry{}, now: time.Now,
		maxTotal: mcpSessionMaxTotal, maxPerPrincipal: mcpSessionMaxPerPrincipal,
		idleTTL: mcpSessionIdleTTL, maxLifetime: mcpSessionMaxLifetime,
	}
}

func mcpSessionKey(tenantID, serverID, sessionID string) string {
	return tenantID + "\x1f" + serverID + "\x1f" + sessionID
}

func (s *mcpMemorySessionStore) expiredLocked(e *memSessionEntry, now time.Time) bool {
	return now.Sub(e.lastSeen) > s.idleTTL || now.Sub(e.binding.CreatedAt) > s.maxLifetime
}

func (s *mcpMemorySessionStore) purgeLocked(now time.Time) {
	for k, e := range s.entries {
		if s.expiredLocked(e, now) {
			delete(s.entries, k)
		}
	}
}

func (s *mcpMemorySessionStore) evictOldestLocked(match func(*memSessionEntry) bool) {
	var oldestKey string
	var oldestSeq uint64
	for k, e := range s.entries {
		if !match(e) {
			continue
		}
		if oldestKey == "" || e.seq < oldestSeq {
			oldestKey, oldestSeq = k, e.seq
		}
	}
	if oldestKey != "" {
		delete(s.entries, oldestKey)
	}
}

func (s *mcpMemorySessionStore) Put(_ context.Context, tenantID, serverID, sessionID string, b mcpSessionBinding) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	if b.CreatedAt.IsZero() {
		b.CreatedAt = now
	}
	s.purgeLocked(now)
	key := mcpSessionKey(tenantID, serverID, sessionID)
	if _, exists := s.entries[key]; !exists {
		count := 0
		for _, e := range s.entries {
			if e.binding.Principal == b.Principal {
				count++
			}
		}
		if count >= s.maxPerPrincipal {
			s.evictOldestLocked(func(e *memSessionEntry) bool { return e.binding.Principal == b.Principal })
		}
		// 复审 M-4：全局写满时绝不淘汰其他主体的会话——否则攻击者用多个 key 灌满表就能挤掉受害者的合法会话。
		// 空闲超时的已在上面 purge 回收过；仍然满就拒绝这次新登记（调用方返回 503 并写日志），
		// 每主体上限保持不变（只淘汰该主体自己最旧的一条）。
		if len(s.entries) >= s.maxTotal {
			return errMCPSessionTableFull
		}
	}
	s.nextSeq++
	s.entries[key] = &memSessionEntry{binding: b, lastSeen: now, seq: s.nextSeq}
	return nil
}

func (s *mcpMemorySessionStore) Get(_ context.Context, tenantID, serverID, sessionID string) (mcpSessionBinding, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := mcpSessionKey(tenantID, serverID, sessionID)
	e := s.entries[key]
	if e == nil {
		return mcpSessionBinding{}, false, nil
	}
	now := s.now()
	if s.expiredLocked(e, now) {
		delete(s.entries, key)
		return mcpSessionBinding{}, false, nil
	}
	e.lastSeen = now
	return e.binding, true, nil
}

func (s *mcpMemorySessionStore) Delete(_ context.Context, tenantID, serverID, sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, mcpSessionKey(tenantID, serverID, sessionID))
	return nil
}

func (s *mcpMemorySessionStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

// mcpSessionKV 是共享存储需要的最小键值能力（生产为 Redis）。
type mcpSessionKV interface {
	Set(ctx context.Context, key, value string, ttl time.Duration) error
	Get(ctx context.Context, key string) (string, bool, error)
	Del(ctx context.Context, key string) error
}

// mcpSharedSessionStore 是多副本共用的实现。
type mcpSharedSessionStore struct {
	kv          mcpSessionKV
	idleTTL     time.Duration
	maxLifetime time.Duration
	now         func() time.Time
}

func newMCPSharedSessionStore(kv mcpSessionKV) *mcpSharedSessionStore {
	return &mcpSharedSessionStore{kv: kv, idleTTL: mcpSessionIdleTTL, maxLifetime: mcpSessionMaxLifetime, now: time.Now}
}

func mcpSharedSessionKey(tenantID, serverID, sessionID string) string {
	sum := sha256.Sum256([]byte(mcpSessionKey(tenantID, serverID, sessionID)))
	return mcpSessionRedisPrefix + hex.EncodeToString(sum[:])
}

func (s *mcpSharedSessionStore) Put(ctx context.Context, tenantID, serverID, sessionID string, b mcpSessionBinding) error {
	if b.CreatedAt.IsZero() {
		b.CreatedAt = s.now()
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return err
	}
	return s.kv.Set(ctx, mcpSharedSessionKey(tenantID, serverID, sessionID), string(raw), s.idleTTL)
}

func (s *mcpSharedSessionStore) Get(ctx context.Context, tenantID, serverID, sessionID string) (mcpSessionBinding, bool, error) {
	key := mcpSharedSessionKey(tenantID, serverID, sessionID)
	raw, ok, err := s.kv.Get(ctx, key)
	if err != nil || !ok {
		return mcpSessionBinding{}, false, err
	}
	var b mcpSessionBinding
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return mcpSessionBinding{}, false, err
	}
	if s.now().Sub(b.CreatedAt) > s.maxLifetime {
		_ = s.kv.Del(ctx, key)
		return mcpSessionBinding{}, false, nil
	}
	_ = s.kv.Set(ctx, key, raw, s.idleTTL) // 刷新空闲 TTL；失败不影响本次校验结论
	return b, true, nil
}

func (s *mcpSharedSessionStore) Delete(ctx context.Context, tenantID, serverID, sessionID string) error {
	return s.kv.Del(ctx, mcpSharedSessionKey(tenantID, serverID, sessionID))
}

// redisSessionKV 把 go-redis 适配为 mcpSessionKV。
type redisSessionKV struct{ client *redis.Client }

func (r redisSessionKV) Set(ctx context.Context, key, value string, ttl time.Duration) error {
	return r.client.Set(ctx, key, value, ttl).Err()
}

func (r redisSessionKV) Get(ctx context.Context, key string) (string, bool, error) {
	v, err := r.client.Get(ctx, key).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	return v, err == nil, err
}

func (r redisSessionKV) Del(ctx context.Context, key string) error {
	return r.client.Del(ctx, key).Err()
}

// NewMCPRedisSessionStore 构造多副本共享的会话登记表（MCP_SESSION_STORE=redis 时由 main 注入）。
func NewMCPRedisSessionStore(client *redis.Client) mcpSessionStore {
	return newMCPSharedSessionStore(redisSessionKV{client: client})
}
