package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	sessionKeyPrefix     = "session:"
	sessionUserKeyPrefix = "session_user:"
	// sessionIndexBackfillMarkerKey 标记「升级前签发的、没有 session_user 索引条目的旧会话」已被一次性回填进索引。
	// 标记不存在时 DeleteByUser 先做一次全量扫描回填（见 backfillSessionIndex），此后吊销只走索引。
	// 标记故意只活 sessionIndexBackfillMarkerTTL：它同时是定期保险丝——任何原因造成的索引缺陷
	// （滚动升级期间旧版本实例按旧逻辑写出的索引、键被淘汰或误删等）最迟在这个窗口之后的下一次吊销里被全量扫描修复。
	sessionIndexBackfillMarkerKey = "session_index:backfilled"
	sessionIndexBackfillMarkerTTL = time.Hour
	// sessionIndexSuspectID 是放进用户索引里的「索引不完整」哨兵成员（不是真实会话）。见 indexSession 与 DeleteByUser。
	sessionIndexSuspectID = "__index_suspect__"
	// 默认值与 system_settings 的 console_session_* 默认值一致（迁移 880）。
	// 登录时由 handler 按当前系统设置写入 Session.IdleTimeoutSeconds / AbsoluteExpiresAt。
	defaultSessionIdleTimeout     = 30 * time.Minute
	defaultSessionAbsoluteTimeout = 12 * time.Hour
)

// Session represents an admin session.
//
// 过期语义（等保三级）：
//   - ExpiresAt：空闲过期点，每次有效访问后滑动到 min(now+idle, AbsoluteExpiresAt)；
//   - AbsoluteExpiresAt：从登录起算的绝对过期点，活跃也不延长。
//
// 升级前签发的会话没有 AbsoluteExpiresAt / IdleTimeoutSeconds，按 CreatedAt+默认绝对时长、默认空闲时长处理。
type Session struct {
	ID                 string    `json:"id"`
	UserID             string    `json:"user_id"`
	Username           string    `json:"username"`
	Role               string    `json:"role"`
	TenantID           string    `json:"tenant_id,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	ExpiresAt          time.Time `json:"expires_at"`
	AbsoluteExpiresAt  time.Time `json:"absolute_expires_at,omitempty"`
	IdleTimeoutSeconds int       `json:"idle_timeout_seconds,omitempty"`
	IP                 string    `json:"ip,omitempty"`
	// TOTPSetupPending：管理员被要求启用双因素但尚未绑定，只允许访问绑定相关接口。
	TOTPSetupPending bool `json:"totp_setup_pending,omitempty"`
}

func (s *Session) idleTimeout() time.Duration {
	if s.IdleTimeoutSeconds > 0 {
		return time.Duration(s.IdleTimeoutSeconds) * time.Second
	}
	return defaultSessionIdleTimeout
}

func (s *Session) absoluteExpiry() time.Time {
	if !s.AbsoluteExpiresAt.IsZero() {
		return s.AbsoluteExpiresAt
	}
	return s.CreatedAt.Add(defaultSessionAbsoluteTimeout)
}

func (s *Session) nextIdleExpiry(now time.Time) time.Time {
	next := now.Add(s.idleTimeout())
	if abs := s.absoluteExpiry(); next.After(abs) {
		return abs
	}
	return next
}

// indexSession 原子地把会话登记到用户索引：
//
//	KEYS[1]=用户索引键 KEYS[2]=回填标记键
//	ARGV[1]=会话ID ARGV[2]=分数 ARGV[3]=索引键到期点(ms) ARGV[4]=哨兵成员名
//
// 两件事：
//
//  1. 索引键到期点只往后推、不缩短。Create 以前用最后写入的会话的到期时间覆盖它，短寿命会话会把长寿命会话的索引
//     提前过期；之后该用户又登录，索引「非空但不完整」，DeleteByUser 就漏掉仍然存活的旧会话。
//
//  2. 索引键是「新建」的，而回填标记存在（系统早已上线并全库扫描过，此刻不应该有索引外的存活会话）：
//     这意味着该用户的索引键在两次登录之间消失了（被淘汰、被误删、旧版本实例缩短过到期点……），
//     此前签发的存活会话可能不在索引里。放入哨兵成员，DeleteByUser 见到哨兵就不信索引，改走扫描兜底。
//     回填标记不存在时不放哨兵：下一次 DeleteByUser 本来就会先做全量回填。
//
// 不用 EXPIREAT ... GT：go-redis 9.7 没有带参封装；脚本在 Valkey/Redis/miniredis 上行为一致。
var indexSession = redis.NewScript(`
local existed = redis.call('EXISTS', KEYS[1])
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
if existed == 0 and redis.call('EXISTS', KEYS[2]) == 1 then
  redis.call('ZADD', KEYS[1], 0, ARGV[4])
end
local cur = redis.call('PEXPIRETIME', KEYS[1])
local want = tonumber(ARGV[3])
if cur == -1 or cur < want then
  redis.call('PEXPIREAT', KEYS[1], want)
end
return existed`)

// backfillIndexSession 回填用：ZADD NX 语义（已有条目保持原分数）+ 到期点只延不缩，不放哨兵。
var backfillIndexSession = redis.NewScript(`
if redis.call('ZSCORE', KEYS[1], ARGV[1]) == false then
  redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
end
local cur = redis.call('PEXPIRETIME', KEYS[1])
local want = tonumber(ARGV[3])
if cur == -1 or cur < want then
  redis.call('PEXPIREAT', KEYS[1], want)
end
return 1`)

// SessionRepository handles session storage in Redis
type SessionRepository struct {
	client *redis.Client
	now    func() time.Time
}

// NewSessionRepository creates a new session repository
func NewSessionRepository(client *redis.Client) *SessionRepository {
	return &SessionRepository{client: client, now: time.Now}
}

// SetClockForTest 仅供测试注入时钟。
func (r *SessionRepository) SetClockForTest(now func() time.Time) { r.now = now }

func (r *SessionRepository) clock() time.Time {
	if r.now == nil {
		return time.Now()
	}
	return r.now()
}

func (r *SessionRepository) save(ctx context.Context, session *Session) error {
	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("failed to marshal session: %w", err)
	}
	ttl := session.ExpiresAt.Sub(r.clock())
	if ttl <= 0 {
		return r.Delete(ctx, session.ID)
	}
	return r.client.Set(ctx, sessionKeyPrefix+session.ID, data, ttl).Err()
}

// Create creates a new session
func (r *SessionRepository) Create(ctx context.Context, session *Session) error {
	now := r.clock()
	session.CreatedAt = now
	if session.AbsoluteExpiresAt.IsZero() {
		session.AbsoluteExpiresAt = now.Add(defaultSessionAbsoluteTimeout)
	}
	if session.IdleTimeoutSeconds <= 0 {
		session.IdleTimeoutSeconds = int(defaultSessionIdleTimeout / time.Second)
	}
	session.ExpiresAt = session.nextIdleExpiry(now)
	// 先写索引、再写会话本体：若中途失败，最坏是留下一条指向不存在会话的索引条目（ActiveSessionIDs 会清理），
	// 而不是留下一个无法按用户吊销的会话。
	if session.UserID != "" {
		userKey := sessionUserKeyPrefix + session.UserID
		if err := indexSession.Run(ctx, r.client, []string{userKey, sessionIndexBackfillMarkerKey},
			session.ID, float64(now.UnixNano()), session.AbsoluteExpiresAt.Add(time.Minute).UnixMilli(),
			sessionIndexSuspectID).Err(); err != nil {
			return fmt.Errorf("failed to index session: %w", err)
		}
	}
	return r.save(ctx, session)
}

// Get retrieves a session by ID
func (r *SessionRepository) Get(ctx context.Context, sessionID string) (*Session, error) {
	key := sessionKeyPrefix + sessionID
	data, err := r.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, nil // Session not found
		}
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("failed to unmarshal session: %w", err)
	}

	now := r.clock()
	if now.After(session.ExpiresAt) || now.After(session.absoluteExpiry()) {
		_ = r.Delete(ctx, sessionID)
		return nil, nil
	}

	return &session, nil
}

// Delete removes a session
func (r *SessionRepository) Delete(ctx context.Context, sessionID string) error {
	key := sessionKeyPrefix + sessionID
	data, err := r.client.Get(ctx, key).Bytes()
	if err == nil {
		var session Session
		if json.Unmarshal(data, &session) == nil && session.UserID != "" {
			_ = r.client.ZRem(ctx, sessionUserKeyPrefix+session.UserID, sessionID).Err()
		}
	}
	return r.client.Del(ctx, key).Err()
}

// Exists checks if a session exists and is valid
func (r *SessionRepository) Exists(ctx context.Context, sessionID string) bool {
	session, err := r.Get(ctx, sessionID)
	if err != nil || session == nil {
		return false
	}
	return true
}

// Extend slides the idle expiry. It never moves past the absolute expiry.
func (r *SessionRepository) Extend(ctx context.Context, sessionID string) error {
	session, err := r.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	if session == nil {
		return fmt.Errorf("session not found")
	}
	session.ExpiresAt = session.nextIdleExpiry(r.clock())
	return r.save(ctx, session)
}

// ClearTOTPSetupPending lifts the enrollment-only restriction after the user binds TOTP.
func (r *SessionRepository) ClearTOTPSetupPending(ctx context.Context, sessionID string) error {
	session, err := r.Get(ctx, sessionID)
	if err != nil || session == nil {
		return err
	}
	session.TOTPSetupPending = false
	return r.save(ctx, session)
}

// ActiveSessionIDs returns the user's live sessions, oldest first, pruning stale index entries.
func (r *SessionRepository) ActiveSessionIDs(ctx context.Context, userID string) ([]string, error) {
	userKey := sessionUserKeyPrefix + userID
	ids, err := r.client.ZRange(ctx, userKey, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list user sessions: %w", err)
	}
	live := make([]string, 0, len(ids))
	for _, id := range ids {
		s, err := r.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		if s == nil || s.UserID != userID {
			_ = r.client.ZRem(ctx, userKey, id).Err()
			continue
		}
		live = append(live, id)
	}
	return live, nil
}

// EnforceMaxConcurrent 在新会话创建前调用：若该账号已有 >= max 个有效会话，
// 按登录时间从旧到新踢掉，直到留出一个名额。max<=0 表示不限制。返回被踢掉的会话数。
// 选择“踢最旧”而非“拒绝登录”：避免管理员关掉浏览器后因残留会话被锁在门外。
func (r *SessionRepository) EnforceMaxConcurrent(ctx context.Context, userID string, max int) (int, error) {
	if max <= 0 || userID == "" {
		return 0, nil
	}
	live, err := r.ActiveSessionIDs(ctx, userID)
	if err != nil {
		return 0, err
	}
	evicted := 0
	for len(live)-evicted >= max {
		if err := r.Delete(ctx, live[evicted]); err != nil {
			return evicted, err
		}
		evicted++
	}
	return evicted, nil
}

// DeleteByUser removes all sessions that belong to a specific user.
//
// 优先用 session_user:<id> 索引取会话 ID 后批量删除，不再每次全量 SCAN 所有 session:*。
// 删除语义与之前一致：该用户的会话必须删干净，其他用户的会话一条都不能动。
//
// 索引不是权威数据，只是加速手段。只信索引的前提是「索引完整」，靠三层保证，任何一层失守都会落到扫描兜底：
//  1. 索引键的到期点只往后推、不缩短（indexSession），正常路径下索引键只会在其全部成员过期之后才消失。
//  2. 索引键在两次登录之间消失（被淘汰、被误删……）时，Create 重建索引会放入哨兵成员（indexSession）；
//     DeleteByUser 见到哨兵就不信这个索引，先按索引删已知的，再扫描补漏。
//  3. 回填标记只活 sessionIndexBackfillMarkerTTL，是定期保险丝：标记缺失/过期时先全量扫描一次，把没有索引条目的
//     存活会话补进各自用户的索引（覆盖升级前签发的旧会话、滚动升级期间旧版本实例按旧逻辑写出的索引），再按索引删除。
//
// 索引里没有该用户的任何条目时同样扫描兜底（确实没有会话，或索引键丢了，无法区分）。
// 回填/扫描失败都直接返回错误，不假装已吊销。
func (r *SessionRepository) DeleteByUser(ctx context.Context, userID string) error {
	if userID == "" {
		return nil
	}
	marked, err := r.client.Exists(ctx, sessionIndexBackfillMarkerKey).Result()
	if err != nil {
		return fmt.Errorf("failed to read session index marker: %w", err)
	}
	if marked == 0 {
		if err := r.backfillSessionIndex(ctx); err != nil {
			return err
		}
	}
	found, suspect, err := r.deleteIndexedSessions(ctx, userID)
	if err != nil {
		return err
	}
	if found && !suspect {
		return nil
	}
	return r.deleteByScan(ctx, userID)
}

// deleteIndexedSessions 按索引删除某用户的全部会话。每个索引条目都要核对会话确实属于该用户后才删，
// 防止被污染的索引条目连带删掉别人的会话。
// found=false：索引里没有该用户的任何真实条目；suspect=true：索引里带哨兵（索引不完整）。
// 这两种情况调用方都必须扫描兜底；已能确认的会话仍然先按索引删掉，扫描只是补漏。
func (r *SessionRepository) deleteIndexedSessions(ctx context.Context, userID string) (found, suspect bool, err error) {
	userKey := sessionUserKeyPrefix + userID
	ids, err := r.client.ZRange(ctx, userKey, 0, -1).Result()
	if err != nil {
		return false, false, fmt.Errorf("failed to list user sessions: %w", err)
	}
	real := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == sessionIndexSuspectID {
			suspect = true
			continue
		}
		real = append(real, id)
	}
	if len(real) == 0 {
		return false, suspect, nil
	}
	const batch = 200
	for start := 0; start < len(real); start += batch {
		end := start + batch
		if end > len(real) {
			end = len(real)
		}
		chunk := real[start:end]
		keys := make([]string, len(chunk))
		for i, id := range chunk {
			keys[i] = sessionKeyPrefix + id
		}
		values, err := r.client.MGet(ctx, keys...).Result()
		if err != nil {
			return false, suspect, fmt.Errorf("failed to load user sessions: %w", err)
		}
		var toDelete []string
		for i, v := range values {
			raw, ok := v.(string)
			if !ok {
				continue // 会话已过期/不存在：只剩索引条目，随索引键一起清掉
			}
			var session Session
			if json.Unmarshal([]byte(raw), &session) != nil {
				// 无法解析的会话体：旧实现同样跳过（无法确认归属，不删）。
				continue
			}
			if session.UserID == userID {
				toDelete = append(toDelete, keys[i])
			}
		}
		if len(toDelete) > 0 {
			if err := r.client.Del(ctx, toDelete...).Err(); err != nil {
				return false, suspect, fmt.Errorf("failed to delete user sessions: %w", err)
			}
		}
	}
	return true, suspect, r.client.Del(ctx, userKey).Err()
}

// deleteByScan 是索引缺失时的兜底：全量 SCAN session:*，删除属于该用户的会话（旧实现的逻辑，语义不变）。
func (r *SessionRepository) deleteByScan(ctx context.Context, userID string) error {
	var cursor uint64
	for {
		keys, next, err := r.client.Scan(ctx, cursor, sessionKeyPrefix+"*", 200).Result()
		if err != nil {
			return fmt.Errorf("failed to scan sessions: %w", err)
		}
		for _, key := range keys {
			data, err := r.client.Get(ctx, key).Bytes()
			if err != nil {
				if err == redis.Nil {
					continue
				}
				return fmt.Errorf("failed to load session %s: %w", key, err)
			}
			var session Session
			if json.Unmarshal(data, &session) != nil {
				continue
			}
			if session.UserID == userID {
				if err := r.client.Del(ctx, key).Err(); err != nil {
					return fmt.Errorf("failed to delete session %s: %w", key, err)
				}
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return r.client.Del(ctx, sessionUserKeyPrefix+userID).Err()
}

// backfillSessionIndex 一次性全量扫描 session:*，把还没有索引条目的会话补进各自用户的索引，然后写回填标记。
// 这是旧版 DeleteByUser 每次都要做的那一遍扫描，现在只在标记缺失时做一次。
func (r *SessionRepository) backfillSessionIndex(ctx context.Context) error {
	var cursor uint64
	for {
		keys, next, err := r.client.Scan(ctx, cursor, sessionKeyPrefix+"*", 200).Result()
		if err != nil {
			return fmt.Errorf("failed to scan sessions: %w", err)
		}
		for _, key := range keys {
			data, err := r.client.Get(ctx, key).Bytes()
			if err != nil {
				if err == redis.Nil {
					continue
				}
				return fmt.Errorf("failed to load session %s: %w", key, err)
			}
			var session Session
			if json.Unmarshal(data, &session) != nil || session.UserID == "" {
				continue
			}
			userKey := sessionUserKeyPrefix + session.UserID
			score := float64(session.CreatedAt.UnixNano())
			// 补进索引并把索引键到期点只延不缩（与 Create 同一个脚本；回填标记键传空，不放哨兵）。
			if err := backfillIndexSession.Run(ctx, r.client, []string{userKey},
				session.ID, score, session.absoluteExpiry().Add(time.Minute).UnixMilli()).Err(); err != nil {
				return fmt.Errorf("failed to backfill session index: %w", err)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return r.client.Set(ctx, sessionIndexBackfillMarkerKey, "1", sessionIndexBackfillMarkerTTL).Err()
}
