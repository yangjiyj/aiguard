package repository

// High-2：DeleteByUser 在「索引键提前过期」后漏掉仍然存活的会话。
//
// 复现：S1 寿命 12h、S2 寿命 1h。Create 每次都用「最后写入的会话」的绝对到期时间去 EXPIREAT 索引键，
// S2 把索引的到期点从 12h 缩到 1h。2h 后索引键过期，S1 仍然存活（会话本体是独立的 key）。
// 此时再登录产生 S3，索引里只有 S3；DeleteByUser 看到索引非空，就不走扫描兜底，S1 被漏删——
// 改密/禁用/改角色之后，用户的旧会话依然可用。
//
// 修复后必须满足：索引键的到期点取所有成员中最晚的绝对到期时间；并且不能只看「索引是否为空」来决定是否扫描。
// miniredis 与真实 Valkey 各跑一遍（REDIS_TEST_ADDR + REDIS_TEST_ALLOW_FLUSH=1）。

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// h2Env 同时推进仓储时钟与（若是 miniredis）服务端时钟；真实 Valkey 用绝对到期点，时钟用真实时间 + 偏移。
type h2Env struct {
	repo   *SessionRepository
	client *redis.Client
	mr     *miniredis.Miniredis
	now    time.Time
	real   bool
}

func newH2Env(t *testing.T) *h2Env {
	t.Helper()
	e := &h2Env{now: time.Now().UTC().Truncate(time.Second)}
	if addr := realRedisAddr(t); addr != "" {
		e.client = redis.NewClient(&redis.Options{Addr: addr})
		e.real = true
		t.Cleanup(func() { e.client.FlushDB(context.Background()); e.client.Close() })
	} else {
		e.mr = miniredis.RunT(t)
		e.mr.SetTime(e.now)
		e.client = redis.NewClient(&redis.Options{Addr: e.mr.Addr()})
		t.Cleanup(func() { e.client.Close() })
	}
	e.repo = NewSessionRepository(e.client)
	e.repo.SetClockForTest(func() time.Time { return e.now })
	return e
}

// realRedisAddr 返回真实库地址；未设置返回空（用 miniredis）。设置了地址但没允许 FLUSHDB 就跳过。
func realRedisAddr(t *testing.T) string {
	addr := envOr("REDIS_TEST_ADDR")
	if addr == "" {
		return ""
	}
	if envOr("REDIS_TEST_ALLOW_FLUSH") != "1" {
		t.Skip("REDIS_TEST_ADDR 已设置但未设置 REDIS_TEST_ALLOW_FLUSH=1：真实库测试会 FLUSHDB，只允许一次性容器")
	}
	c := redis.NewClient(&redis.Options{Addr: addr})
	defer c.Close()
	if err := c.FlushDB(context.Background()).Err(); err != nil {
		t.Fatal(err)
	}
	return addr
}

func (e *h2Env) login(t *testing.T, id, user string, lifetime time.Duration) {
	t.Helper()
	s := &Session{ID: id, UserID: user, Username: user, Role: "security_officer", TenantID: "t1",
		AbsoluteExpiresAt: e.now.Add(lifetime), IdleTimeoutSeconds: int(lifetime / time.Second)}
	if err := e.repo.Create(context.Background(), s); err != nil {
		t.Fatal(err)
	}
}

// advance 把时间向前推进 d。miniredis：直接推进服务端 TTL。真实 Valkey 无法快进，改成等价模拟：
// 按新的 e.now 检查每个 key 的绝对到期点（PEXPIRETIME），已经过期的立即删除——和服务端自然过期的可见结果一致。
func (e *h2Env) advance(d time.Duration) {
	e.now = e.now.Add(d)
	if e.mr != nil {
		e.mr.SetTime(e.now)
		e.mr.FastForward(d)
		return
	}
	ctx := context.Background()
	var cursor uint64
	for {
		keys, next, err := e.client.Scan(ctx, cursor, "*", 200).Result()
		if err != nil {
			panic(err)
		}
		for _, k := range keys {
			if ms := e.client.PExpireTime(ctx, k).Val(); ms > 0 && ms.Milliseconds() <= 0 {
				continue
			}
			at := e.client.Do(ctx, "PEXPIRETIME", k).Val()
			if v, ok := at.(int64); ok && v > 0 && v <= e.now.UnixMilli() {
				e.client.Del(ctx, k)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
}

func (e *h2Env) alive(id string) bool {
	return e.client.Exists(context.Background(), sessionKeyPrefix+id).Val() == 1
}

// 用户可见后果：S1(12h)、S2(1h)；2h 后索引键过期而 S1 仍存活；再登录 S3；DeleteByUser 不能漏掉 S1。
func TestDeleteByUserDoesNotMissLiveSessionsWhenTheIndexKeyExpiredEarly(t *testing.T) {
	e := newH2Env(t)
	ctx := context.Background()
	// 线上稳态：升级后的一次性回填早已完成（标记存在），之后的吊销只走索引。
	// 不先做这一步，第一次 DeleteByUser 会顺手做一次全量回填扫描，恰好救下 S1，掩盖问题。
	if err := e.repo.DeleteByUser(ctx, "__settle__"); err != nil {
		t.Fatal(err)
	}
	e.login(t, "S1", "alice", 12*time.Hour)
	e.login(t, "S2", "alice", 1*time.Hour)

	e.advance(2 * time.Hour)
	if !e.alive("S1") {
		t.Fatal("前置条件：2h 后 S1（12h 寿命）应仍然存活")
	}
	if e.alive("S2") {
		t.Fatal("前置条件：2h 后 S2（1h 寿命）应已过期")
	}

	e.login(t, "S3", "alice", 12*time.Hour)
	if err := e.repo.DeleteByUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"S1", "S3"} {
		if e.alive(id) {
			t.Fatalf("DeleteByUser 之后 %s 仍然存活：吊销漏掉了仍然有效的旧会话", id)
		}
	}
}

// 根因层：索引键的到期点必须是所有成员中最晚的绝对到期时间，后写入的短寿命会话不能把它缩短。
func TestSessionIndexKeyExpiryNeverShrinksBelowTheLatestMemberExpiry(t *testing.T) {
	e := newH2Env(t)
	ctx := context.Background()
	e.login(t, "S1", "alice", 12*time.Hour)
	e.login(t, "S2", "alice", 1*time.Hour)
	remaining := e.client.ExpireTime(ctx, sessionUserKeyPrefix+"alice").Val() - time.Duration(e.now.Unix())*time.Second
	if remaining < 12*time.Hour {
		t.Fatalf("索引键到期点被后写入的短寿命会话缩短了：剩余 %v，应不小于 12h", remaining)
	}
	// 反过来，更长寿命的会话要能延长它。
	e.login(t, "S4", "alice", 24*time.Hour)
	remaining = e.client.ExpireTime(ctx, sessionUserKeyPrefix+"alice").Val() - time.Duration(e.now.Unix())*time.Second
	if remaining < 24*time.Hour {
		t.Fatalf("更长寿命的会话应能延长索引到期点：剩余 %v", remaining)
	}
}

// 索引键因任何原因提前消失/过期（TTL 缺失、被淘汰、被误删）后，下一次登录会让索引「非空但不完整」。
// 不能因为索引非空就相信它：无论走哪条失败路径都不能漏删。
func TestDeleteByUserDoesNotTrustANonEmptyButIncompleteIndex(t *testing.T) {
	e := newH2Env(t)
	ctx := context.Background()
	if err := e.repo.DeleteByUser(ctx, "__settle__"); err != nil {
		t.Fatal(err)
	}
	e.login(t, "S1", "bob", 12*time.Hour)
	// 模拟索引键提前丢失：直接删掉索引键，会话本体仍在。
	if err := e.client.Del(ctx, sessionUserKeyPrefix+"bob").Err(); err != nil {
		t.Fatal(err)
	}
	e.login(t, "S3", "bob", 12*time.Hour) // 索引里现在只有 S3
	if err := e.repo.DeleteByUser(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if e.alive("S1") || e.alive("S3") {
		t.Fatalf("索引非空但不完整时漏删：S1=%v S3=%v", e.alive("S1"), e.alive("S3"))
	}
}

// 改密、禁用、角色变更三条吊销路径都落到 DeleteByUser；这里用同一个会话仓储证明：
// 无论哪种原因触发，该用户的全部旧会话（含索引已缺失的）都失效，其他用户不受影响。
func TestDeleteByUserRevokesAllOldSessionsForPasswordDisableAndRoleChange(t *testing.T) {
	for _, reason := range []string{"改密码", "禁用账号", "角色变更"} {
		t.Run(reason, func(t *testing.T) {
			e := newH2Env(t)
			ctx := context.Background()
			if err := e.repo.DeleteByUser(ctx, "__settle__"); err != nil {
				t.Fatal(err)
			}
			e.login(t, "A-long", "carol", 12*time.Hour)
			e.login(t, "A-short", "carol", 1*time.Hour)
			e.login(t, "other-1", "dave", 12*time.Hour)
			e.advance(2 * time.Hour)
			e.login(t, "A-new", "carol", 12*time.Hour)

			if err := e.repo.DeleteByUser(ctx, "carol"); err != nil {
				t.Fatalf("%s：吊销失败 %v", reason, err)
			}
			for _, id := range []string{"A-long", "A-short", "A-new"} {
				if e.alive(id) {
					t.Fatalf("%s：旧会话 %s 仍然有效", reason, id)
				}
			}
			if !e.alive("other-1") {
				t.Fatalf("%s：其他用户的会话被误删", reason)
			}
		})
	}
}

func envOr(key string) string { return os.Getenv(key) }

// 第二层（哨兵）：索引键在两次登录之间消失，Create 重建索引时放哨兵，DeleteByUser 见到哨兵必须扫描补漏。
// 前提是回填标记存在（系统稳态）——否则下一次 DeleteByUser 本来就会先全量回填，这里要单独把哨兵这一层测出来：
// 手工清掉回填会让标记缺失，所以回填后重新种下标记，隔离出「只靠哨兵」的路径。
func TestDeleteByUserScansWhenTheRebuiltIndexCarriesTheSuspectMarker(t *testing.T) {
	e := newH2Env(t)
	ctx := context.Background()
	if err := e.repo.DeleteByUser(ctx, "__settle__"); err != nil { // 稳态：回填标记存在
		t.Fatal(err)
	}
	e.login(t, "S1", "erin", 12*time.Hour)
	if err := e.client.Del(ctx, sessionUserKeyPrefix+"erin").Err(); err != nil { // 索引键丢失，S1 仍存活
		t.Fatal(err)
	}
	e.login(t, "S3", "erin", 12*time.Hour)
	members := e.client.ZRange(ctx, sessionUserKeyPrefix+"erin", 0, -1).Val()
	hasSuspect := false
	for _, m := range members {
		if m == sessionIndexSuspectID {
			hasSuspect = true
		}
	}
	if !hasSuspect {
		t.Fatalf("回填标记存在时，重建的索引应带哨兵成员：%v", members)
	}
	if e.client.Exists(ctx, sessionIndexBackfillMarkerKey).Val() != 1 {
		t.Fatal("前提：回填标记应仍然存在，才能隔离出哨兵这一层")
	}
	if err := e.repo.DeleteByUser(ctx, "erin"); err != nil {
		t.Fatal(err)
	}
	if e.alive("S1") || e.alive("S3") {
		t.Fatalf("哨兵没有触发扫描补漏：S1=%v S3=%v", e.alive("S1"), e.alive("S3"))
	}
	if e.client.Exists(ctx, sessionUserKeyPrefix+"erin").Val() != 0 {
		t.Fatal("吊销后索引键应清掉（含哨兵）")
	}
}

// 第三层（保险丝）：回填标记只活 sessionIndexBackfillMarkerTTL。滚动升级期间旧版本实例按旧逻辑写出了「非空但缺成员」的索引
// （没有哨兵，旧代码不认识它），新版本无法靠哨兵发现；标记过期后的下一次吊销必须全量扫描，把漏掉的会话救回来。
func TestDeleteByUserBackfillMarkerExpiresSoAnOldVersionsDamagedIndexIsRepaired(t *testing.T) {
	e := newH2Env(t)
	ctx := context.Background()
	if err := e.repo.DeleteByUser(ctx, "__settle__"); err != nil {
		t.Fatal(err)
	}
	if ttl := e.client.TTL(ctx, sessionIndexBackfillMarkerKey).Val(); ttl <= 0 || ttl > sessionIndexBackfillMarkerTTL {
		t.Fatalf("回填标记必须有 TTL 且不超过 %v，实际 %v", sessionIndexBackfillMarkerTTL, ttl)
	}
	// 旧版本实例写出的损坏索引：S1 存活但不在索引里，索引里只有 S3，没有哨兵。
	long := Session{ID: "S1", UserID: "frank", Username: "frank", Role: "auditor", TenantID: "t1",
		CreatedAt: e.now, AbsoluteExpiresAt: e.now.Add(12 * time.Hour), ExpiresAt: e.now.Add(12 * time.Hour)}
	if err := e.repo.save(ctx, &long); err != nil {
		t.Fatal(err)
	}
	s3 := Session{ID: "S3", UserID: "frank", Username: "frank", Role: "auditor", TenantID: "t1",
		CreatedAt: e.now, AbsoluteExpiresAt: e.now.Add(12 * time.Hour), ExpiresAt: e.now.Add(12 * time.Hour)}
	if err := e.repo.save(ctx, &s3); err != nil {
		t.Fatal(err)
	}
	if err := e.client.ZAdd(ctx, sessionUserKeyPrefix+"frank", redis.Z{Score: 1, Member: "S3"}).Err(); err != nil {
		t.Fatal(err)
	}
	// 标记到期（模拟过了一个窗口）。
	e.advance(sessionIndexBackfillMarkerTTL + time.Minute)
	if e.client.Exists(ctx, sessionIndexBackfillMarkerKey).Val() != 0 {
		t.Fatal("前提：回填标记应已过期")
	}
	if err := e.repo.DeleteByUser(ctx, "frank"); err != nil {
		t.Fatal(err)
	}
	if e.alive("S1") || e.alive("S3") {
		t.Fatalf("标记过期后的首次吊销没有全量扫描修复被旧版本损坏的索引：S1=%v S3=%v", e.alive("S1"), e.alive("S3"))
	}
}
