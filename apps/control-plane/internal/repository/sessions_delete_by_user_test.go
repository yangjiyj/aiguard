package repository

// 第 4 项：DeleteByUser 优先用 session_user:<id> 索引，不再每次全量 SCAN session:*。
//
// 删除语义不变：该用户的会话必须删干净，其他用户的一条都不能动。覆盖三个场景：
//   - 多用户：只删目标用户，且走索引（不 SCAN）；
//   - 大量会话：目标用户 N 个会话 + 大量其他用户会话，走索引、不 SCAN，删干净；
//   - 索引缺失：整个索引键丢失、或升级前签发的旧会话没有索引条目，仍然删干净（回退 SCAN）。
//
// 默认用 miniredis；设置 REDIS_TEST_ADDR（如 127.0.0.1:6379）则连真实 Redis/Valkey，
// 用唯一前缀无法隔离 session: 键，所以真实库只允许一次性容器：测试会 FLUSHDB，因此还要求 REDIS_TEST_ALLOW_FLUSH=1。

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type commandCounter struct {
	mu    sync.Mutex
	count map[string]int
}

func (c *commandCounter) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) { return next(ctx, network, addr) }
}
func (c *commandCounter) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		c.mu.Lock()
		c.count[cmd.Name()]++
		c.mu.Unlock()
		return next(ctx, cmd)
	}
}
func (c *commandCounter) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		c.mu.Lock()
		for _, cmd := range cmds {
			c.count[cmd.Name()]++
		}
		c.mu.Unlock()
		return next(ctx, cmds)
	}
}
func (c *commandCounter) get(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count[name]
}
func (c *commandCounter) reset() {
	c.mu.Lock()
	c.count = map[string]int{}
	c.mu.Unlock()
}

func newDeleteByUserRepo(t *testing.T) (*SessionRepository, *redis.Client, *commandCounter) {
	t.Helper()
	var client *redis.Client
	if addr := os.Getenv("REDIS_TEST_ADDR"); addr != "" {
		if os.Getenv("REDIS_TEST_ALLOW_FLUSH") != "1" {
			t.Skip("REDIS_TEST_ADDR 已设置但未设置 REDIS_TEST_ALLOW_FLUSH=1：真实库测试会 FLUSHDB，只允许一次性容器")
		}
		client = redis.NewClient(&redis.Options{Addr: addr})
		if err := client.FlushDB(context.Background()).Err(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { client.FlushDB(context.Background()); client.Close() })
	} else {
		mr := miniredis.RunT(t)
		client = redis.NewClient(&redis.Options{Addr: mr.Addr()})
		t.Cleanup(func() { client.Close() })
	}
	counter := &commandCounter{count: map[string]int{}}
	client.AddHook(counter)
	return NewSessionRepository(client), client, counter
}

func makeSessions(t *testing.T, repo *SessionRepository, user string, n int) []string {
	t.Helper()
	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%s-s%05d", user, i)
		if err := repo.Create(context.Background(), &Session{ID: id, UserID: user, Username: user, Role: "security_officer", TenantID: "t1"}); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

func liveCount(t *testing.T, client *redis.Client, ids []string) int {
	t.Helper()
	n := 0
	for _, id := range ids {
		if client.Exists(context.Background(), sessionKeyPrefix+id).Val() == 1 {
			n++
		}
	}
	return n
}

// 把仓储带到「已完成一次性索引回填」的稳态：新建一个无关用户并对其调用一次 DeleteByUser。
func settleBackfill(t *testing.T, repo *SessionRepository) {
	t.Helper()
	if err := repo.DeleteByUser(context.Background(), "__settle__"); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteByUserUsesIndexInsteadOfScanningAllSessions(t *testing.T) {
	repo, client, counter := newDeleteByUserRepo(t)
	ctx := context.Background()
	alice := makeSessions(t, repo, "alice", 3)
	bob := makeSessions(t, repo, "bob", 4)
	carol := makeSessions(t, repo, "carol", 2)
	settleBackfill(t, repo)

	counter.reset()
	if err := repo.DeleteByUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if n := counter.get("scan"); n != 0 {
		t.Fatalf("有索引时不应该 SCAN 全部会话，SCAN 调用了 %d 次", n)
	}
	if n := liveCount(t, client, alice); n != 0 {
		t.Fatalf("alice 还剩 %d 个会话没删", n)
	}
	if n := liveCount(t, client, bob); n != len(bob) {
		t.Fatalf("bob 的会话被误删：剩 %d/%d", n, len(bob))
	}
	if n := liveCount(t, client, carol); n != len(carol) {
		t.Fatalf("carol 的会话被误删：剩 %d/%d", n, len(carol))
	}
	if client.Exists(ctx, sessionUserKeyPrefix+"alice").Val() != 0 {
		t.Fatal("alice 的索引键应当一并清掉")
	}
	if client.Exists(ctx, sessionUserKeyPrefix+"bob").Val() != 1 {
		t.Fatal("bob 的索引不应被动")
	}
}

func TestDeleteByUserWithManySessions(t *testing.T) {
	repo, client, counter := newDeleteByUserRepo(t)
	ctx := context.Background()
	target := makeSessions(t, repo, "target", 1200)
	var others []string
	for u := 0; u < 20; u++ {
		others = append(others, makeSessions(t, repo, fmt.Sprintf("other%02d", u), 100)...)
	}
	settleBackfill(t, repo)

	counter.reset()
	if err := repo.DeleteByUser(ctx, "target"); err != nil {
		t.Fatal(err)
	}
	if n := counter.get("scan"); n != 0 {
		t.Fatalf("大量会话下仍然 SCAN 了 %d 次", n)
	}
	if n := liveCount(t, client, target); n != 0 {
		t.Fatalf("target 还剩 %d/%d 个会话", n, len(target))
	}
	if n := liveCount(t, client, others); n != len(others) {
		t.Fatalf("其他用户会话被误删：剩 %d/%d", n, len(others))
	}
}

func TestDeleteByUserFallsBackToScanWhenIndexIsMissing(t *testing.T) {
	repo, client, _ := newDeleteByUserRepo(t)
	ctx := context.Background()
	alice := makeSessions(t, repo, "alice", 5)
	bob := makeSessions(t, repo, "bob", 3)
	settleBackfill(t, repo)

	// 场景 1：索引键整体丢失（淘汰/误删/人工清理）。
	if err := client.Del(ctx, sessionUserKeyPrefix+"alice").Err(); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteByUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if n := liveCount(t, client, alice); n != 0 {
		t.Fatalf("索引丢失后 alice 还剩 %d 个会话", n)
	}
	if n := liveCount(t, client, bob); n != len(bob) {
		t.Fatalf("回退扫描误删了 bob：剩 %d/%d", n, len(bob))
	}

	// 场景 2：索引只缺一部分（部分会话没有索引条目）。
	more := makeSessions(t, repo, "dave", 4)
	if err := client.ZRem(ctx, sessionUserKeyPrefix+"dave", more[0], more[1]).Err(); err != nil {
		t.Fatal(err)
	}
	// 稳态下索引非空即视为可信，因此部分缺失只会发生在「升级前的旧会话」上，见下一个测试；
	// 这里确认：索引里还在的会话被删，且不影响其他用户。
	if err := repo.DeleteByUser(ctx, "dave"); err != nil {
		t.Fatal(err)
	}
	if n := liveCount(t, client, more[2:]); n != 0 {
		t.Fatalf("dave 索引内的会话应已删除，还剩 %d", n)
	}
}

// 升级窗口：升级前签发的会话没有索引条目；同一用户升级后再登录一次，索引非空但不完整。
// 吊销（改密/禁用/改角色）必须把旧会话也删掉，不能因为「索引非空」就漏掉它。
func TestDeleteByUserRevokesLegacySessionsThatPredateTheIndex(t *testing.T) {
	repo, client, counter := newDeleteByUserRepo(t)
	ctx := context.Background()

	// 旧会话：只写会话本体，不写索引（模拟升级前的写入方式）。
	legacy := Session{ID: "legacy-1", UserID: "erin", Username: "erin", Role: "auditor", TenantID: "t1"}
	legacy.CreatedAt = time.Now().Add(-time.Hour)
	legacy.AbsoluteExpiresAt = time.Now().Add(10 * time.Hour)
	legacy.ExpiresAt = time.Now().Add(20 * time.Minute)
	if err := repo.save(ctx, &legacy); err != nil {
		t.Fatal(err)
	}
	// 升级后的新会话：带索引。
	fresh := makeSessions(t, repo, "erin", 1)
	other := makeSessions(t, repo, "frank", 2)

	if err := repo.DeleteByUser(ctx, "erin"); err != nil {
		t.Fatal(err)
	}
	if client.Exists(ctx, sessionKeyPrefix+"legacy-1").Val() != 0 {
		t.Fatal("升级前签发的旧会话没有被吊销（索引非空但不完整）")
	}
	if n := liveCount(t, client, fresh); n != 0 {
		t.Fatalf("新会话没删：%d", n)
	}
	if n := liveCount(t, client, other); n != len(other) {
		t.Fatalf("frank 被误删：%d/%d", n, len(other))
	}
	if counter.get("scan") == 0 {
		t.Fatal("首次吊销应当做一次性回填扫描")
	}

	// 回填只做一次：之后的吊销不再扫描，且回填已把其他用户的旧会话补进了索引。
	legacy2 := Session{ID: "legacy-2", UserID: "gina", Username: "gina", Role: "auditor", TenantID: "t1"}
	legacy2.CreatedAt = time.Now()
	legacy2.AbsoluteExpiresAt = time.Now().Add(time.Hour)
	legacy2.ExpiresAt = time.Now().Add(20 * time.Minute)
	if err := repo.save(ctx, &legacy2); err != nil {
		t.Fatal(err)
	}
	// 清掉回填标记，模拟另一副本在回填之前签发的旧会话 → 下一次吊销会重新回填。
	if err := client.Del(ctx, sessionIndexBackfillMarkerKey).Err(); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteByUser(ctx, "gina"); err != nil {
		t.Fatal(err)
	}
	if client.Exists(ctx, sessionKeyPrefix+"legacy-2").Val() != 0 {
		t.Fatal("标记缺失时必须重新回填并删掉旧会话")
	}
	if n := liveCount(t, client, other); n != len(other) {
		t.Fatalf("frank 被误删：%d/%d", n, len(other))
	}
	if client.ZCard(ctx, sessionUserKeyPrefix+"frank").Val() != int64(len(other)) {
		t.Fatal("回填后 frank 的索引应保持完整")
	}
}

func TestDeleteByUserWithNoSessionsIsHarmless(t *testing.T) {
	repo, client, _ := newDeleteByUserRepo(t)
	ctx := context.Background()
	bob := makeSessions(t, repo, "bob", 2)
	if err := repo.DeleteByUser(ctx, "nobody"); err != nil {
		t.Fatal(err)
	}
	if n := liveCount(t, client, bob); n != len(bob) {
		t.Fatalf("误删：%d/%d", n, len(bob))
	}
}

// 索引里指向别人会话的错误条目不能连带删掉别人的会话。
func TestDeleteByUserNeverDeletesAnotherUsersSessionListedInTheIndex(t *testing.T) {
	repo, client, _ := newDeleteByUserRepo(t)
	ctx := context.Background()
	bob := makeSessions(t, repo, "bob", 1)
	alice := makeSessions(t, repo, "alice", 1)
	settleBackfill(t, repo)
	if err := client.ZAdd(ctx, sessionUserKeyPrefix+"alice", redis.Z{Score: 1, Member: bob[0]}).Err(); err != nil {
		t.Fatal(err)
	}
	if err := repo.DeleteByUser(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if liveCount(t, client, alice) != 0 {
		t.Fatal("alice 的会话应已删除")
	}
	if liveCount(t, client, bob) != 1 {
		t.Fatal("索引里的错误条目导致 bob 的会话被删")
	}
}

// 创建会话时必须先写索引再写会话本体：否则「会话已写入、索引写入失败」会留下无法按索引吊销的会话。
func TestCreateWritesTheIndexBeforeTheSession(t *testing.T) {
	repo, client, _ := newDeleteByUserRepo(t)
	ctx := context.Background()
	order := &orderRecorder{}
	client.AddHook(order)
	_ = repo.Create(ctx, &Session{ID: "ordered-1", UserID: "heidi", Username: "heidi", Role: "auditor", TenantID: "t1"})
	// 索引登记现在是一次 Lua 脚本调用（EVALSHA；脚本缓存未命中时先 EVAL），必须出现在 SET 会话本体之前。
	idx := order.indexOf("evalsha")
	if i := order.indexOf("eval"); idx < 0 || (i >= 0 && i < idx) {
		idx = i
	}
	set := order.indexOf("set")
	if idx < 0 || set < 0 || idx > set {
		t.Fatalf("应先登记索引（EVAL/EVALSHA）再 SET 会话，实际顺序：%v", order.names)
	}
}

type orderRecorder struct {
	mu    sync.Mutex
	names []string
}

func (o *orderRecorder) DialHook(next redis.DialHook) redis.DialHook { return next }
func (o *orderRecorder) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		o.mu.Lock()
		o.names = append(o.names, cmd.Name())
		o.mu.Unlock()
		return next(ctx, cmd)
	}
}
func (o *orderRecorder) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		o.mu.Lock()
		for _, c := range cmds {
			o.names = append(o.names, c.Name())
		}
		o.mu.Unlock()
		return next(ctx, cmds)
	}
}
func (o *orderRecorder) indexOf(name string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	for i, n := range o.names {
		if n == name {
			return i
		}
	}
	return -1
}
