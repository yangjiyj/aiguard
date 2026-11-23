package repository

// W3 3.4：会话空闲超时 / 绝对超时 / 并发上限 / 旧会话兼容。miniredis，无外部依赖。

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

type sessionTestClock struct{ now time.Time }

func (c *sessionTestClock) Now() time.Time { return c.now }

func newSessionTestRepo(t *testing.T) (*SessionRepository, *miniredis.Miniredis, *sessionTestClock) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	clock := &sessionTestClock{now: time.Date(2026, 9, 30, 8, 0, 0, 0, time.UTC)}
	repo := NewSessionRepository(client)
	repo.SetClockForTest(clock.Now)
	// Align miniredis with the fixture clock: absolute EXPIREAT values written by
	// Create (the per-user session index) are compared against miniredis time,
	// which defaults to the real wall clock. A fixed fixture date in the past
	// would otherwise expire the index instantly (time-bomb: TestSessionEnforce
	// MaxConcurrentEvictsOldest started failing once real time passed 2026-09-30
	// 20:01 UTC). FastForward below only slides relative TTLs, so advance() also
	// re-anchors SetTime on every step.
	mr.SetTime(clock.now)
	return repo, mr, clock
}

// advance 同时推进仓储时钟与 miniredis 的 TTL。
func advance(mr *miniredis.Miniredis, clock *sessionTestClock, d time.Duration) {
	clock.now = clock.now.Add(d)
	mr.FastForward(d)
	mr.SetTime(clock.now)
}

func TestSessionIdleTimeoutSlidesOnActivity(t *testing.T) {
	repo, mr, clock := newSessionTestRepo(t)
	ctx := context.Background()
	s := &Session{ID: "s1", UserID: "u1", IdleTimeoutSeconds: 1800, AbsoluteExpiresAt: clock.now.Add(12 * time.Hour)}
	if err := repo.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		advance(mr, clock, 20*time.Minute)
		if got, _ := repo.Get(ctx, "s1"); got == nil {
			t.Fatalf("active session expired early at step %d", i)
		}
		if err := repo.Extend(ctx, "s1"); err != nil {
			t.Fatal(err)
		}
	}
	advance(mr, clock, 31*time.Minute)
	if got, _ := repo.Get(ctx, "s1"); got != nil {
		t.Fatal("session must expire after 30 idle minutes")
	}
}

func TestSessionAbsoluteTimeoutIgnoresActivity(t *testing.T) {
	repo, mr, clock := newSessionTestRepo(t)
	ctx := context.Background()
	s := &Session{ID: "s2", UserID: "u2", IdleTimeoutSeconds: 1800, AbsoluteExpiresAt: clock.now.Add(time.Hour)}
	if err := repo.Create(ctx, s); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		advance(mr, clock, 10*time.Minute)
		_ = repo.Extend(ctx, "s2")
	}
	advance(mr, clock, 11*time.Minute)
	if got, _ := repo.Get(ctx, "s2"); got != nil {
		t.Fatal("session must end at the absolute timeout even while active")
	}
}

func TestSessionLegacyPayloadGetsDefaultLimits(t *testing.T) {
	repo, mr, clock := newSessionTestRepo(t)
	ctx := context.Background()
	// 升级前签发的会话：只有 created_at / expires_at（24h 滑动）。
	legacy := map[string]any{"id": "old", "user_id": "u3", "username": "admin", "role": "platform_admin",
		"created_at": clock.now.Add(-11 * time.Hour), "expires_at": clock.now.Add(24 * time.Hour)}
	raw, _ := json.Marshal(legacy)
	mr.Set(sessionKeyPrefix+"old", string(raw))
	if got, _ := repo.Get(ctx, "old"); got == nil {
		t.Fatal("legacy session within 12h must remain valid")
	}
	advance(mr, clock, 61*time.Minute)
	if got, _ := repo.Get(ctx, "old"); got != nil {
		t.Fatal("legacy session must be capped at 12h absolute lifetime")
	}
}

func TestSessionEnforceMaxConcurrentEvictsOldest(t *testing.T) {
	repo, mr, clock := newSessionTestRepo(t)
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c"} {
		if err := repo.Create(ctx, &Session{ID: id, UserID: "u4"}); err != nil {
			t.Fatal(err)
		}
		advance(mr, clock, time.Second)
	}
	evicted, err := repo.EnforceMaxConcurrent(ctx, "u4", 2)
	if err != nil || evicted != 2 {
		t.Fatalf("expected 2 evictions to make room for one new session, got %d (%v)", evicted, err)
	}
	if got, _ := repo.Get(ctx, "c"); got == nil {
		t.Fatal("newest session must survive")
	}
	for _, id := range []string{"a", "b"} {
		if got, _ := repo.Get(ctx, id); got != nil {
			t.Fatalf("old session %s must be evicted", id)
		}
	}
	if n, _ := repo.EnforceMaxConcurrent(ctx, "u4", 0); n != 0 {
		t.Fatal("max=0 means unlimited")
	}
}

func TestSessionDeleteByUserClearsIndex(t *testing.T) {
	repo, _, _ := newSessionTestRepo(t)
	ctx := context.Background()
	_ = repo.Create(ctx, &Session{ID: "x1", UserID: "u5"})
	_ = repo.Create(ctx, &Session{ID: "x2", UserID: "u5"})
	_ = repo.Create(ctx, &Session{ID: "y1", UserID: "u6"})
	if err := repo.DeleteByUser(ctx, "u5"); err != nil {
		t.Fatal(err)
	}
	if ids, _ := repo.ActiveSessionIDs(ctx, "u5"); len(ids) != 0 {
		t.Fatalf("index must be empty, got %v", ids)
	}
	if got, _ := repo.Get(ctx, "y1"); got == nil {
		t.Fatal("other users' sessions must be untouched")
	}
}
