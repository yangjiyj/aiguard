package permission

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 这组测试锁定"部门变更立即撤销旧模型权限"的两道防线：
//   1. outbox/reconciler 路径：部门迁移提交后 RecordDepartmentChange 入队 ->
//      Reconciler.ProcessOne -> InvalidateUserCache 清掉 grants 缓存（任务3已实现，
//      任务11 确保它是 department_id 单一事实源下的失效信号）。
//   2. department_version fallback: every production cache hit reads the authoritative
//      users.department_version revision and reloads grants when it changes.
// Together these prevent stale department grants while outbox processing is delayed.
// 旧部门权限。

// TestGrantsCacheRejectsStaleDepartmentVersion 验证 version 比对原语：
// SetWithVersion 写入后 GetWithVersion 命中并返回相同 version；version 变化由
// MatchVersion 判定（见下），GetWithVersion 本身只管 entry 新鲜度。
func TestGrantsCacheRejectsStaleDepartmentVersion(t *testing.T) {
	cache := NewGrantsCache()

	t0 := int64(1000)
	grants := []Grant{{ID: "g1", UserID: "u1", TenantID: "t1", ScopeType: "team", ScopeID: "dept_A", Role: "dept_manager"}}

	cache.SetWithVersion("u1", grants, t0)
	got, ver, ok := cache.GetWithVersion("u1")
	if !ok {
		t.Fatal("expected cache hit after SetWithVersion")
	}
	if len(got) != 1 || got[0].ScopeID != "dept_A" {
		t.Fatalf("unexpected cached grants: %+v", got)
	}
	if ver != t0 {
		t.Fatalf("cached version = %v, want %v", ver, t0)
	}
}

// TestGrantsCacheVersionMismatchDrivesMiss 验证版本比对的核心判定：
// 调用方持有一个旧 version（来自长会话），cache 里是新 version，
// MatchVersion 必须返回 false，促使调用方丢弃旧 grants 重载。
// 这是 department_version 机制防"长会话复用旧权限"的关键。
func TestGrantsCacheVersionMismatchDrivesMiss(t *testing.T) {
	cache := NewGrantsCache()
	t0 := int64(1000)
	t1 := int64(1001)
	cache.SetWithVersion("u1", []Grant{{UserID: "u1"}}, t1)

	if cache.MatchVersion("u1", t0) {
		t.Fatal("stale session version must NOT match refreshed cache version")
	}
	if !cache.MatchVersion("u1", t1) {
		t.Fatal("current session version must match cache version")
	}
	if cache.MatchVersion("u2", t0) {
		t.Fatal("unknown user must not match")
	}
	if cache.MatchVersion("u1", 0) {
		t.Fatal("zero session version must not match")
	}
}

// TestInvalidateUserCacheClearsVersion 验证 Invalidate 同时清掉 version，
// 防止"grants 被清但 version 残留导致下一次比对假命中"。
func TestInvalidateUserCacheClearsVersion(t *testing.T) {
	cache := NewGrantsCache()
	t0 := int64(1000)
	cache.SetWithVersion("u1", []Grant{{UserID: "u1"}}, t0)
	cache.Invalidate("u1")
	if _, _, ok := cache.GetWithVersion("u1"); ok {
		t.Fatal("expected miss after Invalidate")
	}
	if cache.MatchVersion("u1", t0) {
		t.Fatal("Invalidate must clear version so MatchVersion cannot hit")
	}
}

// stubSystemPermChecker 让 versioned loader 单测不连 DB 也能跑 rolesHavePermission。
type stubSystemPermChecker struct {
	allowed bool
}

func (s stubSystemPermChecker) rolesHavePermission(ctx context.Context, roles map[string]bool, resource, action string) (bool, error) {
	return s.allowed, nil
}

// TestGrantsForUserVersionedLoadsAndCaches 验证 grantsForUserVersioned 的核心契约：
// cache miss 时调 loader，把 grants 连同 loader 返回的 department_version 一起写入 cache；
// 再次调用命中缓存不再调 loader。这条路径是 InvalidateUserCache 之后的重载入口——
// 部门迁移 → outbox → InvalidateUserCache 清缓存 → 下次请求 miss → loader 读新 department_id。
func TestGrantsForUserVersionedLoadsAndCaches(t *testing.T) {
	cache := NewGrantsCache()
	t0 := int64(1000)

	loadCount := 0
	currentGrants := []Grant{{ID: "g1", UserID: "u1", TenantID: "t1", ScopeType: "team", ScopeID: "dept_A", Role: "dept_manager"}}
	currentVersion := t0

	loader := func(ctx context.Context, userID, tenantID string) ([]Grant, int64, error) {
		loadCount++
		return currentGrants, currentVersion, nil
	}

	c := &Checker{
		cache:           cache,
		grantsLoader:    loader,
		systemPermCheck: stubSystemPermChecker{allowed: true},
	}

	// 第一次：miss → load → cache
	g1, v1, err := c.grantsForUserVersioned(context.Background(), "u1", "t1")
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if loadCount != 1 {
		t.Fatalf("loadCount = %d, want 1", loadCount)
	}
	if len(g1) != 1 || g1[0].ScopeID != "dept_A" {
		t.Fatalf("unexpected grants: %+v", g1)
	}
	if v1 != t0 {
		t.Fatalf("version = %v, want %v", v1, t0)
	}

	// 第二次：hit → 不再 load
	_, _, _ = c.grantsForUserVersioned(context.Background(), "u1", "t1")
	if loadCount != 1 {
		t.Fatalf("loadCount = %d, want 1 (cache hit)", loadCount)
	}

	// 模拟部门迁移：InvalidateUserCache（由 outbox/reconciler 触发）
	c.InvalidateUserCache("u1")

	// 迁移后 loader 返回新部门 + 新 version
	currentVersion = 1001
	currentGrants = []Grant{{ID: "g2", UserID: "u1", TenantID: "t1", ScopeType: "team", ScopeID: "dept_B", Role: "dept_manager"}}

	// 第三次：Invalidate 后 miss → load 新部门 grants
	g3, v3, err := c.grantsForUserVersioned(context.Background(), "u1", "t1")
	if err != nil {
		t.Fatalf("post-migration load: %v", err)
	}
	if loadCount != 2 {
		t.Fatalf("loadCount = %d, want 2 (reload after Invalidate)", loadCount)
	}
	if len(g3) != 1 || g3[0].ScopeID != "dept_B" {
		t.Fatalf("expected dept_B grants after migration, got %+v", g3)
	}
	if v3 != currentVersion {
		t.Fatalf("post-migration version = %v, want %v", v3, currentVersion)
	}
}

func TestGrantsForUserVersionedReloadsWhenCurrentVersionAdvances(t *testing.T) {
	cache := NewGrantsCache()
	t0 := int64(1000)
	t1 := int64(1001)
	currentVersion := t0
	currentGrants := []Grant{{ID: "g-a", UserID: "u1", TenantID: "t1", ScopeType: "team", ScopeID: "dept_A", Role: "dept_manager"}}
	loadCount := 0
	versionReadCount := 0
	c := &Checker{
		cache: cache,
		grantsLoader: func(context.Context, string, string) ([]Grant, int64, error) {
			loadCount++
			return currentGrants, currentVersion, nil
		},
		currentVersionLoader: func(context.Context, string, string) (int64, bool, error) {
			versionReadCount++
			return currentVersion, true, nil
		},
		systemPermCheck: stubSystemPermChecker{allowed: true},
	}
	first, _, err := c.grantsForUserVersioned(context.Background(), "u1", "t1")
	if err != nil {
		t.Fatalf("first load: %v", err)
	}
	if len(first) != 1 || first[0].ScopeID != "dept_A" || loadCount != 1 {
		t.Fatalf("unexpected first load: grants=%+v loadCount=%d", first, loadCount)
	}
	_, _, err = c.grantsForUserVersioned(context.Background(), "u1", "t1")
	if err != nil {
		t.Fatalf("same-version cache hit: %v", err)
	}
	if loadCount != 1 || versionReadCount != 1 {
		t.Fatalf("same version must reuse cache: loadCount=%d versionReadCount=%d", loadCount, versionReadCount)
	}
	currentVersion = t1
	currentGrants = []Grant{{ID: "g-b", UserID: "u1", TenantID: "t1", ScopeType: "team", ScopeID: "dept_B", Role: "dept_manager"}}
	reloaded, version, err := c.grantsForUserVersioned(context.Background(), "u1", "t1")
	if err != nil {
		t.Fatalf("reload after version advance: %v", err)
	}
	if loadCount != 2 || versionReadCount != 2 {
		t.Fatalf("version advance must reload: loadCount=%d versionReadCount=%d", loadCount, versionReadCount)
	}
	if len(reloaded) != 1 || reloaded[0].ScopeID != "dept_B" || version != t1 {
		t.Fatalf("stale grant reused: grants=%+v version=%v", reloaded, version)
	}
}

func TestGrantsForUserVersionedRejectsZeroVersionOnCacheMiss(t *testing.T) {
	cache := NewGrantsCache()
	loadCount := 0
	c := &Checker{
		cache: cache,
		grantsLoader: func(context.Context, string, string) ([]Grant, int64, error) {
			loadCount++
			return []Grant{{ID: "g-a", UserID: "u1", TenantID: "t1", ScopeType: "team", ScopeID: "dept_A", Role: "dept_manager"}}, 0, nil
		},
		currentVersionLoader: func(context.Context, string, string) (int64, bool, error) {
			return 0, true, nil
		},
		systemPermCheck: stubSystemPermChecker{allowed: true},
	}

	grants, version, err := c.grantsForUserVersioned(context.Background(), "u1", "t1")
	if err != nil {
		t.Fatalf("zero-version load: %v", err)
	}
	if loadCount != 1 || len(grants) != 0 || version != 0 {
		t.Fatalf("zero version must fail closed: loadCount=%d grants=%+v version=%d", loadCount, grants, version)
	}
	if _, _, ok := cache.GetWithVersion("u1"); ok {
		t.Fatal("zero-version grants must not be cached")
	}
}

func TestGrantsForUserVersionedRejectsZeroVersionAfterCacheHit(t *testing.T) {
	cache := NewGrantsCache()
	cache.SetWithVersion("u1", []Grant{{ID: "stale", UserID: "u1", TenantID: "t1", ScopeType: "team", ScopeID: "dept_A", Role: "dept_manager"}}, 1000)
	loadCount := 0
	versionReadCount := 0
	c := &Checker{
		cache: cache,
		grantsLoader: func(context.Context, string, string) ([]Grant, int64, error) {
			loadCount++
			return []Grant{{ID: "reloaded", UserID: "u1", TenantID: "t1", ScopeType: "team", ScopeID: "dept_B", Role: "dept_manager"}}, 0, nil
		},
		currentVersionLoader: func(context.Context, string, string) (int64, bool, error) {
			versionReadCount++
			return 0, true, nil
		},
		systemPermCheck: stubSystemPermChecker{allowed: true},
	}

	grants, version, err := c.grantsForUserVersioned(context.Background(), "u1", "t1")
	if err != nil {
		t.Fatalf("zero-version reload: %v", err)
	}
	if versionReadCount != 1 || loadCount != 1 || len(grants) != 0 || version != 0 {
		t.Fatalf("zero current version must fail closed after cache hit: versionReads=%d loads=%d grants=%+v version=%d", versionReadCount, loadCount, grants, version)
	}
	if _, _, ok := cache.GetWithVersion("u1"); ok {
		t.Fatal("cache must remain invalid after zero-version reload")
	}
}

func TestVersionedCheckerDoesNotTrustLegacyUnversionedEntry(t *testing.T) {
	cache := NewGrantsCache()
	cache.Set("u1", []Grant{{ID: "g-a", UserID: "u1", TenantID: "t1", ScopeType: "team", ScopeID: "dept_A", Role: "dept_manager"}})
	t1 := int64(1001)
	loadCount := 0
	c := &Checker{
		cache: cache,
		grantsLoader: func(context.Context, string, string) ([]Grant, int64, error) {
			loadCount++
			return []Grant{{ID: "g-b", UserID: "u1", TenantID: "t1", ScopeType: "team", ScopeID: "dept_B", Role: "dept_manager"}}, t1, nil
		},
		currentVersionLoader: func(context.Context, string, string) (int64, bool, error) {
			return t1, true, nil
		},
		systemPermCheck: stubSystemPermChecker{allowed: true},
	}
	grants, version, err := c.grantsForUserVersioned(context.Background(), "u1", "t1")
	if err != nil {
		t.Fatalf("reload legacy entry: %v", err)
	}
	if loadCount != 1 || len(grants) != 1 || grants[0].ScopeID != "dept_B" || version != t1 {
		t.Fatalf("legacy entry bypassed version check: loadCount=%d grants=%+v version=%v", loadCount, grants, version)
	}
}

// TestLegacySetDoesNotBindVersion 验证 cache 层的严格性：
// 通过旧 Set() 写入（无 version）的 entry，GetWithVersion 必须 miss
// （没有 version 可比对，不能让需要 version 保证的调用方假命中）。
// 注意：Checker.grantsForUserVersioned 在 GetWithVersion miss 时会 fallback 到
// legacy Get，保持向后兼容——那是 checker 层的策略，cache 层本身保持严格。
func TestLegacySetDoesNotBindVersion(t *testing.T) {
	cache := NewGrantsCache()
	cache.Set("u1", []Grant{{UserID: "u1"}})
	if _, _, ok := cache.GetWithVersion("u1"); ok {
		t.Fatal("legacy Set entry must NOT satisfy GetWithVersion (no version bound)")
	}
	if cache.MatchVersion("u1", 1) {
		t.Fatal("legacy entry must not match any version")
	}
	// 旧 Get 仍命中（向后兼容）
	if _, ok := cache.Get("u1"); !ok {
		t.Fatal("legacy Set entry must still satisfy legacy Get")
	}
}

// TestSanitizedErrorDoesNotLeakDSN 验证权限加载失败时返回的错误不泄露底层细节。
// sanitizedLoaderError 只能返固定串，不含 DSN/SQL/claims/email。
func TestSanitizedErrorDoesNotLeakDSN(t *testing.T) {
	cases := []string{
		"postgres://user:pass@host:5432/db",
		"select * from users where email='a@b.com'",
		"groups=[g1,g2] subject=sub123",
		"ERROR: duplicate key value violates unique constraint",
	}
	for _, secret := range cases {
		msg := sanitizedLoaderError(secret)
		if strings.Contains(msg, secret) {
			t.Errorf("sanitized error leaked secret %q: %s", secret, msg)
		}
	}
}

func TestDepartmentVersionReloadsFromDatabaseBeforeOutboxInvalidation(t *testing.T) {
	dsn := os.Getenv("CONTENT_LOGS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("CONTENT_LOGS_TEST_DATABASE_URL is not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "perm-version-tenant-" + suffix
	userID := "perm-version-user-" + suffix
	grantID := "perm-version-grant-" + suffix
	departmentA := "perm-version-dept-a-" + suffix
	departmentB := "perm-version-dept-b-" + suffix
	t0 := time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)
	t1 := t0.Add(time.Minute)

	if _, err := pool.Exec(ctx, `
		INSERT INTO tenants (id,name,edition,status,is_test)
		VALUES ($1,$1,'enterprise','active',TRUE)
	`, tenantID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM permission_grants WHERE tenant_id=$1", tenantID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM users WHERE tenant_id=$1", tenantID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM teams WHERE tenant_id=$1", tenantID)
		_, _ = pool.Exec(context.Background(), "DELETE FROM tenants WHERE id=$1", tenantID)
	})
	if _, err := pool.Exec(ctx, `
		INSERT INTO teams (id,tenant_id,name,path) VALUES
			($1,$3,'Department A',$4),
			($2,$3,'Department B',$5)
	`, departmentA, departmentB, tenantID, "/"+departmentA, "/"+departmentB); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO users (id,tenant_id,username,role,status,department_id,department_resolved_at)
		VALUES ($1,$2,$1,'developer','active',$3,$4)
	`, userID, tenantID, departmentA, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO permission_grants (id,tenant_id,user_id,scope_type,scope_id,role,granted_by)
		VALUES ($1,$2,$3,'team',$4,'dept_manager',$3)
	`, grantID, tenantID, userID, departmentA); err != nil {
		t.Fatal(err)
	}

	checker := NewChecker(pool, NewGrantsCache())
	first, version0, err := checker.grantsForUserVersioned(ctx, userID, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 1 || first[0].ScopeID != departmentA || version0 == 0 {
		t.Fatalf("unexpected primed cache: grants=%+v version=%v", first, version0)
	}

	if _, err := pool.Exec(ctx, "UPDATE users SET department_id=$1, department_resolved_at=$2 WHERE id=$3 AND tenant_id=$4", departmentB, t1, userID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM permission_grants WHERE id=$1", grantID); err != nil {
		t.Fatal(err)
	}

	reloaded, version1, err := checker.grantsForUserVersioned(ctx, userID, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloaded) != 0 || version1 == 0 || version1 == version0 {
		t.Fatalf("stale grant survived version change: grants=%+v version=%v", reloaded, version1)
	}
	cached, cachedVersion, ok := checker.cache.GetWithVersion(userID)
	if !ok || len(cached) != 0 || cachedVersion != version1 {
		t.Fatalf("zero-grant user version not cached: grants=%+v version=%v ok=%v", cached, cachedVersion, ok)
	}
}
