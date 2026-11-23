package scanfp

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ---- 测试桩：最小 DB ----

type fakeRow struct {
	raw          []byte
	firstReq     string
	firstEventID string
	contextKey   string
	seenAt       time.Time
	err          error
}

func (r *fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	*dest[0].(*[]byte) = r.raw
	*dest[1].(*string) = r.firstReq
	*dest[2].(*string) = r.firstEventID
	*dest[3].(*string) = r.contextKey
	*dest[4].(*time.Time) = r.seenAt
	return nil
}

type fakeDB struct {
	execSQL   []string
	execArgs  [][]any
	queryRows int
	row       *fakeRow
}

func (f *fakeDB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.execSQL = append(f.execSQL, sql)
	f.execArgs = append(f.execArgs, args)
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (f *fakeDB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	f.queryRows++
	if f.row != nil {
		return f.row
	}
	return &fakeRow{err: pgx.ErrNoRows}
}

// ---- 用例 ----

func TestSHA256Hex(t *testing.T) {
	// sha256("abc") 已知向量
	if got := SHA256Hex("abc"); got != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatalf("SHA256Hex(abc) = %s", got)
	}
}

func TestEntryHasFindings(t *testing.T) {
	cases := []struct {
		raw  string
		want bool
	}{
		{"", false},
		{"[]", false},
		{`[{"rule_id":"a"}]`, true},
		{"not-json", true}, // 解析失败按有命中处理（保守，绝不静默漏检）
	}
	for _, c := range cases {
		e := &Entry{RawFindings: json.RawMessage(c.raw)}
		if got := e.HasFindings(); got != c.want {
			t.Fatalf("HasFindings(%q) = %v, want %v", c.raw, got, c.want)
		}
	}
	var nilEntry *Entry
	if nilEntry.HasFindings() {
		t.Fatal("nil Entry 必须返回 false")
	}
}

func TestLookupMissWhenVersionsUnknown(t *testing.T) {
	db := &fakeDB{}
	s := NewStore(db, 8)
	if _, hit := s.Lookup(context.Background(), "t1", SHA256Hex("x")); hit {
		t.Fatal("版本对未知时必须 miss（强制全量检测以学习版本）")
	}
	if db.queryRows != 0 {
		t.Fatal("版本对未知时不得触碰 DB")
	}
}

func TestStoreResultThenLookupHitsLRU(t *testing.T) {
	s := NewStore(nil, 8) // 纯 LRU，无 DB
	sha := SHA256Hex("same system prompt")
	s.StoreResult(context.Background(), Entry{
		TenantID: "t1", ContentSHA256: sha,
		RulePackVersion: "rp1", EngineBuild: "b1",
		SemanticConfigRevision: "sem1", ContextScope: "scope1", ContextKey: "ctx1",
		RawFindings: json.RawMessage(`[{"rule_id":"pi-1"}]`), FirstRequestID: "req-1", FirstSecurityEventID: "evt-1",
	})
	e, hit := s.LookupScoped(context.Background(), "t1", sha, "scope1")
	if !hit {
		t.Fatal("StoreResult 后 LRU 应命中")
	}
	if e.FirstRequestID != "req-1" || e.FirstSecurityEventID != "evt-1" || e.ContextKey != "ctx1" || !e.HasFindings() {
		t.Fatalf("entry = %+v", e)
	}
	// 不同租户不得命中
	if _, hit := s.LookupScoped(context.Background(), "t2", sha, "scope1"); hit {
		t.Fatal("跨租户不得命中")
	}
}

func TestLookupNaturallyMissesAfterRuleEngineOrSemanticVersionChange(t *testing.T) {
	s := NewStore(nil, 8)
	sha := SHA256Hex("versioned content")
	s.StoreResult(context.Background(), Entry{
		TenantID: "t1", ContentSHA256: sha,
		RulePackVersion: "rules-1", EngineBuild: "engine-1",
		SemanticConfigRevision: "semantic-1", ContextScope: "scope-1",
		RawFindings: json.RawMessage("[{\"rule_id\":\"secret-1\"}]"),
	})

	s.SetVersions("rules-2", "engine-1", "semantic-1")
	if _, hit := s.LookupScoped(context.Background(), "t1", sha, "scope-1"); hit {
		t.Fatal("rule-pack version change must miss the old fingerprint")
	}
	s.SetVersions("rules-1", "engine-1", "semantic-2")
	if _, hit := s.LookupScoped(context.Background(), "t1", sha, "scope-1"); hit {
		t.Fatal("semantic configuration revision change must miss the old fingerprint")
	}
}

func TestLRUEviction(t *testing.T) {
	s := NewStore(nil, 2)
	shas := []string{SHA256Hex("a"), SHA256Hex("b"), SHA256Hex("c")}
	for i, sha := range shas {
		s.StoreResult(context.Background(), Entry{
			TenantID: "t1", ContentSHA256: sha,
			RulePackVersion: "rp1", EngineBuild: "b1",
			FirstRequestID: "r", RawFindings: json.RawMessage("[]"),
		})
		_ = i
	}
	if _, hit := s.Lookup(context.Background(), "t1", shas[0]); hit {
		t.Fatal("容量 2 存 3 个后最旧的应被逐出")
	}
	if _, hit := s.Lookup(context.Background(), "t1", shas[2]); !hit {
		t.Fatal("最新的必须还在")
	}
}

func TestLookupFallsBackToDBAndBumps(t *testing.T) {
	db := &fakeDB{row: &fakeRow{
		raw: []byte(`[{"rule_id":"pi-1"}]`), firstReq: "req-0",
		firstEventID: "evt-0", contextKey: "ctx-0", seenAt: time.Now(),
	}}
	s := NewStore(db, 8)
	s.SetVersions("rp1", "b1", "sem1")
	sha := SHA256Hex("db cached content")

	e, hit := s.LookupScoped(context.Background(), "t1", sha, "scope1")
	if !hit || e.FirstRequestID != "req-0" || e.FirstSecurityEventID != "evt-0" || e.ContextKey != "ctx-0" || !e.HasFindings() {
		t.Fatalf("DB 回查应命中, hit=%v entry=%+v", hit, e)
	}
	if db.queryRows != 1 {
		t.Fatalf("应查 DB 一次, got %d", db.queryRows)
	}
	if len(db.execSQL) != 1 || !strings.Contains(db.execSQL[0], "hit_count = hit_count + 1") {
		t.Fatalf("DB 命中应 bump last_seen/hit_count, execSQL=%v", db.execSQL)
	}
	// 第二次同键：LRU 命中，不再查 DB
	if _, hit := s.LookupScoped(context.Background(), "t1", sha, "scope1"); !hit {
		t.Fatal("回填 LRU 后应命中")
	}
	if db.queryRows != 1 {
		t.Fatalf("回填 LRU 后不得再查 DB, got %d", db.queryRows)
	}
}

func TestStoreResultUpsertSQL(t *testing.T) {
	db := &fakeDB{}
	s := NewStore(db, 8)
	s.StoreResult(context.Background(), Entry{
		TenantID: "t1", ContentSHA256: SHA256Hex("x"),
		RulePackVersion: "rp1", EngineBuild: "b1",
		RawFindings: nil, FirstRequestID: "req-9",
	})
	if len(db.execSQL) != 1 {
		t.Fatalf("应执行一条 UPSERT, got %d", len(db.execSQL))
	}
	if !strings.Contains(db.execSQL[0], "semantic_config_revision, context_scope)") {
		t.Fatalf("UPSERT 必须按契约主键冲突, sql=%s", db.execSQL[0])
	}
	// RawFindings 为空时必须落 []（NOT NULL 列）
	if string(db.execArgs[0][7].([]byte)) != "[]" {
		t.Fatalf("空 findings 应落 [], got %s", db.execArgs[0][7])
	}
	// StoreResult 顺带学习版本对
	if _, _, _, ok := s.versions(); !ok {
		t.Fatal("StoreResult 后版本对应已知")
	}
}

func TestLookupScopedSeparatesContextAndSemanticRevision(t *testing.T) {
	s := NewStore(nil, 8)
	sha := SHA256Hex("same")
	s.StoreResult(context.Background(), Entry{
		TenantID: "t1", ContentSHA256: sha, RulePackVersion: "rp1", EngineBuild: "b1",
		SemanticConfigRevision: "sem1", ContextScope: "source-system",
		RawFindings: json.RawMessage(`[{"rule_id":"pi-1"}]`),
	})
	if _, hit := s.LookupScoped(context.Background(), "t1", sha, "source-user"); hit {
		t.Fatal("不同 actor/source scope 不得命中")
	}
	s.SetVersions("rp2", "b1", "sem1")
	if _, hit := s.LookupScoped(context.Background(), "t1", sha, "source-system"); hit {
		t.Fatal("规则包版本变化不得命中旧缓存")
	}
	s.SetVersions("rp1", "b2", "sem1")
	if _, hit := s.LookupScoped(context.Background(), "t1", sha, "source-system"); hit {
		t.Fatal("引擎版本变化不得命中旧缓存")
	}
	s.SetVersions("rp1", "b1", "sem2")
	if _, hit := s.LookupScoped(context.Background(), "t1", sha, "source-system"); hit {
		t.Fatal("语义 revision 变化不得命中旧缓存")
	}
}

func TestStoreResultRejectsIncompleteKey(t *testing.T) {
	db := &fakeDB{}
	s := NewStore(db, 8)
	s.StoreResult(context.Background(), Entry{TenantID: "t1", ContentSHA256: "sha"}) // 缺版本对
	if len(db.execSQL) != 0 {
		t.Fatal("缓存键不完整不得落库")
	}
}
