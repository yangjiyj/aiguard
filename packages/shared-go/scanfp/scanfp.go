// Package scanfp 实现"已检指纹缓存"（安全三视图重构 模块 2a，共享契约 8/9）：
// 缓存键 = tenant + content_sha256 + rule_pack_version + engine_build，
// 缓存值 = 降档/例外之前的原始 findings（raw_findings JSON 数组）。
// 进程内 LRU 前置 + DB(scan_fingerprints, 迁移 110) 回查；写入 ON CONFLICT 容忍
// gateway-core/proxy-server 多写入者（多副本最坏 = 良性重复检测一次）。
// 本包只负责缓存原始检测与稳定上下文；调用方决定保留完整事件还是写轻量 occurrence。
// 已知取舍：LRU 命中不回写 DB last_seen_at（省每消息一次 UPDATE）——热内容可能被
// fpclean 按 last_seen 清掉，代价 = 进程重启/LRU 逐出后重检一次（良性）。
package scanfp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// SHA256Hex 返回 UTF-8 字节序列的 sha256 十六进制小写摘要（缓存键分量）。
// 与 shared-go/aiconvo.ContentSHA256（Plan D）对同一字节序列结果一致；此处自带
// 实现以解除并行计划间的创建顺序依赖。
func SHA256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// DB 是 Store 依赖的最小数据库接口，*pgxpool.Pool 天然满足；测试用桩实现。
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Entry 是一条指纹缓存记录（与 scan_fingerprints 行一一对应）。
type Entry struct {
	TenantID               string
	ContentSHA256          string
	RulePackVersion        string
	EngineBuild            string
	SemanticConfigRevision string
	ContextScope           string
	ContextKey             string
	RawFindings            json.RawMessage // 原始 findings JSON 数组；nil/空视为 []
	FirstRequestID         string
	FirstSecurityEventID   string
	FirstSeenAt            time.Time
}

// HasFindings 报告首见检测是否有原始命中（决定命中后走 /apply-context/ 重放还是静默跳过）。
func (e *Entry) HasFindings() bool {
	if e == nil || len(e.RawFindings) == 0 {
		return false
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(e.RawFindings, &arr); err != nil {
		return true // 解析失败按"有命中"处理（保守：走重放/全量，绝不静默漏检）
	}
	return len(arr) > 0
}

// Store 是指纹缓存门面：进程内 LRU 前置 + DB 回查/落库。db 可为 nil（纯 LRU 模式，单测用）。
type Store struct {
	db DB

	mu  sync.Mutex
	lru *lruCache

	verMu            sync.RWMutex
	rulePackVersion  string
	engineBuild      string
	semanticRevision string
}

// NewStore 构造缓存。lruCapacity <= 0 时用默认 4096。
func NewStore(db DB, lruCapacity int) *Store {
	if lruCapacity <= 0 {
		lruCapacity = 4096
	}
	return &Store{db: db, lru: newLRUCache(lruCapacity)}
}

// SetVersions 记录最近一次真实引擎响应回带的版本对（缓存键分量，契约 1 回带）。
// 版本对未知（进程刚启动、引擎未回带）时 Lookup 恒 miss——宁可多检不可错用旧缓存。
func (s *Store) SetVersions(rulePackVersion, engineBuild string, semanticRevision ...string) {
	if rulePackVersion == "" || engineBuild == "" {
		return
	}
	revision := ""
	if len(semanticRevision) > 0 {
		revision = semanticRevision[0]
	}
	s.verMu.Lock()
	s.rulePackVersion, s.engineBuild, s.semanticRevision = rulePackVersion, engineBuild, revision
	s.verMu.Unlock()
}

// CurrentVersions 返回最近一次真实引擎响应回带的规则包版本、引擎构建与语义修订号；未知时为空。
func (s *Store) CurrentVersions() (rulePackVersion, engineBuild, semanticRevision string) {
	if s == nil {
		return "", "", ""
	}
	rp, eb, sr, ok := s.versions()
	if !ok {
		return "", "", ""
	}
	return rp, eb, sr
}

func (s *Store) versions() (string, string, string, bool) {
	s.verMu.RLock()
	defer s.verMu.RUnlock()
	return s.rulePackVersion, s.engineBuild, s.semanticRevision, s.rulePackVersion != "" && s.engineBuild != ""
}

func cacheKey(tenantID, sha, rulePack, build, semanticRevision, contextScope string) string {
	return tenantID + "|" + sha + "|" + rulePack + "|" + build + "|" + semanticRevision + "|" + contextScope
}

const lookupSQL = `
SELECT raw_findings_json, COALESCE(first_request_id, ''),
       COALESCE(first_security_event_id, ''), COALESCE(context_key, ''), first_seen_at
FROM scan_fingerprints
WHERE tenant_id = $1 AND content_sha256 = $2 AND rule_pack_version = $3 AND engine_build = $4
  AND semantic_config_revision = $5 AND context_scope = $6`

const bumpSQL = `
UPDATE scan_fingerprints
SET last_seen_at = now(), hit_count = hit_count + 1
WHERE tenant_id = $1 AND content_sha256 = $2 AND rule_pack_version = $3 AND engine_build = $4
  AND semantic_config_revision = $5 AND context_scope = $6`

// Lookup 按 tenant+sha256+当前版本对查缓存：先 LRU，miss 再回查 DB
// （DB 命中即回填 LRU 并 best-effort bump last_seen/hit_count）。
// 任何 DB 错误一律按 miss（fail-open：多检一次，绝不漏检）。
func (s *Store) Lookup(ctx context.Context, tenantID, contentSHA256 string) (*Entry, bool) {
	return s.LookupScoped(ctx, tenantID, contentSHA256, "")
}

// LookupScoped 在版本键之外加入稳定调用上下文，防止 project/user/actor/source
// 变化时错误复用另一上下文的安全结论。
func (s *Store) LookupScoped(ctx context.Context, tenantID, contentSHA256, contextScope string) (*Entry, bool) {
	if s == nil || tenantID == "" || contentSHA256 == "" {
		return nil, false
	}
	rp, eb, sr, ok := s.versions()
	if !ok {
		return nil, false
	}
	key := cacheKey(tenantID, contentSHA256, rp, eb, sr, contextScope)
	s.mu.Lock()
	if e, hit := s.lru.get(key); hit {
		s.mu.Unlock()
		return e, true
	}
	s.mu.Unlock()
	if s.db == nil {
		return nil, false
	}
	e := &Entry{
		TenantID: tenantID, ContentSHA256: contentSHA256,
		RulePackVersion: rp, EngineBuild: eb,
		SemanticConfigRevision: sr, ContextScope: contextScope,
	}
	var raw []byte
	if err := s.db.QueryRow(ctx, lookupSQL, tenantID, contentSHA256, rp, eb, sr, contextScope).
		Scan(&raw, &e.FirstRequestID, &e.FirstSecurityEventID, &e.ContextKey, &e.FirstSeenAt); err != nil {
		return nil, false
	}
	e.RawFindings = raw
	_, _ = s.db.Exec(ctx, bumpSQL, tenantID, contentSHA256, rp, eb, sr, contextScope)
	s.mu.Lock()
	s.lru.put(key, e)
	s.mu.Unlock()
	return e, true
}

const upsertSQL = `
INSERT INTO scan_fingerprints
    (tenant_id, content_sha256, rule_pack_version, engine_build,
     semantic_config_revision, context_scope, context_key,
     raw_findings_json, first_request_id, first_security_event_id,
     first_seen_at, last_seen_at, hit_count)
VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, ''), $8, NULLIF($9, ''), NULLIF($10, ''), now(), now(), 1)
ON CONFLICT (tenant_id, content_sha256, rule_pack_version, engine_build, semantic_config_revision, context_scope)
DO UPDATE SET
    last_seen_at = now(),
    hit_count = scan_fingerprints.hit_count + 1,
    context_key = COALESCE(NULLIF(scan_fingerprints.context_key, ''), EXCLUDED.context_key),
    first_security_event_id = COALESCE(NULLIF(scan_fingerprints.first_security_event_id, ''), EXCLUDED.first_security_event_id)`

// StoreResult 落库一次真实检测的指纹并回填 LRU（契约 8：ON CONFLICT 只 bump，
// 绝不覆盖首见 raw_findings/first_request_id——首见即基准）。best-effort：失败不影响主链。
func (s *Store) StoreResult(ctx context.Context, e Entry) {
	if s == nil || e.TenantID == "" || e.ContentSHA256 == "" ||
		e.RulePackVersion == "" || e.EngineBuild == "" {
		return
	}
	if len(e.RawFindings) == 0 {
		e.RawFindings = json.RawMessage("[]")
	}
	if e.FirstSeenAt.IsZero() {
		e.FirstSeenAt = time.Now()
	}
	s.SetVersions(e.RulePackVersion, e.EngineBuild, e.SemanticConfigRevision)
	key := cacheKey(e.TenantID, e.ContentSHA256, e.RulePackVersion, e.EngineBuild, e.SemanticConfigRevision, e.ContextScope)
	entry := e
	s.mu.Lock()
	s.lru.put(key, &entry)
	s.mu.Unlock()
	if s.db == nil {
		return
	}
	_, _ = s.db.Exec(ctx, upsertSQL,
		e.TenantID, e.ContentSHA256, e.RulePackVersion, e.EngineBuild,
		e.SemanticConfigRevision, e.ContextScope, e.ContextKey,
		[]byte(e.RawFindings), e.FirstRequestID, e.FirstSecurityEventID)
}
