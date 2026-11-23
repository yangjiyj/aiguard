-- 110_scan_fingerprints.sql
-- P1-B 已检指纹缓存（安全三视图重构 模块 2a，共享契约 8）：
--   缓存键 = (tenant_id, content_sha256, rule_pack_version, engine_build)，
--   缓存值 = 降档/例外之前的原始 findings（raw_findings_json）。
--   引擎镜像升级/规则包变更 → 版本对变化 → 旧行自然失效（worker fpclean 周期清理）。
-- 红线：本表只省"检测算力"，security_events 照写（matched_summary.scan_mode=fingerprint_reuse），
--   证据永不减量。写入方（gateway-core/proxy-server 多写入者）用 ON CONFLICT 容忍并发。
-- 纯附加、幂等（IF NOT EXISTS）；无 CONCURRENTLY，由 migration-runner 事务包裹（原子可回滚）。

CREATE TABLE IF NOT EXISTS scan_fingerprints (
    tenant_id         TEXT        NOT NULL,
    content_sha256    TEXT        NOT NULL,
    rule_pack_version TEXT        NOT NULL,
    engine_build      TEXT        NOT NULL,
    raw_findings_json JSONB       NOT NULL DEFAULT '[]'::jsonb,
    first_request_id  TEXT,
    first_seen_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    hit_count         BIGINT      NOT NULL DEFAULT 1,
    PRIMARY KEY (tenant_id, content_sha256, rule_pack_version, engine_build)
);

-- worker fpclean：按 last_seen_at 清理超留存期行 + 判定"当前版本对"（last_seen_at 最新行）
CREATE INDEX IF NOT EXISTS idx_scan_fingerprints_last_seen
    ON scan_fingerprints (last_seen_at);

COMMENT ON TABLE scan_fingerprints IS '已检指纹缓存（契约 8）：同一 (tenant,content_sha256,rule_pack_version,engine_build) 只全量检测一次，后续走 /apply-context/ 廉价重放；只省算力，security_events 照写。';
COMMENT ON COLUMN scan_fingerprints.raw_findings_json IS '降档/例外之前的原始 findings 数组（引擎 raw_findings），重放输入。';
COMMENT ON COLUMN scan_fingerprints.first_request_id IS '首次全量检测的 request_id（溯源/调试用，可空）。';
COMMENT ON COLUMN scan_fingerprints.last_seen_at IS '最近一次命中时间；worker fpclean 按此清理超留存期行。';
COMMENT ON COLUMN scan_fingerprints.hit_count IS '累计命中次数（含首见），ON CONFLICT 时 +1。';
