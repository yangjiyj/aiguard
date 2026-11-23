-- 103_alert_lifecycle_indexes.sql
-- P0-A 索引（CREATE INDEX CONCURRENTLY，单独文件，不进事务）。
-- migration-runner.sh 的 requires_no_outer_transaction 识别 CONCURRENTLY → 走不包事务路径。
-- 评审修正：CONCURRENTLY IF NOT EXISTS 对 INVALID 残留索引不可重入（见到同名 INVALID 即跳过、永不重建）。
--   故每条前置 DROP INDEX IF EXISTS 回收可能的 INVALID 残留（元数据操作，快），保证整文件可安全重跑。

DROP INDEX IF EXISTS idx_alert_groups_ttl;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alert_groups_ttl
  ON alert_groups (tenant_id, last_seen_at)
  WHERE status IN ('open', 'acknowledged') AND NOT is_canary AND NOT hard_floor;

DROP INDEX IF EXISTS idx_alert_groups_class;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alert_groups_class
  ON alert_groups (tenant_id, class_key)
  WHERE status IN ('open', 'acknowledged');

DROP INDEX IF EXISTS idx_alert_groups_disp;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alert_groups_disp
  ON alert_groups (tenant_id, disposition_class, effective_severity);

DROP INDEX IF EXISTS idx_secevt_principal;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_secevt_principal
  ON security_events (tenant_id, principal_key, created_at DESC);
