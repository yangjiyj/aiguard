-- +goose NO TRANSACTION
-- 1007_request_logs_risk_columns_pending_index: 留存预算列待算行的部分索引（2.9.22 批次 7）。
--
-- 1006 的触发器在正文、留存会话、安全事件变化时把 request_logs 的预算列置空，控制面周期任务按本索引
-- 找到这些行重新计算（BackfillRiskColumns），不再顺序扫描整张请求表。索引只含待算行，平时很小。
-- CONCURRENTLY 不阻塞请求写入，必须在事务外执行；中断留下的无效索引先改名再删，重跑可恢复。
-- 回滚：deploy/migrations/rollback/1007_request_logs_risk_columns_pending_index.sql。

DROP INDEX CONCURRENTLY IF EXISTS idx_request_logs_risk_columns_pending_invalid_guard;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid
    WHERE c.relname = 'idx_request_logs_risk_columns_pending' AND NOT i.indisvalid
  ) THEN
    ALTER INDEX idx_request_logs_risk_columns_pending RENAME TO idx_request_logs_risk_columns_pending_invalid_guard;
  END IF;
END
$$;

DROP INDEX CONCURRENTLY IF EXISTS idx_request_logs_risk_columns_pending_invalid_guard;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_risk_columns_pending
    ON request_logs (id)
    WHERE risk_state IS NULL OR risk_reasons IS NULL OR request_body_exists IS NULL OR response_body_exists IS NULL;
