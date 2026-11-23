-- deploy/migrations/rollback/1007_request_logs_risk_columns_pending_index.sql
-- 删除留存预算列待算行的部分索引；回退后周期补算按原方式顺序扫描。
DROP INDEX CONCURRENTLY IF EXISTS idx_request_logs_risk_columns_pending;
