-- 096_request_logs_source_ip_indexes.sql
-- 为按源 IP / api-key(client_id) 过滤的评测审计查询建检索索引。
--
-- 含 CONCURRENTLY，不可在事务内执行：CREATE INDEX CONCURRENTLY 不能跑在显式事务块里。
-- migration-runner.sh 的 requires_no_outer_transaction() 会识别 CONCURRENTLY 并走
-- apply_file_plain（不包 BEGIN/COMMIT），因此本文件可由 runner 正常应用。
-- 全部带 IF NOT EXISTS，重复执行安全；partial index 跳过空值行，省空间。

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_tenant_source_ip_created
    ON request_logs (tenant_id, source_ip, created_at DESC)
    WHERE source_ip IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_tenant_proxy_source_ip_created
    ON request_logs (tenant_id, proxy_source_ip, created_at DESC)
    WHERE proxy_source_ip IS NOT NULL;

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_request_logs_tenant_client_id_created
    ON request_logs (tenant_id, client_id, created_at DESC)
    WHERE client_id IS NOT NULL;
