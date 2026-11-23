-- 079_drop_dead_indexes.sql
-- +goose Up
-- 删除结构性死索引(任何部署都安全,非凭单机使用习惯):
--   ① idx_request_logs_access_retention_type: 被 forward_acctype_created 取代
--      (代码已迁到 proxy_access_type_resolved 列,旧的 proxy_access_type 索引永不命中);
--   ② idx_request_logs_forward_proxy_target: 目标host过滤走 LIKE,btree等值索引用不上。
-- 回收 ~113MB + 减轻每次写入的索引维护。非 CONCURRENTLY(drop 仅毫秒级元数据锁)。
DROP INDEX IF EXISTS idx_request_logs_access_retention_type;
DROP INDEX IF EXISTS idx_request_logs_forward_proxy_target;

-- +goose Down
CREATE INDEX IF NOT EXISTS idx_request_logs_access_retention_type ON request_logs (tenant_id, proxy_access_type, created_at DESC) WHERE ((proxy_mode)::text = 'forward'::text);
CREATE INDEX IF NOT EXISTS idx_request_logs_forward_proxy_target ON request_logs (tenant_id, proxy_target_host, created_at DESC) WHERE ((proxy_mode)::text = 'forward'::text);
