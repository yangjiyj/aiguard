-- 108: 内容留证按 conversation_id 聚合查询索引。
-- 支持会话代表行、成员列表、轮次统计和风险汇总；仅覆盖可可靠聚合的非空会话键。
-- CONCURRENTLY 避免在生产 access_content_logs 上阻塞正常写入；本文件不可包显式事务。
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_access_content_logs_conversation
    ON access_content_logs (tenant_id, conversation_id, created_at DESC, request_id)
    WHERE conversation_id IS NOT NULL;
