-- 093: access_content_logs turn 分组读侧索引（SP4 读侧 turn 分组投影依赖）。
-- 与生产现存索引定义一致；IF NOT EXISTS 幂等（生产已手工建过=空操作，仅补离线/复现可重建性）。
-- 部分索引（conversation_id IS NOT NULL）只覆盖可分组行，体积小；非 CONCURRENTLY 以兼容事务式迁移运行器，
-- 全新安装时表空/小，建索引开销可忽略。
CREATE INDEX IF NOT EXISTS idx_access_content_logs_turn
    ON access_content_logs (tenant_id, conversation_id, section_id, created_at DESC, request_id)
    WHERE conversation_id IS NOT NULL;
