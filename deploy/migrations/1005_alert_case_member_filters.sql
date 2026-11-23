BEGIN;

-- 1005_alert_case_member_filters: 告警案件物化支持按用户、会话、会话键筛选（2.9.22 批次 7）。
--
-- 告警页按用户（user_id）、会话（session_id）、会话键（conversation_key）筛选时，案件只按命中这些条件的命中
-- 聚合，过去只能实时查询（租户全部历史重算）。这里给 alert_case_members 加上与实时查询同口径的操作人、
-- 请求会话、端点会话三列并建索引；会话键已有列。列由控制面重算时写入：控制面的物化口径指纹随之变化，
-- 启动后自动重建全部物化结果，重建完成前读接口实时查询。
-- 只给新表加列和索引。回滚：deploy/migrations/rollback/1005_alert_case_member_filters.sql。

ALTER TABLE alert_case_members
    ADD COLUMN IF NOT EXISTS actor_user_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS filter_session_id TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS endpoint_session_id TEXT NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS idx_alert_case_members_actor
    ON alert_case_members (tenant_id, actor_user_id) WHERE actor_user_id <> '';
CREATE INDEX IF NOT EXISTS idx_alert_case_members_session
    ON alert_case_members (tenant_id, filter_session_id) WHERE filter_session_id <> '';
CREATE INDEX IF NOT EXISTS idx_alert_case_members_endpoint_session
    ON alert_case_members (tenant_id, endpoint_session_id) WHERE endpoint_session_id <> '';
CREATE INDEX IF NOT EXISTS idx_alert_case_members_conversation_key
    ON alert_case_members (tenant_id, conversation_key) WHERE conversation_key <> '';

COMMIT;
