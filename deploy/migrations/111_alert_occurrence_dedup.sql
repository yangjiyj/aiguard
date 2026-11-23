-- 108_alert_occurrence_dedup.sql
-- 安全三视图重构 P1-D（契约第 6 条）：告警主指标改口径的数据模型。
--  * security_events 加 alert_group_id / principal_key / conversation_key（均可空）：
--    - alert_group_id：桥 UpsertOpen 成功后回填（UPDATE），供告警详情"发生明细"直查；
--      被抑制/FP 静默的事件恒为 NULL（证据不减量，只是不进组）。
--    - principal_key：各写入点 Go 侧物化 COALESCE(user_id, client_id, source_ip)。
--      注：102 已加过该列（varchar(160)），此处 IF NOT EXISTS 兜底以逐字对齐契约文本，实际为 no-op。
--    - conversation_key：A 路由网关用 shared-go/aiconvo 计算物化；proxy/反代路径暂空，
--      计数口径统一 COUNT(DISTINCT COALESCE(conversation_key, request_id))。
--  * alert_groups 加 distinct_occurrences / affected_users / last_calc_at：
--    幂等重算结果（桥 at-least-once，绝不增量 +1）；last_calc_at IS NULL = 存量回算
--    尚未覆盖（UI 显示 occurrence_count 兜底并标注"回算中"）。
-- 纯附加幂等：全部 IF NOT EXISTS；无 CONCURRENTLY，由 migration-runner 事务包裹。

ALTER TABLE security_events ADD COLUMN IF NOT EXISTS alert_group_id   TEXT;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS principal_key    TEXT;
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS conversation_key TEXT;

-- 发生明细分页直查 WHERE tenant_id=? AND alert_group_id=?；部分索引避免给未进组行（多数）建项
CREATE INDEX IF NOT EXISTS idx_security_events_alert_group
    ON security_events(tenant_id, alert_group_id)
    WHERE alert_group_id IS NOT NULL;

ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS distinct_occurrences INTEGER;
ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS affected_users       INTEGER;
ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS last_calc_at         TIMESTAMPTZ;

COMMENT ON COLUMN security_events.alert_group_id IS '所属告警组（桥 UpsertOpen 成功后回填；被抑制/FP 静默的事件恒为 NULL）';
COMMENT ON COLUMN security_events.conversation_key IS '会话归组键（aiconvo.ConversationKey；A 路物化，proxy/反代暂空）';
COMMENT ON COLUMN alert_groups.distinct_occurrences IS '独立事发次数=COUNT(DISTINCT COALESCE(conversation_key, request_id))，幂等重算';
COMMENT ON COLUMN alert_groups.affected_users IS '涉及人数=COUNT(DISTINCT principal_key)（空值不计），幂等重算';
COMMENT ON COLUMN alert_groups.last_calc_at IS '上次重算时间；NULL=存量回算未覆盖（UI 显示回算中）';
