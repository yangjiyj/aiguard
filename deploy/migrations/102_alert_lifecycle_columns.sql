-- 102_alert_lifecycle_columns.sql
-- P0-A 告警生命周期重设计：
--   * alert_groups 加情境/分档/三闸列（effective_severity/disposition_class/class_key/
--     principal_key/is_canary/stage/hard_floor），供可行动性闸门与 TTL 自动关闭使用；
--   * security_events 加写入侧冗余主体/情境列（principal_key/effective_severity/class_key），
--     避免自适应基线每次 join 大表；
--   * 放宽 alert_groups.severity CHECK 以容纳 effective_severity 用到的 low/medium。
-- 全部 IF NOT EXISTS，幂等；无 CONCURRENTLY，由 migration-runner 事务包裹（原子可回滚）。
-- 说明：不引入 closed 状态，status CHECK 保持 open/acknowledged/resolved/false_positive 不变；
--       自动/人工关闭统一落 resolved（自动关用 disposition_by='system_ttl' 区分）。

ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS effective_severity varchar(16);
ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS disposition_class  varchar(24);
ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS class_key          varchar(64);
ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS principal_key      varchar(160);
ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS is_canary          boolean NOT NULL DEFAULT false;
ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS stage              varchar(12);
ALTER TABLE alert_groups ADD COLUMN IF NOT EXISTS hard_floor         boolean NOT NULL DEFAULT false;

ALTER TABLE alert_groups DROP CONSTRAINT IF EXISTS alert_groups_severity_check;
ALTER TABLE alert_groups ADD  CONSTRAINT alert_groups_severity_check
  CHECK (severity IN ('info','warning','low','medium','high','critical'));

ALTER TABLE alert_groups DROP CONSTRAINT IF EXISTS alert_groups_eff_sev_check;
ALTER TABLE alert_groups ADD  CONSTRAINT alert_groups_eff_sev_check
  CHECK (effective_severity IS NULL OR effective_severity IN ('low','medium','high','critical'));

ALTER TABLE alert_groups DROP CONSTRAINT IF EXISTS alert_groups_disp_class_check;
ALTER TABLE alert_groups ADD  CONSTRAINT alert_groups_disp_class_check
  CHECK (disposition_class IS NULL OR disposition_class IN ('action_required','informational','suppressed'));

ALTER TABLE alert_groups DROP CONSTRAINT IF EXISTS alert_groups_stage_check;
ALTER TABLE alert_groups ADD  CONSTRAINT alert_groups_stage_check
  CHECK (stage IS NULL OR stage IN ('input','output','tool'));

ALTER TABLE security_events ADD COLUMN IF NOT EXISTS principal_key      varchar(160);
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS effective_severity varchar(16);
ALTER TABLE security_events ADD COLUMN IF NOT EXISTS class_key          varchar(64);
