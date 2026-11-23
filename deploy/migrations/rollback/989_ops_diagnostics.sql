BEGIN;
-- 先回退应用版本，再删除诊断会话与设置；不触及任何业务表与审计记录。
DROP TABLE IF EXISTS diag_sessions, diag_settings;
COMMIT;
