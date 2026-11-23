BEGIN;
-- 先回退应用版本，再执行本脚本。会销毁全部脱敏原文留证（不可恢复）；不触及 content_logs 与审计记录。
DROP TABLE IF EXISTS content_raw_evidence;
DELETE FROM system_settings WHERE key = 'raw_evidence_enabled';
COMMIT;
