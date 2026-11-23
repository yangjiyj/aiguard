BEGIN;
-- 先回退应用版本，再移除派生列；不修改任何正文、审计或证据。
DROP INDEX IF EXISTS idx_request_logs_internal_title_pending;
ALTER TABLE request_logs DROP COLUMN internal_title_request;
COMMIT;
