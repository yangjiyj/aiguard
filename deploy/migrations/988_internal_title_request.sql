BEGIN;

-- NULL 表示尚未判定，读侧保留原规则回退；不在迁移事务内扫描正文或全量回填。
ALTER TABLE request_logs ADD COLUMN internal_title_request BOOLEAN;
COMMENT ON COLUMN request_logs.internal_title_request IS '内部标题/摘要请求；NULL 待判定，规则由 shared-go/internaltitle 统一维护';
CREATE INDEX idx_request_logs_internal_title_pending
    ON request_logs (created_at DESC, id DESC) WHERE internal_title_request IS NULL;

COMMIT;
