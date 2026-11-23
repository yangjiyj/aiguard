-- 130_security_event_occurrences.sql
-- 重复检测信号与完整安全事件分离：
--   1. scan_fingerprints 按语义 revision + 稳定上下文隔离；
--   2. 首次命中保留完整 security_event；
--   3. 后续相同上下文仅写幂等 occurrence，告警组建立前允许挂账。

ALTER TABLE scan_fingerprints
    ADD COLUMN IF NOT EXISTS semantic_config_revision TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS context_scope TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS context_key TEXT,
    ADD COLUMN IF NOT EXISTS first_security_event_id TEXT;

DO $$
DECLARE
    current_pk TEXT;
BEGIN
    SELECT pg_get_constraintdef(oid)
      INTO current_pk
      FROM pg_constraint
     WHERE conrelid = 'scan_fingerprints'::regclass
       AND contype = 'p'
     LIMIT 1;

    IF current_pk IS NULL OR position('semantic_config_revision' IN current_pk) = 0 THEN
        ALTER TABLE scan_fingerprints DROP CONSTRAINT IF EXISTS scan_fingerprints_pkey;
        ALTER TABLE scan_fingerprints
            ADD CONSTRAINT scan_fingerprints_pkey PRIMARY KEY (
                tenant_id,
                content_sha256,
                rule_pack_version,
                engine_build,
                semantic_config_revision,
                context_scope
            );
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS security_event_occurrences (
    tenant_id               TEXT        NOT NULL,
    representative_event_id TEXT        NOT NULL,
    request_id              TEXT        NOT NULL,
    principal_key           TEXT,
    conversation_key        TEXT,
    context_key             TEXT        NOT NULL,
    alert_group_id          TEXT,
    occurred_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, representative_event_id, request_id)
);

CREATE INDEX IF NOT EXISTS idx_security_event_occurrences_pending
    ON security_event_occurrences (tenant_id, representative_event_id)
    WHERE alert_group_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_security_event_occurrences_group
    ON security_event_occurrences (tenant_id, alert_group_id, occurred_at DESC)
    WHERE alert_group_id IS NOT NULL;

COMMENT ON TABLE security_event_occurrences IS
    '重复安全信号轻量发生账本；每个 request 对同一代表事件最多一条，告警组建立前可挂账。';
COMMENT ON COLUMN security_event_occurrences.representative_event_id IS
    '首次完整 security_event 的 id；不设外键以容忍异步 outbox 先后顺序。';
COMMENT ON COLUMN security_event_occurrences.context_key IS
    '规则版本、语义 revision、actor/source、主体与处置结果共同形成的稳定上下文摘要。';
