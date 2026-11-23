BEGIN;

-- 运维诊断机器人：会话与按租户设置。全部为新表，不改动业务表。
CREATE TABLE IF NOT EXISTS diag_sessions (
    id            VARCHAR(64) PRIMARY KEY,
    tenant_id     VARCHAR(64) NOT NULL,
    user_id       VARCHAR(64) NOT NULL,
    is_admin      BOOLEAN NOT NULL,
    input_json    JSONB NOT NULL,
    status        VARCHAR(16) NOT NULL,           -- running | done | failed
    tier          VARCHAR(4),
    report_json   JSONB,
    steps_json    JSONB,                          -- 含工具输出（已脱敏），仅供诊断包使用，不下发前端
    messages_json JSONB NOT NULL DEFAULT '[]',    -- 追问历史
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at   TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_diag_sessions_user ON diag_sessions (tenant_id, user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_diag_sessions_created ON diag_sessions (created_at);

CREATE TABLE IF NOT EXISTS diag_settings (
    tenant_id      VARCHAR(64) PRIMARY KEY,
    ai_enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    model_id       VARCHAR(64),
    selfcheck_json JSONB,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMIT;
