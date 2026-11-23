-- M3-B Phase-2/3：门户上传留痕专用表。
-- security_events 表有 5 个外键强耦合 chat 流（request_logs/users/rules/projects/tenants），
-- upload 留痕无对应 chat 实体，强行写入代价高且污染语义。
-- 本表为轻量留痕，仅 tenant_id 弱关联（不加外键，避免跨租户清理依赖），user_id 作归因主键。
-- audit-only：命中策略只记摘要，不拦上传（hard_floor 标记事后人工处置）。
CREATE TABLE IF NOT EXISTS portal_upload_events (
    id            VARCHAR(64)  NOT NULL,
    tenant_id     VARCHAR(64)  NOT NULL,
    user_id       VARCHAR(64)  NOT NULL,
    filename      VARCHAR(255) NOT NULL,
    mime_type     VARCHAR(128) NOT NULL,
    size          BIGINT       NOT NULL,
    sha256        VARCHAR(64)  NOT NULL,
    reference_key TEXT         NOT NULL,
    model         VARCHAR(128),
    action_taken  VARCHAR(32)  NOT NULL,
    findings_json JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    CONSTRAINT portal_upload_events_pkey PRIMARY KEY (id)
);

CREATE INDEX IF NOT EXISTS idx_portal_upload_events_tenant_user_created
    ON portal_upload_events (tenant_id, user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_portal_upload_events_sha256
    ON portal_upload_events (tenant_id, sha256);
