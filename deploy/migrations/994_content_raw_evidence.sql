BEGIN;

-- 994_content_raw_evidence.sql
-- 脱敏原文留证（客户要求：发给 AI 的是脱敏文本，但内容留痕必须能看到原文以便溯源定位）。
--
-- 改法（全部为新增，不改动任何现有表）：
--   * 新表 content_raw_evidence：命中脱敏或被阻断的输入/输出，另存一份加密原文（enc:v3:，AES-GCM / SM4-GCM，
--     密钥由平台数据加密密钥域分离派生，AAD 绑定 租户|请求|用户|会话|方向|序号|处置，密文搬到别的行或改挂用户都解不开）。
--   * message_index：输入为客户端协议里的消息序号（-1 表示 system/instructions 这类没有协议序号的消息，-2 表示工具定义），输出为 choice 序号。
--   * content_hmac 是租户内原文的 HMAC-SHA256（密钥由数据加密密钥域分离派生），只用于去重，不存无盐摘要，
--     接口也不返回它；超长原文截断到 512K 字符，content_truncated 标记并在 original_chars 记原始长度。
--   * 正文只存密文；明文原文不进 content_logs、security_events、缓存、语义裁判、规则包与日志。
--   * 不加外键到 request_logs：被阻断请求没有对话内容行，也要能留证；保留期与 content_logs 同一个
--     log_retention_days，由控制面保留期任务按 created_at 一并清理。
--   * 独立开关 system_settings.raw_evidence_enabled，默认 true（新装与升级一致）；关闭后只停止新增，
--     已存留证按保留期自然过期，不立即删除。
-- 回滚：deploy/migrations/rollback/994_content_raw_evidence.sql 删除该表与开关（原文留证随之销毁）。

CREATE TABLE IF NOT EXISTS content_raw_evidence (
    id                 VARCHAR(64) PRIMARY KEY DEFAULT ('cre_'::text || substr((gen_random_uuid())::text, 1, 16)),
    tenant_id          VARCHAR(64) NOT NULL,
    request_id         VARCHAR(64) NOT NULL,
    session_id         VARCHAR(255),
    user_id            VARCHAR(64),
    direction          VARCHAR(8)  NOT NULL,
    role               VARCHAR(32) NOT NULL,
    message_index      INTEGER     NOT NULL DEFAULT 0,
    disposition        VARCHAR(8)  NOT NULL,
    block_id           VARCHAR(64),
    rule_ids           TEXT[]      NOT NULL DEFAULT '{}',
    rule_names         TEXT[]      NOT NULL DEFAULT '{}',
    categories         TEXT[]      NOT NULL DEFAULT '{}',
    content_ciphertext TEXT,
    content_hmac       BYTEA       NOT NULL,
    content_chars      INTEGER     NOT NULL DEFAULT 0,
    content_truncated  BOOLEAN     NOT NULL DEFAULT FALSE,
    original_chars     INTEGER     NOT NULL DEFAULT 0,
    environment_scope  VARCHAR(32) NOT NULL DEFAULT 'legacy-unclassified',
    ref_evidence_id    VARCHAR(64),
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT content_raw_evidence_direction_check CHECK (direction IN ('input', 'output')),
    CONSTRAINT content_raw_evidence_disposition_check CHECK (disposition IN ('masked', 'blocked')),
    CONSTRAINT content_raw_evidence_cipher_check CHECK (
        (ref_evidence_id IS NULL AND content_ciphertext IS NOT NULL AND content_ciphertext LIKE 'enc:v3:%')
        OR (ref_evidence_id IS NOT NULL AND content_ciphertext IS NULL)),
    CONSTRAINT content_raw_evidence_hmac_len CHECK (octet_length(content_hmac) = 32),
    CONSTRAINT content_raw_evidence_chars_check CHECK (original_chars >= content_chars),
    CONSTRAINT content_raw_evidence_message_index_range CHECK (message_index >= -2)
);

-- 同一请求同一位置同一处置只留一份（网关重试不重复写）。
CREATE UNIQUE INDEX IF NOT EXISTS uq_content_raw_evidence_slot
    ON content_raw_evidence (tenant_id, request_id, direction, message_index, disposition);
-- 去重：同一租户、同一会话（网关无会话时写请求编号）、同一方向与处置下同一原文只存一份。
-- 智能体多轮对话每轮都会重发并重新脱敏同一段 tool_result，不去重时每轮各存一份（单行最大约 1.5MB）。
-- 后续请求只写一行引用（ref_evidence_id 指向首条，不含密文，约数百字节），按后续请求 ID 仍能定位与查看。
CREATE UNIQUE INDEX IF NOT EXISTS uq_content_raw_evidence_dedup
    ON content_raw_evidence (tenant_id, session_id, direction, disposition, content_hmac) WHERE ref_evidence_id IS NULL;
CREATE INDEX IF NOT EXISTS idx_content_raw_evidence_tenant_created
    ON content_raw_evidence (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_content_raw_evidence_block
    ON content_raw_evidence (tenant_id, block_id) WHERE block_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_content_raw_evidence_created
    ON content_raw_evidence (created_at);

-- 独立开关：升级后存量部署同样默认开启（与新装一致）；已有显式取值则保持不变。
INSERT INTO system_settings (key, value)
VALUES ('raw_evidence_enabled', 'true')
ON CONFLICT (key) DO NOTHING;

COMMIT;
