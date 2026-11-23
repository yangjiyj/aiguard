BEGIN;

-- 987_content_logs_body_dedup.sql
-- 客户现场 2026-10-22：Claude Code 等客户端每个请求都带整段对话历史，content_logs 一天约 46.6 万行，
-- 同租户相同内容去重后只剩约 1.6%（系统提示词每轮重发、历史工具输出重发）；表 6.6 GB，其中索引 4.2 GB，
-- 最大的 GIN 三元组索引 1.8 GB 自 10-15 起扫描次数为 0。磁盘慢时写入放大直接拖垮整机。
--
-- 改法（读方零改动）：
--   * 原表改名 content_logs_legacy（瞬间完成，不搬数据）；历史行按保留期自然清理。
--   * 新行写入 content_log_entries（不带正文）+ content_log_bodies（同租户同内容只存一份）。
--   * 同名视图 content_logs = entries⋈bodies ∪ legacy，列名、类型、默认值与原表一致，
--     50 个读方看到的行与列完全一样；INSERT/UPDATE/DELETE 由 INSTEAD OF 触发器转发。
--   * 原 content_logs 上的两个派生触发器（客户内容投影、证据索引）在 entries 与历史表上都保留，触发时机与语义不变。
--   * 不再为新表建从未使用的索引：三元组 GIN、(tenant_id, created_at)、(user_id)、(session_id)。
--   * 正文不随单行删除立即回收；保留期清理调用 prune_content_log_bodies() 删除无人引用的正文。
--   * 依赖本迁移的代码：控制面保留期清理直接分批删两张底表；worker 环境标记回填分别锁两张底表。
-- 回滚：deploy/migrations/rollback/987_content_logs_body_dedup.sql 把 entries 还原回单表。

-- 1. 原表改名，并把它的序列/约束/索引名保持不变（读方只经视图访问）。
ALTER TABLE content_logs RENAME TO content_logs_legacy;

-- 2. 正文表：同租户同内容一份。customer_text 预先算好，供部分索引与客户内容投影使用。
CREATE TABLE content_log_bodies (
    tenant_id      VARCHAR(64) NOT NULL,
    content_sha256 BYTEA       NOT NULL,
    content        TEXT        NOT NULL,
    customer_text  BOOLEAN     NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, content_sha256),
    CONSTRAINT content_log_bodies_sha256_len CHECK (octet_length(content_sha256) = 32)
);

-- 3. 消息行表：与原表列一致，正文换成摘要引用。
CREATE TABLE content_log_entries (
    id                VARCHAR(64) PRIMARY KEY DEFAULT ('cl_'::text || substr((gen_random_uuid())::text, 1, 12)),
    request_id        VARCHAR(64) NOT NULL REFERENCES request_logs(id) ON DELETE CASCADE,
    tenant_id         VARCHAR(64) NOT NULL,
    user_id           VARCHAR(64),
    session_id        VARCHAR(255),
    role              VARCHAR(32) NOT NULL,
    content_sha256    BYTEA       NOT NULL,
    customer_text     BOOLEAN     NOT NULL,
    tokens            INTEGER DEFAULT 0,
    created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    environment_scope VARCHAR(32) NOT NULL DEFAULT 'legacy-unclassified',
    message_index     INTEGER,
    CONSTRAINT content_log_entries_body_fk FOREIGN KEY (tenant_id, content_sha256)
        REFERENCES content_log_bodies (tenant_id, content_sha256),
    CONSTRAINT content_log_entries_environment_scope_check
        CHECK (environment_scope IN ('customer', 'home', 'claude', 'codex', 'legacy-unclassified')),
    CONSTRAINT content_log_entries_message_index_nonnegative_check
        CHECK (message_index IS NULL OR message_index >= 0)
);

-- 与原表在用的索引一一对应（扫描次数为 0 的四个不再建）。
CREATE INDEX idx_content_log_entries_request_created ON content_log_entries (request_id, created_at DESC);
CREATE INDEX idx_content_log_entries_projection_lookup ON content_log_entries (tenant_id, request_id, role);
CREATE INDEX idx_content_log_entries_tenant_role_request ON content_log_entries (tenant_id, role, request_id, created_at);
CREATE INDEX idx_content_log_entries_tenant_request_session_latest ON content_log_entries (tenant_id, request_id, created_at DESC)
    INCLUDE (session_id, user_id) WHERE session_id IS NOT NULL;
CREATE INDEX idx_content_log_entries_tenant_session_user_created ON content_log_entries (tenant_id, session_id, created_at)
    WHERE role = 'user' AND session_id IS NOT NULL;
CREATE INDEX idx_content_log_entries_customer_text ON content_log_entries (tenant_id, request_id, role, created_at, id)
    WHERE role IN ('user', 'assistant') AND customer_text;
CREATE INDEX idx_content_log_entries_tenant_scope_created ON content_log_entries (tenant_id, environment_scope, created_at DESC);
CREATE INDEX idx_content_log_entries_created ON content_log_entries (created_at DESC);
CREATE INDEX idx_content_log_entries_tenant ON content_log_entries (tenant_id);
CREATE INDEX idx_content_log_entries_body ON content_log_entries (tenant_id, content_sha256);

-- 4. 兼容视图：列顺序、名称、类型与原表一致。
CREATE VIEW content_logs AS
    SELECT e.id, e.request_id, e.tenant_id, e.user_id, e.session_id, e.role, b.content, e.tokens,
           e.created_at, e.environment_scope, e.message_index
    FROM content_log_entries e
    JOIN content_log_bodies b ON b.tenant_id = e.tenant_id AND b.content_sha256 = e.content_sha256
    UNION ALL
    SELECT l.id, l.request_id, l.tenant_id, l.user_id, l.session_id, l.role, l.content, l.tokens,
           l.created_at, l.environment_scope, l.message_index
    FROM content_logs_legacy l;

ALTER VIEW content_logs ALTER COLUMN id SET DEFAULT ('cl_'::text || substr((gen_random_uuid())::text, 1, 12));
ALTER VIEW content_logs ALTER COLUMN tokens SET DEFAULT 0;
ALTER VIEW content_logs ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP;
ALTER VIEW content_logs ALTER COLUMN environment_scope SET DEFAULT 'legacy-unclassified';

-- 5. 写入转发：先确保正文存在（同内容复用），再写消息行。
-- 正文复用时先 FOR KEY SHARE 锁住已有正文，没有才插入：与 prune_content_log_bodies 的
-- FOR UPDATE SKIP LOCKED 配合，正在被引用的正文不会被并发回收；正在回收的正文等回收提交后
-- 在这里重新插入，消息行的外键检查不会因为回收而失败。
CREATE OR REPLACE FUNCTION content_log_body_ensure(
    p_tenant_id VARCHAR, p_content TEXT, OUT o_sha256 BYTEA, OUT o_customer BOOLEAN
)
LANGUAGE plpgsql
AS $$
DECLARE
    v_attempt INTEGER := 0;
BEGIN
    o_sha256 := sha256(convert_to(p_content, 'UTF8'));
    LOOP
        SELECT b.customer_text INTO o_customer
        FROM content_log_bodies b
        WHERE b.tenant_id = p_tenant_id AND b.content_sha256 = o_sha256
        FOR KEY SHARE;
        IF FOUND THEN
            RETURN;
        END IF;
        o_customer := jjdguard_customer_content_text(p_content);
        INSERT INTO content_log_bodies (tenant_id, content_sha256, content, customer_text)
        VALUES (p_tenant_id, o_sha256, p_content, o_customer)
        ON CONFLICT (tenant_id, content_sha256) DO NOTHING;
        IF FOUND THEN
            RETURN;
        END IF;
        v_attempt := v_attempt + 1;
        IF v_attempt >= 5 THEN
            RAISE EXCEPTION 'content_log_bodies: could not reference body after % attempts', v_attempt
                USING ERRCODE = 'serialization_failure';
        END IF;
    END LOOP;
END;
$$;

CREATE OR REPLACE FUNCTION content_logs_view_insert()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_sha256 BYTEA;
    v_customer BOOLEAN;
BEGIN
    IF NEW.content IS NULL THEN
        RAISE EXCEPTION 'content_logs.content must not be null' USING ERRCODE = 'not_null_violation';
    END IF;
    SELECT o_sha256, o_customer INTO v_sha256, v_customer
    FROM content_log_body_ensure(NEW.tenant_id, NEW.content);
    INSERT INTO content_log_entries (
        id, request_id, tenant_id, user_id, session_id, role, content_sha256, customer_text,
        tokens, created_at, environment_scope, message_index
    ) VALUES (
        COALESCE(NEW.id, 'cl_'::text || substr((gen_random_uuid())::text, 1, 12)),
        NEW.request_id, NEW.tenant_id, NEW.user_id, NEW.session_id, NEW.role, v_sha256, v_customer,
        COALESCE(NEW.tokens, 0), COALESCE(NEW.created_at, CURRENT_TIMESTAMP),
        COALESCE(NEW.environment_scope, 'legacy-unclassified'), NEW.message_index
    );
    RETURN NEW;
END;
$$;

-- UPDATE：只允许改元数据与正文（正文改动转成新的正文引用）；对新旧两张底表都生效。
CREATE OR REPLACE FUNCTION content_logs_view_update()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_sha256 BYTEA;
    v_customer BOOLEAN;
BEGIN
    IF NEW.content IS NULL THEN
        RAISE EXCEPTION 'content_logs.content must not be null' USING ERRCODE = 'not_null_violation';
    END IF;
    IF NEW.content IS DISTINCT FROM OLD.content OR NEW.tenant_id IS DISTINCT FROM OLD.tenant_id THEN
        SELECT o_sha256, o_customer INTO v_sha256, v_customer
        FROM content_log_body_ensure(NEW.tenant_id, NEW.content);
    END IF;
    UPDATE content_log_entries e SET
        request_id = NEW.request_id, tenant_id = NEW.tenant_id, user_id = NEW.user_id,
        session_id = NEW.session_id, role = NEW.role,
        content_sha256 = COALESCE(v_sha256, e.content_sha256),
        customer_text = COALESCE(v_customer, e.customer_text),
        tokens = NEW.tokens, created_at = NEW.created_at,
        environment_scope = NEW.environment_scope, message_index = NEW.message_index
    WHERE e.id = OLD.id;
    IF NOT FOUND THEN
        UPDATE content_logs_legacy l SET
            request_id = NEW.request_id, tenant_id = NEW.tenant_id, user_id = NEW.user_id,
            session_id = NEW.session_id, role = NEW.role, content = NEW.content,
            tokens = NEW.tokens, created_at = NEW.created_at,
            environment_scope = NEW.environment_scope, message_index = NEW.message_index
        WHERE l.id = OLD.id;
    END IF;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION content_logs_view_delete()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    DELETE FROM content_log_entries WHERE id = OLD.id;
    IF NOT FOUND THEN
        DELETE FROM content_logs_legacy WHERE id = OLD.id;
    END IF;
    RETURN OLD;
END;
$$;

CREATE TRIGGER content_logs_view_insert INSTEAD OF INSERT ON content_logs
    FOR EACH ROW EXECUTE FUNCTION content_logs_view_insert();
CREATE TRIGGER content_logs_view_update INSTEAD OF UPDATE ON content_logs
    FOR EACH ROW EXECUTE FUNCTION content_logs_view_update();
CREATE TRIGGER content_logs_view_delete INSTEAD OF DELETE ON content_logs
    FOR EACH ROW EXECUTE FUNCTION content_logs_view_delete();

-- 6. 派生触发器。原函数按 TG_TABLE_NAME = 'content_logs' 分支，改名后的历史表和新的消息行表都不再叫这个名字：
--    * 客户内容投影：用同语义的薄包装按行取 tenant/request 再调用投影函数，消息行表与历史表共用；
--      投影函数改为直接查两张底表，新行用预先算好的 customer_text（命中部分索引），历史行仍按正文判断。
--    * 证据索引：历史表沿用原触发器，函数里把 'content_logs_legacy' 并入原分支；消息行表新增分支从正文表取正文。
CREATE OR REPLACE FUNCTION content_log_row_customer_projection()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    v_old_request VARCHAR(64);
    v_new_request VARCHAR(64);
BEGIN
    IF TG_OP IN ('DELETE', 'UPDATE') THEN
        SELECT rl.request_id INTO v_old_request FROM request_logs rl
        WHERE rl.tenant_id = OLD.tenant_id AND rl.id = OLD.request_id;
        PERFORM jjdguard_refresh_request_customer_content_projection(OLD.tenant_id, v_old_request);
    END IF;
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        SELECT rl.request_id INTO v_new_request FROM request_logs rl
        WHERE rl.tenant_id = NEW.tenant_id AND rl.id = NEW.request_id;
        IF TG_OP <> 'UPDATE' OR OLD.tenant_id IS DISTINCT FROM NEW.tenant_id OR v_old_request IS DISTINCT FROM v_new_request THEN
            PERFORM jjdguard_refresh_request_customer_content_projection(NEW.tenant_id, v_new_request);
        END IF;
    END IF;
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

-- 客户内容投影函数（986 版本 + 987 底表查询）。
CREATE OR REPLACE FUNCTION public.jjdguard_refresh_request_customer_content_projection(p_tenant_id character varying, p_request_id character varying)
 RETURNS void
 LANGUAGE plpgsql
AS $$
BEGIN
    -- Serialize sibling evidence writes before acquiring the snapshot used by
    -- the UPDATE below. One UPDATE alone can wait on the row and still evaluate
    -- its child-table EXISTS clauses against its pre-wait READ COMMITTED snapshot.
    -- NO KEY UPDATE remains compatible with the KEY SHARE locks taken by child
    -- foreign keys; FOR UPDATE here can deadlock two concurrent child inserts.
    PERFORM 1
    FROM request_logs rl
    WHERE rl.tenant_id = p_tenant_id
      AND rl.request_id = p_request_id
    FOR NO KEY UPDATE;

    UPDATE request_logs rl
    SET has_customer_content = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND (
                      jjdguard_customer_content_text(acl.request_content_redacted)
                      OR jjdguard_customer_content_text(acl.response_content_redacted)
                      OR COALESCE(acl.file_metadata_json, '[]'::jsonb) <> '[]'::jsonb
                  )
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND (
                    EXISTS (
                        SELECT 1
                        FROM content_log_entries e
                        WHERE e.tenant_id = rl.tenant_id
                          AND e.request_id = rl.id
                          AND e.role IN ('user', 'assistant')
                          AND e.customer_text
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM content_logs_legacy cl
                        WHERE cl.tenant_id = rl.tenant_id
                          AND cl.request_id = rl.id
                          AND cl.role IN ('user', 'assistant')
                          AND jjdguard_customer_content_text(cl.content)
                    )
                )
            )
        ),
        has_customer_request_body = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.request_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND (
                    EXISTS (
                        SELECT 1
                        FROM content_log_entries e
                        WHERE e.tenant_id = rl.tenant_id
                          AND e.request_id = rl.id
                          AND e.role = 'user'
                          AND e.customer_text
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM content_logs_legacy cl
                        WHERE cl.tenant_id = rl.tenant_id
                          AND cl.request_id = rl.id
                          AND cl.role = 'user'
                          AND jjdguard_customer_content_text(cl.content)
                    )
                )
            )
        ),
        has_customer_response_body = (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.response_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND (
                    EXISTS (
                        SELECT 1
                        FROM content_log_entries e
                        WHERE e.tenant_id = rl.tenant_id
                          AND e.request_id = rl.id
                          AND e.role = 'assistant'
                          AND e.customer_text
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM content_logs_legacy cl
                        WHERE cl.tenant_id = rl.tenant_id
                          AND cl.request_id = rl.id
                          AND cl.role = 'assistant'
                          AND jjdguard_customer_content_text(cl.content)
                    )
                )
            )
        ),
        customer_content_rule_version = 1
    WHERE rl.tenant_id = p_tenant_id
      AND rl.request_id = p_request_id
      -- 986：派生值不变就不写。987：content_logs 拆成消息行表与历史表后，直接查两张底表。长对话一个请求逐条插入上千条消息，
      -- 原来每插一条都把同一行 request_logs 整行重写一次。
      AND (rl.customer_content_rule_version IS DISTINCT FROM 1
        OR rl.has_customer_content IS DISTINCT FROM (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND (
                      jjdguard_customer_content_text(acl.request_content_redacted)
                      OR jjdguard_customer_content_text(acl.response_content_redacted)
                      OR COALESCE(acl.file_metadata_json, '[]'::jsonb) <> '[]'::jsonb
                  )
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND (
                    EXISTS (
                        SELECT 1
                        FROM content_log_entries e
                        WHERE e.tenant_id = rl.tenant_id
                          AND e.request_id = rl.id
                          AND e.role IN ('user', 'assistant')
                          AND e.customer_text
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM content_logs_legacy cl
                        WHERE cl.tenant_id = rl.tenant_id
                          AND cl.request_id = rl.id
                          AND cl.role IN ('user', 'assistant')
                          AND jjdguard_customer_content_text(cl.content)
                    )
                )
            )
        )
        OR rl.has_customer_request_body IS DISTINCT FROM (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.request_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND (
                    EXISTS (
                        SELECT 1
                        FROM content_log_entries e
                        WHERE e.tenant_id = rl.tenant_id
                          AND e.request_id = rl.id
                          AND e.role = 'user'
                          AND e.customer_text
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM content_logs_legacy cl
                        WHERE cl.tenant_id = rl.tenant_id
                          AND cl.request_id = rl.id
                          AND cl.role = 'user'
                          AND jjdguard_customer_content_text(cl.content)
                    )
                )
            )
        )
        OR rl.has_customer_response_body IS DISTINCT FROM (
            EXISTS (
                SELECT 1
                FROM access_content_logs acl
                WHERE acl.tenant_id = rl.tenant_id
                  AND acl.request_id = rl.request_id
                  AND jjdguard_customer_content_text(acl.response_content_redacted)
            )
            OR (
                COALESCE(rl.proxy_mode, '') <> 'forward'
                AND (
                    EXISTS (
                        SELECT 1
                        FROM content_log_entries e
                        WHERE e.tenant_id = rl.tenant_id
                          AND e.request_id = rl.id
                          AND e.role = 'assistant'
                          AND e.customer_text
                    )
                    OR EXISTS (
                        SELECT 1
                        FROM content_logs_legacy cl
                        WHERE cl.tenant_id = rl.tenant_id
                          AND cl.request_id = rl.id
                          AND cl.role = 'assistant'
                          AND jjdguard_customer_content_text(cl.content)
                    )
                )
            )
        ));
END;
$$;

DROP TRIGGER IF EXISTS trg_content_logs_customer_content_projection ON content_logs_legacy;

CREATE TRIGGER trg_content_log_entries_customer_content_projection
    AFTER INSERT OR DELETE OR UPDATE OF tenant_id, request_id, role, content_sha256 ON content_log_entries
    FOR EACH ROW EXECUTE FUNCTION content_log_row_customer_projection();

-- 历史表不再有新行写入，但保留期删除、视图 UPDATE 仍会改动它，投影要跟着重算（与原触发器同时机）。
CREATE TRIGGER trg_content_logs_legacy_customer_content_projection
    AFTER DELETE OR UPDATE OF tenant_id, request_id, role, content ON content_logs_legacy
    FOR EACH ROW EXECUTE FUNCTION content_log_row_customer_projection();

-- 证据索引同步：沿用 sync_evidence_run_request_index()（986 版本），原分支并入历史表名，新增 content_log_entries 分支。
CREATE OR REPLACE FUNCTION public.sync_evidence_run_request_index()
 RETURNS trigger
 LANGUAGE plpgsql
AS $$
DECLARE
    v_tenant_id VARCHAR(64);
    v_request_log_id VARCHAR(64);
    v_request_id VARCHAR(64);
    old_chain_principal VARCHAR(256);
    old_agent_type VARCHAR(64);
    old_title_hash CHAR(32);
    old_candidate BOOLEAN := FALSE;
    v_codex_match BOOLEAN := FALSE;
BEGIN
    IF TG_TABLE_NAME = 'request_logs' THEN
        v_tenant_id := NEW.tenant_id;
        v_request_log_id := NEW.id;
        v_request_id := NEW.request_id;
    ELSIF TG_TABLE_NAME IN ('content_logs', 'content_logs_legacy') THEN
        SELECT rl.tenant_id, rl.id, rl.request_id
        INTO v_tenant_id, v_request_log_id, v_request_id
        FROM request_logs rl
        WHERE rl.tenant_id = NEW.tenant_id AND rl.id = NEW.request_id
        LIMIT 1;
        v_codex_match := NEW.content ILIKE '%OpenAI Codex%'
            OR NEW.content ILIKE '%Codex Desktop%';
    ELSIF TG_TABLE_NAME = 'content_log_entries' THEN
        -- 987：消息行表不带正文，按摘要从正文表取回后做同样的 Codex 识别。
        SELECT rl.tenant_id, rl.id, rl.request_id
        INTO v_tenant_id, v_request_log_id, v_request_id
        FROM request_logs rl
        WHERE rl.tenant_id = NEW.tenant_id AND rl.id = NEW.request_id
        LIMIT 1;
        SELECT b.content ILIKE '%OpenAI Codex%' OR b.content ILIKE '%Codex Desktop%'
        INTO v_codex_match
        FROM content_log_bodies b
        WHERE b.tenant_id = NEW.tenant_id AND b.content_sha256 = NEW.content_sha256;
        v_codex_match := COALESCE(v_codex_match, FALSE);
    ELSIF TG_TABLE_NAME = 'access_content_logs' THEN
        SELECT rl.tenant_id, rl.id, rl.request_id
        INTO v_tenant_id, v_request_log_id, v_request_id
        FROM request_logs rl
        WHERE rl.tenant_id = NEW.tenant_id AND rl.request_id = NEW.request_id
        LIMIT 1;
    END IF;

    IF v_request_log_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT
        eri.chain_principal,
        eri.effective_agent_type,
        eri.title_hash,
        eri.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
    INTO old_chain_principal, old_agent_type, old_title_hash, old_candidate
    FROM evidence_run_request_index eri
    WHERE eri.tenant_id = v_tenant_id AND eri.request_log_id = v_request_log_id;

    IF old_candidate THEN
        UPDATE evidence_run_request_index eri
        SET chain_dirty = TRUE, updated_at = NOW()
        WHERE eri.tenant_id = v_tenant_id
          AND eri.chain_dirty IS DISTINCT FROM TRUE
          AND eri.chain_principal = old_chain_principal
          AND eri.effective_agent_type = old_agent_type
          AND eri.title_hash = old_title_hash
          AND eri.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate');
    END IF;

    INSERT INTO evidence_run_request_index (
        tenant_id, request_log_id, request_id, created_at,
        effective_agent_type, effective_agent_runtime, effective_detection_source, effective_detection_confidence,
        session_id, evidence_run_id, evidence_run_source, conversation_id, section_id,
        chain_principal, title_hash, transcript_signature, derived_chain_root, derived_chain_size,
        chain_dirty, updated_at
    )
    SELECT
        rl.tenant_id,
        rl.id,
        rl.request_id,
        rl.created_at,
        CASE
            WHEN LOWER(BTRIM(COALESCE(rl.agent_type, ''))) IN (
                'openai-codex', 'codex', 'codex-cli', 'openai codex'
            ) THEN 'openai-codex'
            WHEN COALESCE(rl.agent_type, '') = 'vscode' AND v_codex_match
                THEN 'openai-codex'
            ELSE COALESCE(rl.agent_type, '')
        END,
        COALESCE(NULLIF(rl.agent_runtime, ''), CASE WHEN rl.agent_type = 'vscode' THEN 'vscode' ELSE '' END),
        CASE WHEN COALESCE(rl.agent_type, '') = 'vscode' AND v_codex_match
            THEN 'content' ELSE COALESCE(rl.agent_detection_source, '') END,
        CASE WHEN COALESCE(rl.agent_type, '') = 'vscode' AND v_codex_match
            THEN 0.98 ELSE COALESCE(rl.agent_detection_confidence, 0) END,
        COALESCE(rl.session_id, ''),
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN '' ELSE COALESCE(rl.evidence_run_id, '') END,
        COALESCE(rl.evidence_run_source, ''),
        COALESCE(acl.conversation_id, ''),
        COALESCE(acl.section_id, ''),
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN COALESCE(NULLIF(rl.client_id, ''), NULLIF(rl.user_id, ''), NULLIF(rl.proxy_source_ip, ''), NULLIF(rl.source_ip, ''), rl.request_id)
            ELSE '' END,
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN md5(COALESCE(
                NULLIF(BTRIM(title_cl.content, '"'), ''),
                NULLIF(CASE WHEN jjdguard_customer_content_text(acl.request_content_redacted) THEN acl.request_content_redacted ELSE '' END, ''),
                ''
            ))
            ELSE '' END,
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN COALESCE((
                SELECT string_agg(
                    CASE WHEN cl.role IN ('user', 'assistant')
                        THEN LEFT(cl.role, 1) || ':' || md5(COALESCE(cl.content, ''))
                        ELSE LEFT(COALESCE(cl.role, 'other'), 1) || ':' || octet_length(COALESCE(cl.content, ''))::text
                    END,
                    ':' ORDER BY cl.created_at, cl.id
                )
                FROM content_logs cl
                WHERE cl.tenant_id = rl.tenant_id AND cl.request_id = rl.id
            ), '')
            ELSE '' END,
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN rl.request_id ELSE '' END,
        CASE WHEN COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
            THEN 1 ELSE 0 END,
        COALESCE(rl.evidence_run_source, '') IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate'),
        NOW()
    FROM request_logs rl
    LEFT JOIN LATERAL (
        SELECT conversation_id, section_id, request_content_redacted
        FROM access_content_logs acl_inner
        WHERE acl_inner.tenant_id = rl.tenant_id AND acl_inner.request_id = rl.request_id
        ORDER BY acl_inner.created_at DESC, acl_inner.id DESC
        LIMIT 1
    ) acl ON TRUE
    LEFT JOIN LATERAL (
        SELECT content
        FROM content_logs cl
        WHERE cl.tenant_id = rl.tenant_id
          AND cl.request_id = rl.id
          AND cl.role = 'user'
          AND jjdguard_customer_content_text(cl.content)
        ORDER BY cl.created_at ASC, cl.id ASC
        LIMIT 1
    ) title_cl ON TRUE
    WHERE rl.tenant_id = v_tenant_id AND rl.id = v_request_log_id
    -- 986：所有派生列都没变时不写（原来每插一条消息都重写一次索引行）。
    ON CONFLICT (tenant_id, request_log_id) DO UPDATE SET
        request_id = EXCLUDED.request_id,
        created_at = EXCLUDED.created_at,
        effective_agent_type = CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_agent_type
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_agent_type
            ELSE EXCLUDED.effective_agent_type
        END,
        effective_agent_runtime = EXCLUDED.effective_agent_runtime,
        effective_detection_source = CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_detection_source
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_detection_source
            ELSE EXCLUDED.effective_detection_source
        END,
        effective_detection_confidence = CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_detection_confidence
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_detection_confidence
            ELSE EXCLUDED.effective_detection_confidence
        END,
        session_id = EXCLUDED.session_id,
        evidence_run_id = EXCLUDED.evidence_run_id,
        evidence_run_source = EXCLUDED.evidence_run_source,
        conversation_id = EXCLUDED.conversation_id,
        section_id = EXCLUDED.section_id,
        chain_principal = EXCLUDED.chain_principal,
        title_hash = EXCLUDED.title_hash,
        transcript_signature = EXCLUDED.transcript_signature,
        chain_dirty = CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN evidence_run_request_index.chain_dirty
                     OR evidence_run_request_index.transcript_signature IS DISTINCT FROM EXCLUDED.transcript_signature
                     OR evidence_run_request_index.title_hash IS DISTINCT FROM EXCLUDED.title_hash
                     OR evidence_run_request_index.effective_agent_type IS DISTINCT FROM EXCLUDED.effective_agent_type
                     OR evidence_run_request_index.chain_principal IS DISTINCT FROM EXCLUDED.chain_principal
            ELSE FALSE
        END,
        derived_chain_root = CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN COALESCE(NULLIF(evidence_run_request_index.derived_chain_root, ''), EXCLUDED.request_id)
            ELSE ''
        END,
        derived_chain_size = CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN GREATEST(evidence_run_request_index.derived_chain_size, 1)
            ELSE 0
        END,
        updated_at = NOW()
    WHERE evidence_run_request_index.request_id IS DISTINCT FROM (EXCLUDED.request_id)
       OR evidence_run_request_index.created_at IS DISTINCT FROM (EXCLUDED.created_at)
       OR evidence_run_request_index.effective_agent_type IS DISTINCT FROM (CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_agent_type
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_agent_type
            ELSE EXCLUDED.effective_agent_type
        END)
       OR evidence_run_request_index.effective_agent_runtime IS DISTINCT FROM (EXCLUDED.effective_agent_runtime)
       OR evidence_run_request_index.effective_detection_source IS DISTINCT FROM (CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_detection_source
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_detection_source
            ELSE EXCLUDED.effective_detection_source
        END)
       OR evidence_run_request_index.effective_detection_confidence IS DISTINCT FROM (CASE
            WHEN EXCLUDED.effective_agent_type = 'openai-codex'
                THEN EXCLUDED.effective_detection_confidence
            WHEN LOWER(BTRIM(COALESCE(EXCLUDED.effective_agent_type, ''))) IN (
                     '', 'main', 'default', 'agent', 'assistant', 'unknown', 'electron', 'vscode'
                 )
                 AND evidence_run_request_index.effective_agent_type = 'openai-codex'
                THEN evidence_run_request_index.effective_detection_confidence
            ELSE EXCLUDED.effective_detection_confidence
        END)
       OR evidence_run_request_index.session_id IS DISTINCT FROM (EXCLUDED.session_id)
       OR evidence_run_request_index.evidence_run_id IS DISTINCT FROM (EXCLUDED.evidence_run_id)
       OR evidence_run_request_index.evidence_run_source IS DISTINCT FROM (EXCLUDED.evidence_run_source)
       OR evidence_run_request_index.conversation_id IS DISTINCT FROM (EXCLUDED.conversation_id)
       OR evidence_run_request_index.section_id IS DISTINCT FROM (EXCLUDED.section_id)
       OR evidence_run_request_index.chain_principal IS DISTINCT FROM (EXCLUDED.chain_principal)
       OR evidence_run_request_index.title_hash IS DISTINCT FROM (EXCLUDED.title_hash)
       OR evidence_run_request_index.transcript_signature IS DISTINCT FROM (EXCLUDED.transcript_signature)
       OR evidence_run_request_index.chain_dirty IS DISTINCT FROM (CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN evidence_run_request_index.chain_dirty
                     OR evidence_run_request_index.transcript_signature IS DISTINCT FROM EXCLUDED.transcript_signature
                     OR evidence_run_request_index.title_hash IS DISTINCT FROM EXCLUDED.title_hash
                     OR evidence_run_request_index.effective_agent_type IS DISTINCT FROM EXCLUDED.effective_agent_type
                     OR evidence_run_request_index.chain_principal IS DISTINCT FROM EXCLUDED.chain_principal
            ELSE FALSE
        END)
       OR evidence_run_request_index.derived_chain_root IS DISTINCT FROM (CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN COALESCE(NULLIF(evidence_run_request_index.derived_chain_root, ''), EXCLUDED.request_id)
            ELSE ''
        END)
       OR evidence_run_request_index.derived_chain_size IS DISTINCT FROM (CASE
            WHEN EXCLUDED.evidence_run_source IN ('responses_prompt_cache_key', 'responses_prompt_cache_key_candidate')
                THEN GREATEST(evidence_run_request_index.derived_chain_size, 1)
            ELSE 0
        END);

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_content_log_entries_evidence_run_request_index
    AFTER INSERT OR UPDATE OF content_sha256, role, session_id ON content_log_entries
    FOR EACH ROW EXECUTE FUNCTION sync_evidence_run_request_index();

-- 7. 正文回收：删除没有任何消息行引用的正文（按批，供保留期清理调用）。
--    p_before：只看这个时间之前首次出现的正文（过了保留期才可能失去全部引用），走 created_at 索引，
--    不必每次扫完整张正文表。分两步：先 FOR UPDATE SKIP LOCKED 锁住候选（写入方正在 FOR KEY SHARE
--    引用的会被跳过），再用新快照复核无人引用后删除。锁住之后不会再有新的引用提交，复核结果可靠，
--    不会因为并发写入触发外键错误。
CREATE INDEX idx_content_log_bodies_created ON content_log_bodies (created_at);

CREATE OR REPLACE FUNCTION prune_content_log_bodies(p_limit INTEGER DEFAULT 5000, p_before TIMESTAMPTZ DEFAULT NULL)
RETURNS INTEGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_tenants VARCHAR[];
    v_shas BYTEA[];
    v_deleted INTEGER;
BEGIN
    SELECT array_agg(c.tenant_id), array_agg(c.content_sha256)
    INTO v_tenants, v_shas
    FROM (
        SELECT b.tenant_id, b.content_sha256
        FROM content_log_bodies b
        WHERE (p_before IS NULL OR b.created_at < p_before)
          AND NOT EXISTS (
              SELECT 1 FROM content_log_entries e
              WHERE e.tenant_id = b.tenant_id AND e.content_sha256 = b.content_sha256
          )
        ORDER BY b.created_at
        LIMIT GREATEST(p_limit, 1)
        FOR UPDATE SKIP LOCKED
    ) c;
    IF v_tenants IS NULL THEN
        RETURN 0;
    END IF;
    DELETE FROM content_log_bodies b
    USING unnest(v_tenants, v_shas) AS k(tenant_id, content_sha256)
    WHERE b.tenant_id = k.tenant_id AND b.content_sha256 = k.content_sha256
      AND NOT EXISTS (
          SELECT 1 FROM content_log_entries e
          WHERE e.tenant_id = b.tenant_id AND e.content_sha256 = b.content_sha256
      );
    GET DIAGNOSTICS v_deleted = ROW_COUNT;
    RETURN v_deleted;
END;
$$;

COMMIT;
