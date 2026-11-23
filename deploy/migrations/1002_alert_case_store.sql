BEGIN;

-- 1002_alert_case_store: 告警排查问题（案件）写入时物化（2.9.22 批次 7）。
--
-- 告警列表、汇总、命中明细、处置授权过去每次都把租户全部历史告警（客户现场 3.97 万事件、9.98 万命中、
-- 2025 个问题）重新展开、归并成案件，每次 5～6.4 秒。这里把归并结果存下来：
--   * alert_case_members：每条命中一行，存控制面告警查询逐条算出的归并字段（案件编号、车道、严重级别、
--     发生时间、证据标识、去重键等）。由控制面用同一段 SQL 计算，口径与实时查询逐条一致。
--   * alert_cases：每个案件按两种范围各一行（all = 含开发作用域折叠的命中；customer = 不含），
--     存首末时间、命中数、请求数、代表命中、处置状态等聚合结果。
--   * alert_case_groups：告警组的开发作用域折叠标记（“已折叠 N 个开发作用域组”计数用）。
--   * alert_case_dirty：待重算队列。1003 的触发器在告警事件、请求记录、留存会话、处置、告警组、凭据
--     发生相关变化时写入；控制面读之前先把本租户的队列消化掉，后台任务也定期消化。
--   * alert_case_backfill：历史回填进度。控制面后台按事件编号分批回填，可中断、可重入；某租户回填完成前，
--     读接口照旧走实时查询，结果不受影响。
--
-- 只建新表，不改现有表。回滚：deploy/migrations/rollback/1002_alert_case_store.sql。

CREATE TABLE IF NOT EXISTS alert_case_members (
    tenant_id           VARCHAR(64) NOT NULL,
    event_id            VARCHAR(64) NOT NULL,
    finding_slot        INTEGER     NOT NULL,
    finding_index       INTEGER,
    id                  TEXT        NOT NULL,
    request_id          TEXT        NOT NULL DEFAULT '',
    project_id          TEXT        NOT NULL DEFAULT '',
    created_at          TIMESTAMPTZ,
    occurred_at         TIMESTAMPTZ,
    time_known          BOOLEAN     NOT NULL DEFAULT FALSE,
    event_action_taken  TEXT        NOT NULL DEFAULT '',
    case_id             TEXT        NOT NULL,
    case_category       TEXT        NOT NULL DEFAULT '',
    case_conversation   TEXT        NOT NULL DEFAULT '',
    evidence_identity   TEXT        NOT NULL DEFAULT '',
    alert_group_id      TEXT        NOT NULL DEFAULT '',
    conversation_key    TEXT        NOT NULL DEFAULT '',
    disposition_status  TEXT        NOT NULL DEFAULT 'open',
    member_lane         TEXT        NOT NULL DEFAULT 'action',
    type                TEXT        NOT NULL DEFAULT '',
    category            TEXT        NOT NULL DEFAULT '',
    severity            TEXT        NOT NULL DEFAULT '',
    rule_id             TEXT        NOT NULL DEFAULT '',
    finding_rule_name   TEXT        NOT NULL DEFAULT '',
    action_taken        TEXT        NOT NULL DEFAULT '',
    has_output_anchor   BOOLEAN     NOT NULL DEFAULT FALSE,
    message_index       INTEGER,
    attachment_index    INTEGER,
    message_role        TEXT        NOT NULL DEFAULT '',
    content_source      TEXT        NOT NULL DEFAULT '',
    stage               TEXT        NOT NULL DEFAULT '',
    matched_location    TEXT        NOT NULL DEFAULT '',
    review_state        TEXT        NOT NULL DEFAULT '',
    suppression_reason  TEXT        NOT NULL DEFAULT '',
    suppressed          BOOLEAN     NOT NULL DEFAULT FALSE,
    occurrence_key      JSONB       NOT NULL,
    dev_folded          BOOLEAN     NOT NULL DEFAULT FALSE,
    lane_key_id         TEXT        NOT NULL DEFAULT '',
    refreshed_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, event_id, finding_slot)
);
CREATE INDEX IF NOT EXISTS idx_alert_case_members_case
    ON alert_case_members (tenant_id, case_id);
CREATE INDEX IF NOT EXISTS idx_alert_case_members_occurrence
    ON alert_case_members (tenant_id, occurrence_key);
CREATE INDEX IF NOT EXISTS idx_alert_case_members_created
    ON alert_case_members (tenant_id, created_at);
CREATE INDEX IF NOT EXISTS idx_alert_case_members_group
    ON alert_case_members (tenant_id, alert_group_id) WHERE alert_group_id <> '';
CREATE INDEX IF NOT EXISTS idx_alert_case_members_request
    ON alert_case_members (tenant_id, request_id) WHERE request_id <> '';
CREATE INDEX IF NOT EXISTS idx_alert_case_members_lane_key
    ON alert_case_members (tenant_id, lane_key_id) WHERE lane_key_id <> '';

CREATE TABLE IF NOT EXISTS alert_cases (
    tenant_id               VARCHAR(64) NOT NULL,
    scope                   VARCHAR(16) NOT NULL,
    case_id                 TEXT        NOT NULL,
    project_id              TEXT        NOT NULL DEFAULT '',
    case_category           TEXT        NOT NULL DEFAULT '',
    case_lane               TEXT        NOT NULL DEFAULT 'action',
    severity                TEXT        NOT NULL DEFAULT '',
    first_seen              TIMESTAMPTZ,
    last_seen               TIMESTAMPTZ,
    last_detected_at        TIMESTAMPTZ,
    new_evidence_at         TIMESTAMPTZ,
    hit_count               INTEGER     NOT NULL DEFAULT 0,
    request_count           INTEGER     NOT NULL DEFAULT 0,
    rule_name_count         INTEGER     NOT NULL DEFAULT 0,
    blocked_count           INTEGER     NOT NULL DEFAULT 0,
    all_times_known         BOOLEAN,
    all_suppressed          BOOLEAN,
    all_handled             BOOLEAN,
    all_false_positive      BOOLEAN,
    has_unknown_occurred    BOOLEAN     NOT NULL DEFAULT FALSE,
    grouping_basis          TEXT        NOT NULL DEFAULT '',
    disposition_status      TEXT        NOT NULL DEFAULT 'open',
    rep_event_id            VARCHAR(64) NOT NULL,
    rep_finding_slot        INTEGER     NOT NULL,
    refreshed_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, scope, case_id),
    CONSTRAINT alert_cases_scope_check CHECK (scope IN ('all', 'customer'))
);
CREATE INDEX IF NOT EXISTS idx_alert_cases_lane_status_last_seen
    ON alert_cases (tenant_id, scope, case_lane, disposition_status, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_alert_cases_last_seen
    ON alert_cases (tenant_id, scope, last_seen DESC);

-- 告警组的开发作用域折叠标记（与实时查询逐事件判断的同一条件），供“已折叠 N 个开发作用域组”计数。
CREATE TABLE IF NOT EXISTS alert_case_groups (
    tenant_id     VARCHAR(64) NOT NULL,
    group_id      TEXT        NOT NULL,
    folded        BOOLEAN     NOT NULL DEFAULT FALSE,
    refreshed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, group_id)
);
CREATE INDEX IF NOT EXISTS idx_alert_case_groups_folded
    ON alert_case_groups (tenant_id) WHERE folded;

CREATE TABLE IF NOT EXISTS alert_case_dirty (
    id          BIGSERIAL   PRIMARY KEY,
    tenant_id   VARCHAR(64) NOT NULL,
    kind        VARCHAR(16) NOT NULL,
    ref         TEXT        NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT alert_case_dirty_kind_check CHECK (kind IN ('event', 'request', 'group', 'key', 'case'))
);
CREATE INDEX IF NOT EXISTS idx_alert_case_dirty_tenant
    ON alert_case_dirty (tenant_id, id);

CREATE TABLE IF NOT EXISTS alert_case_backfill (
    tenant_id        VARCHAR(64) PRIMARY KEY,
    cursor_event_id  TEXT        NOT NULL DEFAULT '',
    done             BOOLEAN     NOT NULL DEFAULT FALSE,
    started_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 已有租户都要回填一次；之后新建的租户没有历史，由触发器全程覆盖，不需要回填行。
INSERT INTO alert_case_backfill (tenant_id)
SELECT id FROM tenants
ON CONFLICT (tenant_id) DO NOTHING;

COMMIT;
