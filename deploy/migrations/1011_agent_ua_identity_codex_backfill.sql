BEGIN;

-- 网关补齐 Codex 官方客户端识别（codex-tui、codex_vscode、codex_cli_rs、codex_sdk_ts、originator 头…，
-- 特征以 agent-registry.json 为唯一来源）后，把此前被内容兜底错判的历史请求改回 openai-codex。
-- 客户现场 14 天约 2511 条 codex-tui / codex_vscode 请求被判成 dify-coze。
--
-- 由 worker 的 agent_ua_identity_v2 分批执行（与 991 同一套候选/修正 SQL）：
--   * 只看任务开始前 90 天内、存有 User-Agent 或 Originator 的 request_logs 行；
--   * 只改识别来源为 content / message_protocol / user_agent_runtime / 空 的行，客户端声明头、
--     登记规则、产品身份等来源一律不碰；
--   * 请求头重新识别为 openai-codex 时改成 openai-codex、来源 user_agent、置信度 0.85；
--   * 改前前值写入 agent_protocol_repairs(migration='1011')，同一行只修一次（幂等），可断点续跑；
--   * 同事务纠正 agent_sessions（会话存值为空/通用值/运行时值，或就是被修行带进去的错值时才改）；
--     evidence_run_request_index 由 request_logs 的触发器随之刷新；安全事件、告警明细按请求关联读取，
--     无需另改。
-- governance-test: apps/worker/internal/backfill/agent_ua_identity_codex_integration_1121_test.go::TestAgentUAIdentityCodexBackfillOnMigratedSchema
-- 每批 250 行、行锁 SKIP LOCKED、lock_timeout 1 秒、statement_timeout 30 秒，限速每秒 1000 行。
INSERT INTO migration_backfill_tasks (
    task_name, task_version, state, checkpoint, scan_upper_bound,
    batch_size, rate_limit_rows_per_second, lock_timeout_ms,
    statement_timeout_ms, max_retries, priority
)
VALUES (
    'agent_ua_identity_v2', 1, 'pending', '{}'::jsonb, '{}'::jsonb,
    250, 1000, 1000, 30000, 20, 27
)
ON CONFLICT (task_name, task_version) DO NOTHING;

INSERT INTO migration_backfill_events(task_name, task_version, event_type, state, summary)
SELECT 'agent_ua_identity_v2', 1, 'registered', 'pending',
       'Historical Codex identity corrected from stored User-Agent / Originator evidence'
WHERE NOT EXISTS (
    SELECT 1 FROM migration_backfill_events
    WHERE task_name='agent_ua_identity_v2'
      AND task_version=1 AND event_type='registered'
);

COMMIT;
