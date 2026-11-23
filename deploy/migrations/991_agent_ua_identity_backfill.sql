BEGIN;

-- 新增 deepseek-harness 后，已登记客户端名单要同步包含它，否则身份确认页会把它当成"待识别"。
CREATE OR REPLACE FUNCTION agent_identity_known(t text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT COALESCE(t,'') = ANY(ARRAY['claude-code','openai-codex','cursor','windsurf','github-copilot','cline','roo-code','kilo-code','continue','aider','amazon-q-developer','gemini-code-assist','coderabbit','autogpt-babyagi','langchain-llamaindex','crewai-autogen','dify-coze','opencode','devin','amp','goose','gemini-cli','qwen-code','jetbrains-junie','tabnine','qodo','sourcegraph-cody','amazon-kiro','google-antigravity','replit-agent','bolt','lovable','v0','codebuddy','tongyi-lingma','qoder','codearts-snap','deveco-codegenie','trae','marscode','baidu-comate','iflycode','codegeex','codefuse','workbuddy','deepseek-harness']::text[])
$$;

-- 历史行按存储的 User-Agent 受控回填：只改有 UA 证据能认出产品的行，改前前值写入
-- agent_protocol_repairs(migration='991')，分批、可断点续跑，由 worker 执行。
INSERT INTO migration_backfill_tasks (
    task_name, task_version, state, checkpoint, scan_upper_bound,
    batch_size, rate_limit_rows_per_second, lock_timeout_ms,
    statement_timeout_ms, max_retries, priority
)
VALUES (
    'agent_ua_identity_v1', 1, 'pending', '{}'::jsonb, '{}'::jsonb,
    250, 1000, 1000, 30000, 20, 26
)
ON CONFLICT (task_name, task_version) DO NOTHING;

INSERT INTO migration_backfill_events(task_name, task_version, event_type, state, summary)
SELECT 'agent_ua_identity_v1', 1, 'registered', 'pending',
       'Historical agent identity corrected from stored User-Agent evidence'
WHERE NOT EXISTS (
    SELECT 1 FROM migration_backfill_events
    WHERE task_name='agent_ua_identity_v1'
      AND task_version=1 AND event_type='registered'
);

COMMIT;
