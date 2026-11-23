-- 052_agent_stats_query_indexes.sql
-- Speed up intelligent-agent statistics by indexing the lookups used for
-- one-time backfill and by storing inferred agent type on request_logs.

CREATE INDEX IF NOT EXISTS idx_content_logs_request_created
    ON content_logs(request_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_tool_call_logs_request
    ON tool_call_logs(request_id);

CREATE INDEX IF NOT EXISTS idx_request_logs_tenant_agent_type_created
    ON request_logs(tenant_id, agent_type, created_at)
    WHERE agent_type IS NOT NULL AND agent_type != '';

WITH content_agent AS (
    SELECT cl.request_id,
           string_agg(cl.content, E'\n' ORDER BY cl.created_at DESC) AS content_text
    FROM content_logs cl
    GROUP BY cl.request_id
),
tool_agent AS (
    SELECT DISTINCT request_id
    FROM tool_call_logs
),
inferred AS (
    SELECT rl.id,
           CASE
               WHEN content_text ILIKE '%opencode%' OR content_text ILIKE '%open code%' THEN 'opencode'
               WHEN content_text ILIKE '%Claude Code%' OR content_text ILIKE '%cc_version=%' THEN 'claude-code'
               WHEN content_text ILIKE '%openai codex%' OR content_text ILIKE '%codex cli%' OR content_text ILIKE '%@openai/codex%' THEN 'openai-codex'
               WHEN content_text ILIKE '%cursor%' OR content_text ILIKE '%.cursorrules%' THEN 'cursor'
               WHEN content_text ILIKE '%windsurf%' OR content_text ILIKE '%cascade%' OR content_text ILIKE '%codeium%' THEN 'windsurf'
               WHEN content_text ILIKE '%github copilot%' OR content_text ILIKE '%copilot coding agent%' THEN 'github-copilot'
               WHEN content_text ILIKE '%cline%' THEN 'cline'
               WHEN content_text ILIKE '%roo code%' OR content_text ILIKE '%roo-code%' OR content_text ILIKE '%roocode%' THEN 'roo-code'
               WHEN content_text ILIKE '%kilo code%' OR content_text ILIKE '%kilo-code%' OR content_text ILIKE '%kilocode%' THEN 'kilo-code'
               WHEN content_text ILIKE '%continue.dev%' OR content_text ILIKE '%continue-vscode%' OR content_text ILIKE '%continuedev%' THEN 'continue'
               WHEN content_text ILIKE '%aider%' THEN 'aider'
               WHEN content_text ILIKE '%devin%' OR content_text ILIKE '%cognition devin%' THEN 'devin'
               WHEN content_text ILIKE '%sourcegraph amp%' OR content_text ILIKE '%amp-code%' OR content_text ILIKE '%ampcode%' THEN 'amp'
               WHEN content_text ILIKE '%block goose%' OR content_text ILIKE '%goose-cli%' THEN 'goose'
               WHEN content_text ILIKE '%gemini cli%' OR content_text ILIKE '%gemini-cli%' THEN 'gemini-cli'
               WHEN content_text ILIKE '%qwen code%' OR content_text ILIKE '%qwen-code%' OR content_text ILIKE '%qwen coder%' OR content_text ILIKE '%qwen3-coder%' THEN 'qwen-code'
               WHEN content_text ILIKE '%jetbrains junie%' OR content_text ILIKE '%junie%' THEN 'jetbrains-junie'
               WHEN content_text ILIKE '%tabnine%' THEN 'tabnine'
               WHEN content_text ILIKE '%qodo%' THEN 'qodo'
               WHEN content_text ILIKE '%sourcegraph cody%' OR content_text ILIKE '%sourcegraph-cody%' OR content_text ILIKE '%cody ai%' THEN 'sourcegraph-cody'
               WHEN content_text ILIKE '%amazon kiro%' OR content_text ILIKE '%kiro ide%' THEN 'amazon-kiro'
               WHEN content_text ILIKE '%google antigravity%' OR content_text ILIKE '%antigravity%' THEN 'google-antigravity'
               WHEN content_text ILIKE '%replit agent%' THEN 'replit-agent'
               WHEN content_text ILIKE '%bolt.new%' OR content_text ILIKE '%stackblitz bolt%' THEN 'bolt'
               WHEN content_text ILIKE '%lovable%' THEN 'lovable'
               WHEN content_text ILIKE '%v0.dev%' OR content_text ILIKE '%vercel v0%' THEN 'v0'
               WHEN content_text ILIKE '%codebuddy%' OR content_text ILIKE '%腾讯云代码助手%' THEN 'codebuddy'
               WHEN content_text ILIKE '%通义灵码%' OR content_text ILIKE '%tongyi lingma%' OR content_text ILIKE '%aliyun lingma%' OR content_text ILIKE '%lingma%' THEN 'tongyi-lingma'
               WHEN content_text ILIKE '%qoder%' THEN 'qoder'
               WHEN content_text ILIKE '%codearts snap%' OR content_text ILIKE '%codearts-snap%' OR content_text ILIKE '%华为云 codearts snap%' THEN 'codearts-snap'
               WHEN content_text ILIKE '%deveco codegenie%' OR content_text ILIKE '%codegenie%' THEN 'deveco-codegenie'
               WHEN content_text ILIKE '%trae%' OR content_text ILIKE '%the real ai engineer%' THEN 'trae'
               WHEN content_text ILIKE '%marscode%' OR content_text ILIKE '%豆包 marscode%' OR content_text ILIKE '%豆包marscode%' THEN 'marscode'
               WHEN content_text ILIKE '%baidu comate%' OR content_text ILIKE '%百度comate%' OR content_text ILIKE '%百度 comate%' THEN 'baidu-comate'
               WHEN content_text ILIKE '%iflycode%' OR content_text ILIKE '%星火飞码%' THEN 'iflycode'
               WHEN content_text ILIKE '%codegeex%' OR content_text ILIKE '%智谱 codegeex%' THEN 'codegeex'
               WHEN content_text ILIKE '%codefuse%' OR content_text ILIKE '%蚂蚁 codefuse%' THEN 'codefuse'
               WHEN ta.request_id IS NOT NULL THEN 'agent-tool-call'
               ELSE ''
           END AS agent_type
    FROM request_logs rl
    LEFT JOIN content_agent ca ON ca.request_id = rl.id
    LEFT JOIN tool_agent ta ON ta.request_id = rl.request_id
    WHERE COALESCE(rl.agent_type, '') = ''
)
UPDATE request_logs rl
SET agent_type = inferred.agent_type
FROM inferred
WHERE rl.id = inferred.id
  AND inferred.agent_type != '';
