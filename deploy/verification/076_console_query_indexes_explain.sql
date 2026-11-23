-- 076_console_query_indexes_explain.sql
-- Run this file before and after deploy/migrations/076_console_query_indexes.sql.
--
-- Example:
--   psql "$DATABASE_URL" \
--     -v tenant_id=tenant_default \
--     -v keyword=secret \
--     -v request_pk=reqlog_123 \
--     -v request_id=req_123 \
--     -f deploy/verification/076_console_query_indexes_explain.sql \
--     > /tmp/076-console-query-indexes-before.txt
--
-- Use real high-cardinality tenant/request/session values from the target DB.

\set ON_ERROR_STOP on

\if :{?tenant_id}
\else
  \set tenant_id tenant_default
\endif

\if :{?keyword}
\else
  \set keyword secret
\endif

\if :{?request_pk}
\else
  \set request_pk reqlog_123
\endif

\if :{?request_id}
\else
  \set request_id req_123
\endif

\echo === 076 index presence ===
SELECT indexname, indexdef
FROM pg_indexes
WHERE schemaname = 'public'
  AND indexname IN (
    'idx_content_logs_tenant_role_request',
    'idx_content_logs_tenant_created',
    'idx_content_logs_content_trgm',
    'idx_security_events_tenant_request',
    'idx_agent_sessions_tenant_last_request'
  )
ORDER BY indexname;

\echo === content_logs first user content by request ===
EXPLAIN (ANALYZE, BUFFERS)
SELECT cl.content
FROM content_logs cl
WHERE cl.tenant_id = :'tenant_id'
  AND cl.role = 'user'
  AND cl.request_id = :'request_pk'
  AND cl.content !~* '^The user stepped away and is coming back'
  AND cl.content !~* '^Recap in under [0-9]+ words'
  AND cl.content !~* '^<system-reminder>'
ORDER BY cl.created_at ASC
LIMIT 1;

\echo === content_logs tenant pagination ===
EXPLAIN (ANALYZE, BUFFERS)
SELECT cl.id, cl.request_id, cl.tenant_id, cl.user_id, cl.session_id,
       cl.role, cl.content, cl.tokens, cl.created_at
FROM content_logs cl
WHERE cl.tenant_id = :'tenant_id'
ORDER BY cl.created_at DESC
LIMIT 50 OFFSET 0;

\echo === content_logs keyword search ===
EXPLAIN (ANALYZE, BUFFERS)
SELECT cl.id, cl.request_id, cl.tenant_id, cl.user_id, cl.session_id,
       cl.role, cl.content, cl.tokens, cl.created_at
FROM content_logs cl
WHERE cl.tenant_id = :'tenant_id'
  AND cl.content ILIKE '%' || :'keyword' || '%'
ORDER BY cl.created_at DESC
LIMIT 50 OFFSET 0;

\echo === security_events tenant/request association ===
EXPLAIN (ANALYZE, BUFFERS)
SELECT COUNT(*)
FROM security_events se
WHERE se.tenant_id = :'tenant_id'
  AND se.request_id = :'request_id';

\echo === agent_sessions tenant pagination ===
EXPLAIN (ANALYZE, BUFFERS)
SELECT id, tenant_id, project_id, user_id, session_id, agent_type, workspace_id,
       client_name, client_version, first_request_at, last_request_at,
       request_count, risk_score, status, created_at, updated_at
FROM agent_sessions
WHERE tenant_id = :'tenant_id'
ORDER BY last_request_at DESC
LIMIT 50 OFFSET 0;
