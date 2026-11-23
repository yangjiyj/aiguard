\set ON_ERROR_STOP on

DO $guard$
BEGIN
  IF current_database() !~ '^jjdguard_query_bench_' THEN
    RAISE EXCEPTION 'refusing to seed non-benchmark database %', current_database();
  END IF;
END
$guard$;

BEGIN;
SET LOCAL session_replication_role = replica;

TRUNCATE TABLE
  evidence_run_request_index,
  security_event_occurrences,
  audit_dispositions,
  tool_call_logs,
  security_events,
  alert_groups,
  access_content_logs,
  content_logs,
  request_logs
RESTART IDENTITY CASCADE;

DELETE FROM users WHERE id LIKE 'bench-user-%';
INSERT INTO teams (id, tenant_id, name, path)
VALUES ('bench-department', 'tenant_default', '基准部门', '/bench-department')
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (
  id, tenant_id, username, role, status, department_id,
  department_assignment_mode, department_assignment_source
)
SELECT
  'bench-user-' || i,
  'tenant_default',
  '测试用户' || lpad(i::text, 4, '0'),
  'developer',
  'active',
  'bench-department',
  'manual',
  'admin'
FROM generate_series(0, 999) AS i;

INSERT INTO tenants (id, name, edition, status)
VALUES ('tenant_benchmark_noise', '基准隔离噪声租户', 'enterprise', 'active')
ON CONFLICT (id) DO NOTHING;

INSERT INTO request_logs (
  id, request_id, tenant_id, project_id, user_id, client_id, session_id,
  agent_type, agent_runtime, agent_detection_source, agent_detection_confidence,
  evidence_run_id, evidence_run_source, endpoint_type, request_status,
  upstream_status_code, latency_ms, input_tokens, output_tokens, created_at,
  input_audit_result, output_audit_result, proxy_mode, proxy_target_host,
  proxy_target_path, proxy_method, proxy_source_ip, proxy_response_bytes,
  proxy_tls_inspected, proxy_provider, proxy_endpoint_kind, proxy_product,
  proxy_access_type, proxy_access_type_resolved, proxy_path_template,
  proxy_retention_level, proxy_content_retained, risk_state, has_retained_content,
  environment_scope, has_customer_content, customer_content_rule_version,
  has_customer_request_body, has_customer_response_body
)
SELECT
  'bench-log-' || lpad(i::text, 9, '0'),
  'bench-req-' || lpad(i::text, 9, '0'),
  'tenant_default',
  'project_default',
  'bench-user-' || (i % 1000),
  'bench-client-' || (i % 50),
  'bench-session-' || ((i - 1) / 5),
  CASE WHEN i % 5 = 0 THEN 'openai-codex' ELSE 'workbuddy' END,
  CASE WHEN i % 5 = 0 THEN 'vscode' ELSE 'electron' END,
  'explicit_header',
  0.99,
  'bench-run-' || ((i - 1) / 5),
  'session_id',
  'chat',
  CASE WHEN i % 50 = 0 THEN 'blocked' ELSE 'success' END,
  CASE WHEN i % 50 = 0 THEN 403 ELSE 200 END,
  20 + (i % 800),
  100 + (i % 900),
  200 + (i % 1800),
  TIMESTAMPTZ '2026-09-08 00:00:00+00' - ((:rows - i) % 43200) * INTERVAL '1 second',
  CASE WHEN i % 10 = 0 THEN jsonb_build_object(
    'action_taken', 'audit',
    'findings', jsonb_build_array(jsonb_build_object(
      'category', 'secret',
      'rule_id', 'bench_secret',
      'counts_as_security_finding', true
    ))
  ) ELSE '{}'::jsonb END,
  '{}'::jsonb,
  CASE WHEN i % 4 = 0 THEN 'forward' ELSE 'reverse' END,
  CASE WHEN i % 3 = 0 THEN 'api.deepseek.com' ELSE 'api.openai.com' END,
  '/v1/chat/completions',
  'POST',
  '10.10.' || (i % 32) || '.' || (i % 250 + 1),
  1024 + (i % 16384),
  true,
  CASE WHEN i % 3 = 0 THEN 'deepseek' ELSE 'openai' END,
  'chat',
  CASE WHEN i % 5 = 0 THEN 'cursor_agent' ELSE 'workbuddy' END,
  CASE WHEN i % 10 < 7 THEN 'llm' WHEN i % 10 < 9 THEN 'ai_ide' ELSE 'normal_public' END,
  CASE WHEN i % 10 < 7 THEN 'llm' WHEN i % 10 < 9 THEN 'ai_ide' ELSE 'normal_public' END,
  '/v1/chat/completions',
  'content',
  i % 10 <> 9,
  CASE WHEN i % 50 = 0 THEN 'blocked' WHEN i % 10 = 0 THEN 'risk' ELSE 'normal' END,
  i % 10 <> 9,
  'customer',
  i % 10 <> 9,
  1,
  i % 10 <> 9,
  i % 10 <> 9
FROM generate_series(1, :rows) AS i;

INSERT INTO request_logs (
  id, request_id, tenant_id, project_id, user_id, session_id, endpoint_type,
  request_status, created_at, proxy_mode, proxy_target_host, proxy_target_path,
  proxy_method, proxy_access_type_resolved, risk_state, has_retained_content,
  environment_scope, has_customer_content
)
SELECT
  'noise-req-' || lpad(i::text, 9, '0'),
  'noise-req-' || lpad(i::text, 9, '0'),
  'tenant_benchmark_noise',
  NULL,
  NULL,
  'noise-session-' || ((i - 1) / 5),
  'chat',
  'success',
  TIMESTAMPTZ '2026-09-08 00:00:00+00' - (i % 43200) * INTERVAL '1 second',
  'reverse',
  'noise.example',
  '/v1/chat/completions',
  'POST',
  'llm',
  'normal',
  false,
  'customer',
  false
FROM generate_series(1, GREATEST(1, :rows / 10)) AS i;

INSERT INTO content_logs (
  id, request_id, tenant_id, user_id, session_id, role, content, tokens,
  created_at, environment_scope, message_index
)
SELECT
  'bench-cl-' || lpad(i::text, 9, '0') || '-' || role_index,
  'bench-log-' || lpad(i::text, 9, '0'),
  'tenant_default',
  'bench-user-' || (i % 1000),
  'bench-session-' || ((i - 1) / 5),
  CASE role_index WHEN 0 THEN 'user' ELSE 'assistant' END,
  CASE
    WHEN (i - 1) % 300 = 0 AND role_index = 0 THEN '异常 旧会话尾部命中 ' || i
    WHEN i % 500 = 8 AND role_index = 0 THEN '异常 仅 content_logs 命中 ' || i
    WHEN i % 100 = 0 AND role_index = 0 THEN '异常 登录失败 基准命中 ' || i
    WHEN role_index = 0 THEN '普通用户问题 ' || i
    ELSE '普通模型回答 ' || i
  END,
  100 + (i % 500),
  TIMESTAMP '2026-09-08 00:00:00' - ((:rows - i) % 43200) * INTERVAL '1 second' + role_index * INTERVAL '100 milliseconds',
  'customer',
  role_index
FROM generate_series(1, :rows) AS i
CROSS JOIN generate_series(0, 1) AS role_index
WHERE i % 10 <= 5 OR i % 10 = 8;

INSERT INTO access_content_logs (
  id, request_id, tenant_id, provider, product, model, conversation_id,
  request_content_redacted, response_content_redacted, file_metadata_json,
  retention_until, created_at, section_id, environment_scope
)
SELECT
  'bench-acl-' || lpad(i::text, 9, '0'),
  'bench-req-' || lpad(i::text, 9, '0'),
  'tenant_default',
  CASE WHEN i % 3 = 0 THEN 'deepseek' ELSE 'openai' END,
  CASE WHEN i % 5 = 0 THEN 'cursor_agent' ELSE 'workbuddy' END,
  'bench-model',
  'bench-conversation-' || ((i - 1) / 3),
  CASE
    WHEN (i - 1) % 300 = 0 THEN '异常 旧会话尾部命中 ' || i
    WHEN i % 500 = 6 THEN '异常 仅 access_content_logs 命中 ' || i
    WHEN i % 100 = 0 THEN '异常 登录失败 留存请求 ' || i
    ELSE '普通留存请求 ' || i
  END,
  '普通留存响应 ' || i,
  '[]'::jsonb,
  TIMESTAMPTZ '2026-12-31 00:00:00+00',
  TIMESTAMPTZ '2026-09-08 00:00:00+00' - ((:rows - i) % 43200) * INTERVAL '1 second',
  'turn-' || (i % 3),
  'customer'
FROM generate_series(1, :rows) AS i
WHERE i % 10 <= 7;

INSERT INTO alert_groups (
  id, tenant_id, project_id, group_key, status, severity, alert_type, title,
  representative_event_id, request_id, occurrence_count, body_json,
  first_seen_at, last_seen_at, created_at, updated_at, effective_severity,
  disposition_class, class_key, principal_key, is_canary, stage,
  distinct_occurrences, affected_users, last_calc_at
)
SELECT
  'ag-bench-' || i,
  'tenant_default',
  'project_default',
  'bench-group-' || i,
  CASE WHEN i % 10 = 0 THEN 'resolved' ELSE 'open' END,
  CASE WHEN i % 20 = 0 THEN 'critical' ELSE 'high' END,
  'content_risk',
  '基准告警组 ' || i,
  'bench-se-' || (i + 1),
  'bench-req-' || lpad((i + 1)::text, 9, '0'),
  CASE WHEN i = 0 THEN 2000 ELSE 8 END,
  jsonb_build_object('summary', 'bounded'),
  TIMESTAMPTZ '2026-09-07 00:00:00+00',
  TIMESTAMPTZ '2026-09-08 00:00:00+00' - i * INTERVAL '1 second',
  TIMESTAMPTZ '2026-09-07 00:00:00+00',
  TIMESTAMPTZ '2026-09-08 00:00:00+00' - i * INTERVAL '1 second',
  CASE WHEN i % 20 = 0 THEN 'critical' ELSE 'high' END,
  'action_required',
  'bench-class',
  'bench-user-' || (i % 1000),
  false,
  'input',
  CASE WHEN i = 0 THEN 2000 ELSE 8 END,
  CASE WHEN i = 0 THEN 1000 ELSE 8 END,
  TIMESTAMPTZ '2026-09-08 00:00:00+00'
FROM generate_series(0, 999) AS i;

INSERT INTO security_events (
  id, request_id, tenant_id, project_id, user_id, event_type, severity,
  rule_id, action_taken, matched_summary, created_at, principal_key,
  effective_severity, class_key, alert_group_id, conversation_key
)
SELECT
  'bench-se-' || i,
  'bench-req-' || lpad((((i - 1) % :rows) + 1)::text, 9, '0'),
  'tenant_default',
  'project_default',
  'bench-user-' || (i % 1000),
  'content_risk',
  CASE WHEN i % 20 = 0 THEN 'critical' ELSE 'high' END,
  'bench_secret',
  CASE WHEN i % 5 = 0 THEN 'block' ELSE 'audit' END,
  jsonb_build_object(
    'category', 'secret',
    'findings', jsonb_build_array(jsonb_build_object(
      'category', 'secret',
      'rule_id', 'bench_secret',
      'counts_as_security_finding', true
    ))
  ),
  TIMESTAMPTZ '2026-09-08 00:00:00+00' - i * INTERVAL '100 milliseconds',
  'bench-user-' || (i % 1000),
  CASE WHEN i % 20 = 0 THEN 'critical' ELSE 'high' END,
  'bench-class',
  CASE WHEN i <= 2000 THEN 'ag-bench-0' ELSE 'ag-bench-' || (i % 1000) END,
  'bench-conversation-' || (i % 2500)
FROM generate_series(1, GREATEST(10000, :rows / 10)) AS i;

INSERT INTO tool_call_logs (
  id, request_id, session_id, tenant_id, user_id, tool_name, tool_type,
  risk_level, parameters, result, status, matched_policy_id,
  matched_policy_name, matched_action, match_reason, raw_decision,
  effective_decision, mode, effective_reason, event_kind,
  execution_observed, result_observed, application_id, agent_type,
  model, protocol, created_at
)
SELECT
  'bench-tc-' || lpad(i::text, 9, '0'),
  'bench-req-' || lpad(i::text, 9, '0'),
  'bench-session-' || ((i - 1) / 5),
  'tenant_default',
  'bench-user-' || (i % 1000),
  CASE WHEN i % 3 = 0 THEN 'filesystem__read' ELSE 'shell__exec' END,
  CASE WHEN i % 3 = 0 THEN 'mcp' ELSE 'system' END,
  CASE WHEN i % 20 = 0 THEN 'critical' WHEN i % 5 = 0 THEN 'high' ELSE 'medium' END,
  jsonb_build_object('sensitive', 'not for list', 'i', i),
  'sensitive result not for list ' || i,
  CASE WHEN i % 20 = 0 THEN 'blocked' ELSE 'audited' END,
  'bench-policy-' || (i % 10),
  '基准工具策略',
  CASE WHEN i % 20 = 0 THEN 'block' ELSE 'audit' END,
  '基准工具判定摘要',
  CASE WHEN i % 20 = 0 THEN 'confirm' ELSE 'audit' END,
  CASE WHEN i % 20 = 0 THEN 'block' ELSE 'audit' END,
  'audit',
  '基准生效原因',
  'invocation_proposed',
  false,
  false,
  'project_default',
  CASE WHEN i % 5 = 0 THEN 'openai-codex' ELSE 'workbuddy' END,
  'bench-model',
  'responses',
  TIMESTAMP '2026-09-08 00:00:00' - ((:rows - i) % 43200) * INTERVAL '1 second'
FROM generate_series(1, :rows) AS i;

INSERT INTO tool_call_logs (
  id, request_id, session_id, tenant_id, tool_name, tool_type, risk_level,
  parameters, result, status, event_kind, execution_observed, result_observed,
  created_at
)
SELECT
  'noise-tc-' || lpad(i::text, 9, '0'),
  'noise-req-' || lpad(i::text, 9, '0'),
  'noise-session-' || ((i - 1) / 5),
  'tenant_benchmark_noise',
  'noise__read',
  'mcp',
  'high',
  '{}'::jsonb,
  '',
  'audited',
  'invocation_proposed',
  false,
  false,
  TIMESTAMP '2026-09-08 00:00:00' - (i % 43200) * INTERVAL '1 second'
FROM generate_series(1, GREATEST(1, :rows / 10)) AS i;

INSERT INTO audit_dispositions (
  tenant_id, subject_type, subject_id, status, note, operator_id, operator_name
)
SELECT
  'tenant_default',
  'tool_call',
  'bench-tc-' || lpad(i::text, 9, '0'),
  CASE WHEN i % 40 = 0 THEN 'accepted' ELSE 'resolved' END,
  '基准处置摘要',
  'user_admin',
  'admin'
FROM generate_series(20, :rows, 20) AS i;

INSERT INTO evidence_run_request_index (
  tenant_id, request_log_id, request_id, created_at, effective_agent_type,
  effective_agent_runtime, effective_detection_source,
  effective_detection_confidence, session_id, evidence_run_id,
  evidence_run_source, conversation_id, section_id, chain_principal,
  title_hash, transcript_signature, derived_chain_root, derived_chain_size,
  chain_dirty
)
SELECT
  tenant_id,
  id,
  request_id,
  created_at,
  COALESCE(agent_type, ''),
  COALESCE(agent_runtime, ''),
  COALESCE(agent_detection_source, ''),
  COALESCE(agent_detection_confidence, 0),
  COALESCE(session_id, ''),
  COALESCE(evidence_run_id, ''),
  COALESCE(evidence_run_source, ''),
  'bench-conversation-' || ((substring(request_id from '[0-9]+$'))::bigint / 3),
  'turn-' || ((substring(request_id from '[0-9]+$'))::bigint % 3),
  COALESCE(user_id, ''),
  repeat('0', 32),
  '',
  '',
  0,
  false
FROM request_logs
WHERE tenant_id = 'tenant_default';

INSERT INTO system_settings (key, value)
VALUES ('content_audit_enabled', 'true')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

COMMIT;

VACUUM (ANALYZE) request_logs;
VACUUM (ANALYZE) content_logs;
VACUUM (ANALYZE) access_content_logs;
VACUUM (ANALYZE) security_events;
VACUUM (ANALYZE) alert_groups;
VACUUM (ANALYZE) tool_call_logs;
VACUUM (ANALYZE) audit_dispositions;
VACUUM (ANALYZE) evidence_run_request_index;
