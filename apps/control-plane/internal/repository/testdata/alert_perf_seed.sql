-- 告警与留存性能回归数据（与客户现场 2.9.21 同量级）。
-- 租户 perf_t：4 万请求（一半正向代理、一半网关直连）、5.2 万安全事件、约 10 万命中、
-- 400 个会话 × 5 类风险 ≈ 2000 个排查问题、约 6.4 万条去重正文、约 670 万条正文条目。
-- 一半请求是认证身份（按用户筛选有结果）。会话 381~400 是 codex 开发作用域，命中全部为语义类并挂在语义告警组上（开发流量折叠）。
-- 正向代理会话每 10 轮一个 conversation（会话内依次 10 个请求）。
-- 由 TestAlertPerformanceRegression 在一次性库里执行；触发器在灌数期间关闭，结束后补算投影。
SET session_replication_role = replica;

INSERT INTO tenants(id, name) VALUES ('perf_t', '性能回归') ON CONFLICT (id) DO NOTHING;
INSERT INTO projects(id, tenant_id, name) VALUES
  ('perf_p1', 'perf_t', '应用一'), ('perf_p2', 'perf_t', '应用二')
ON CONFLICT (id) DO NOTHING;
INSERT INTO teams(id, tenant_id, name, path) VALUES ('perf_team', 'perf_t', '性能部门', 'perf_team') ON CONFLICT (id) DO NOTHING;
INSERT INTO users(id, tenant_id, username, department_id)
SELECT 'perf_u' || g, 'perf_t', '员工' || g, 'perf_team' FROM generate_series(1, 40) g
ON CONFLICT DO NOTHING;
INSERT INTO internal_keys(id, tenant_id, project_id, key_hash, key_prefix, user_id, name, traffic_class)
SELECT 'perf_k' || g, 'perf_t', CASE WHEN g % 2 = 0 THEN 'perf_p2' ELSE 'perf_p1' END,
       md5('perf_k' || g), 'sk-perf', 'perf_u' || g, '凭据' || g,
       CASE WHEN g <= 2 THEN 'evaluation' WHEN g <= 6 THEN 'coding' ELSE '' END
FROM generate_series(1, 40) g
ON CONFLICT (id) DO NOTHING;

CREATE TEMP TABLE perf_req AS
SELECT i, s, k, j,
       CASE WHEN k % 2 = 0 THEN 'perf_p2' ELSE 'perf_p1' END AS project_id,
       CASE WHEN s > 380 THEN 'codex' ELSE 'customer' END AS scope,
       now() - make_interval(secs => i * 194) AS at,
       'perf-hit-' || lpad(i::text, 8, '0') || 'a' AS raw0,
       'perf-hit-' || lpad(i::text, 8, '0') || 'b' AS raw1
FROM (
  SELECT i, ((i - 1) % 400) + 1 AS s, ((((i - 1) % 400)) % 40) + 1 AS k, (i - 1) / 400 AS j
  FROM generate_series(1, 40000) i
) base;

-- 命中正文：raw0 位于 content[40:58]，raw1 位于 content[100:118]。
CREATE TEMP TABLE perf_hit_body AS
SELECT r.*,
       repeat('前文内容填充', 6) || 'abcd' || r.raw0 || repeat('中间段落文字', 7) || r.raw1
         || repeat(' 后续正文内容用于构造足够长度的留存消息 lorem ipsum dolor sit amet ', 40) AS content
FROM perf_req r;

INSERT INTO request_logs(id, request_id, tenant_id, project_id, user_id, client_id, session_id,
  proxy_mode, proxy_target_host, proxy_target_path, proxy_method, proxy_provider, proxy_access_type,
  proxy_access_type_resolved, source_ip, environment_scope, principal_context_json, created_at, request_status)
SELECT 'perf_rl_' || i, 'perf_req_' || i, 'perf_t', project_id, 'perf_u' || k, 'perf_k' || k, 'perf_s' || s,
       CASE WHEN i % 2 = 0 THEN 'forward' END,
       CASE WHEN i % 2 = 0 THEN 'chat.deepseek.com' ELSE 'api.example.com' END,
       '/api/v0/chat/completion', 'POST', 'deepseek', 'llm', 'llm',
       '10.0.' || (k % 250) || '.' || (s % 250), scope,
       CASE WHEN i % 2 = 0 THEN jsonb_build_object('trust_level', 'authenticated', 'actor_user_id', 'perf_u' || k,
         'key_owner_user_id', 'perf_u' || k, 'key_id', 'perf_k' || k, 'identity_source', 'session', 'principal_key', 'user:perf_u' || k)
       ELSE jsonb_build_object('trust_level', 'key_bound', 'key_owner_user_id', 'perf_u' || k, 'key_id', 'perf_k' || k,
         'identity_source', 'api_key', 'principal_key', 'key:perf_k' || k) END,
       at, 'success'
FROM perf_req;

-- 正向代理：access_content_logs（会话 perf_conv_<会话>_<第几组 10 轮>）。
INSERT INTO access_content_logs(request_id, tenant_id, provider, product, conversation_id, section_id,
  request_content_redacted, response_content_redacted, environment_scope, created_at)
SELECT 'perf_req_' || i, 'perf_t', 'deepseek', 'deepseek-chat', 'perf_conv_' || s || '_' || (j / 10), 'perf_sec_' || i,
       content, '好的，以下是回复内容 ' || repeat('模型回复正文 ', 30), scope, at
FROM perf_hit_body WHERE i % 2 = 0;

-- 网关直连：content_log_entries + content_log_bodies。客户现场 4 万请求对应 670 万条正文条目、7.4 万条去重正文
-- （智能体每轮把会话历史整段重发）。这里每个直连请求 335 条消息：24 为本次用户消息（含命中），25 为模型回复，
-- 其余为会话历史（同一会话按 60 种历史正文循环共享）；直连 2 万请求共 670 万条，去重正文约 6.4 万条。
CREATE TEMP TABLE perf_history AS
SELECT s, h, c AS content, sha256(convert_to(c, 'UTF8')) AS sha FROM (
  SELECT s, h, '会话' || s || '的历史消息' || h || ' ' || repeat('历史上下文正文 context history text ', 60) AS c
  FROM generate_series(1, 400) s, generate_series(0, 59) h
) texts;
CREATE TEMP TABLE perf_own AS
SELECT h.i, h.content AS hit, sha256(convert_to(h.content, 'UTF8')) AS hit_sha,
       '回复' || h.i || ' ' || repeat('模型输出正文 assistant output text ', 50) AS reply
FROM perf_hit_body h WHERE h.i % 2 = 1;
ALTER TABLE perf_own ADD COLUMN reply_sha bytea;
UPDATE perf_own SET reply_sha = sha256(convert_to(reply, 'UTF8')) WHERE reply_sha IS NULL;

INSERT INTO content_log_bodies(tenant_id, content_sha256, content, customer_text, created_at)
SELECT DISTINCT ON (sha) 'perf_t', sha, content, true, now() - interval '90 days'
FROM (
  SELECT sha, content FROM perf_history
  UNION ALL SELECT hit_sha, hit FROM perf_own
  UNION ALL SELECT reply_sha, reply FROM perf_own
) bodies
ON CONFLICT DO NOTHING;

INSERT INTO content_log_entries(id, request_id, tenant_id, user_id, session_id, role, content_sha256,
  customer_text, created_at, environment_scope, message_index)
SELECT 'perf_cl_' || r.i || '_' || m, 'perf_rl_' || r.i, 'perf_t', 'perf_u' || r.k, 'perf_s' || r.s,
       CASE WHEN m % 2 = 0 THEN 'user' ELSE 'assistant' END,
       CASE WHEN m = 24 THEN o.hit_sha WHEN m = 25 THEN o.reply_sha ELSE ph.sha END,
       true, (r.at AT TIME ZONE 'UTC') + make_interval(secs => m / 1000.0), r.scope, m
FROM perf_req r JOIN perf_own o USING (i)
CROSS JOIN generate_series(0, 334) m
LEFT JOIN perf_history ph ON ph.s = r.s AND ph.h = m % 60
WHERE r.i % 2 = 1;

-- 告警组：普通组按（会话, 风险类别）；开发作用域会话的语义命中单独成组（可折叠）。
INSERT INTO alert_groups(id, tenant_id, project_id, group_key, status, severity, alert_type, title,
  request_id, first_seen_at, last_seen_at, class_key, domain)
SELECT 'perf_g_' || s || '_' || c, 'perf_t', MIN(project_id), 'perf_g_' || s || '_' || c,
       CASE WHEN s % 37 = 0 AND c = 1 THEN 'false_positive' ELSE 'open' END,
       'high', CASE WHEN c = 4 THEN 'semantic' ELSE 'content' END, '性能告警组',
       'perf_req_' || MIN(i), MIN(at), MAX(at),
       (ARRAY['pii_email', 'pii_phone', 'secret_api_key', 'catalog_policy', 'semantic_jailbreak'])[c + 1], 'content'
FROM perf_req, LATERAL (SELECT CASE WHEN s > 380 THEN 4 ELSE j % 5 END AS c) gc
GROUP BY s, c;

CREATE TEMP TABLE perf_finding_kind(c int PRIMARY KEY, type text, category text, severity text, rule_id text, rule_name text);
INSERT INTO perf_finding_kind VALUES
  (0, 'pii', 'email', 'medium', 'regex_email', '邮箱地址'),
  (1, 'pii', 'phone_cn', 'low', 'regex_phone_cn', '手机号'),
  (2, 'secret', 'api_key', 'high', 'regex_api_key', '接口密钥'),
  (3, 'catalog_policy', 'confidential_keyword', 'high', 'catalog_confidential', '涉密关键词'),
  (4, 'semantic_attack', 'semantic_jailbreak', 'high', 'semantic_jailbreak', '越狱攻击');

CREATE TEMP TABLE perf_event AS
SELECT 'perf_ev_' || r.i AS id, r.*, false AS second FROM perf_req r
UNION ALL
SELECT 'perf_ev2_' || r.i, r.*, true FROM perf_req r WHERE r.i % 10 IN (1, 2, 3);

INSERT INTO security_events(id, request_id, tenant_id, project_id, event_type, severity, action_taken,
  matched_summary, principal_key, conversation_key, alert_group_id, created_at)
SELECT e.id, 'perf_req_' || e.i, 'perf_t', e.project_id, 'security_check',
       CASE WHEN f0.severity = 'high' OR f1.severity = 'high' THEN 'high' ELSE 'medium' END,
       CASE WHEN e.i % 11 = 0 THEN 'block' ELSE 'flag' END,
       jsonb_build_object('stage', CASE WHEN e.second THEN 'output' ELSE 'input' END, 'target_host',
         CASE WHEN e.i % 2 = 0 THEN 'chat.deepseek.com' ELSE '' END,
         'findings', jsonb_build_array(
           jsonb_build_object('type', f0.type, 'category', f0.category, 'severity', f0.severity,
             'rule_id', f0.rule_id, 'rule_name', f0.rule_name, 'message_index', 24,
             'stage', CASE WHEN e.second THEN 'output' ELSE 'input' END,
             'content_source', CASE WHEN e.second THEN 'model_output' ELSE 'user' END,
             'matched_location', 'content[40:58]', 'action', 'audit',
             'redacted_evidence', left(e.raw0, 9) || '****（18 位）',
             'raw_evidence_sha256', encode(sha256(convert_to(e.raw0, 'UTF8')), 'hex'),
             'evidence_context_sha256', encode(sha256(convert_to(
               substring(h.content FROM 1 FOR LEAST(length(h.content), 558))
               || CASE WHEN 558 < length(h.content) THEN '…' ELSE '' END, 'UTF8')), 'hex'),
             'evidence_reason', 'matched ' || f0.rule_id,
             'triage', jsonb_build_object('detection_method', 'regex', 'confidence_kind', 'pattern')),
           jsonb_build_object('type', f1.type, 'category', f1.category, 'severity', f1.severity,
             'rule_id', f1.rule_id, 'rule_name', f1.rule_name, 'message_index', 24,
             'stage', 'input', 'content_source', 'user',
             'matched_location', 'content[100:118]', 'action', 'audit',
             'redacted_evidence', left(e.raw1, 9) || '****（18 位）',
             'raw_evidence_sha256', encode(sha256(convert_to(e.raw1, 'UTF8')), 'hex'),
             'evidence_reason', 'matched ' || f1.rule_id))),
       'key:perf_k' || e.k, 'perf_s' || e.s,
       'perf_g_' || e.s || '_' || CASE WHEN e.s > 380 THEN 4 ELSE e.j % 5 END,
       e.at + interval '1 second'
FROM perf_event e
JOIN perf_hit_body h USING (i)
JOIN perf_finding_kind f0 ON f0.c = CASE WHEN e.s > 380 THEN 4 ELSE e.j % 5 END
JOIN perf_finding_kind f1 ON f1.c = CASE WHEN e.s > 380 THEN 4 ELSE (e.j + 2) % 5 END;

INSERT INTO audit_dispositions(tenant_id, subject_type, subject_id, status, note, operator_id, operator_name)
SELECT 'perf_t', 'security_event', 'perf_ev_' || i, CASE WHEN i % 97 = 0 THEN 'false_positive' ELSE 'resolved' END,
       '性能回归', 'perf_u1', '员工1'
FROM generate_series(1, 40000) i WHERE i % 13 = 0 OR i % 97 = 0
ON CONFLICT DO NOTHING;
INSERT INTO audit_dispositions(tenant_id, subject_type, subject_id, status, note, operator_id, operator_name)
SELECT 'perf_t', 'request', 'perf_req_' || i, 'resolved', '性能回归', 'perf_u1', '员工1'
FROM generate_series(1, 40000) i WHERE i % 199 = 0
ON CONFLICT DO NOTHING;

SET session_replication_role = origin;
ANALYZE request_logs; ANALYZE security_events; ANALYZE content_log_entries; ANALYZE content_log_bodies;
ANALYZE access_content_logs; ANALYZE alert_groups; ANALYZE audit_dispositions;
