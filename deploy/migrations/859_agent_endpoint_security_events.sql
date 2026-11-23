BEGIN;

-- P0-2 端点事件接入既有安全告警聚合（agent_endpoint 源）。
-- 端点事件没有网关 request_logs 投影，也不归属某个 gateway project（agent_endpoints 无 project 字段），
-- 故允许该源 security_events 的 request_id / project_id 为空，不伪造请求或项目。
-- 仅当 matched_summary->>'source' = 'agent_endpoint' 时放行空值；其它来源仍强制必填。
-- CHECK 使用 COALESCE 杜绝 matched_summary 为 NULL / 缺 source 键导致 ->>'source' 为 NULL 而放行普通事件的漏洞。

ALTER TABLE security_events ALTER COLUMN request_id DROP NOT NULL;
ALTER TABLE security_events ALTER COLUMN project_id DROP NOT NULL;

ALTER TABLE security_events ADD CONSTRAINT ck_security_events_request_id_agent_endpoint
  CHECK (request_id IS NOT NULL OR COALESCE(matched_summary->>'source', '') = 'agent_endpoint');

ALTER TABLE security_events ADD CONSTRAINT ck_security_events_project_id_agent_endpoint
  CHECK (project_id IS NOT NULL OR COALESCE(matched_summary->>'source', '') = 'agent_endpoint');

COMMIT;
