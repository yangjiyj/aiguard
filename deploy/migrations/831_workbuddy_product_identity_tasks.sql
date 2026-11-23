BEGIN;
-- Repair only retained generated product_identity evidence. No names inferred from human prose.
CREATE TABLE IF NOT EXISTS agent_protocol_repairs (
 migration text NOT NULL, tenant_id text NOT NULL, request_id text NOT NULL,
 previous_identity jsonb NOT NULL, corrected_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(migration,tenant_id,request_id)
);
/*
-- Superseded synchronous implementation retained as checksum documentation.
CREATE TEMP TABLE workbuddy_product_repairs ON COMMIT DROP AS
WITH candidates AS (
 SELECT r.id,r.tenant_id,r.request_id,
 (regexp_match(c.content, '(?s)^\s*<system-reminder\s+data-role=["'']user-context["'']>\s*<user_info>.*?Workspace Folder:[ \t]*([^\r\n<]+).*?</user_info>.*?<product_identity>\s*You are WorkBuddy,.*?</product_identity>.*?</system-reminder>\s*<user_query>.*?</user_query>\s*$'))[1] AS workspace,
 jsonb_build_object('agent_type',r.agent_type,'source',r.agent_detection_source,'confidence',r.agent_detection_confidence,'evidence_run_id',r.evidence_run_id,'evidence_run_source',r.evidence_run_source) AS previous_identity
 FROM request_logs r JOIN content_logs c ON c.request_id=r.id AND c.tenant_id=r.tenant_id AND c.environment_scope=r.environment_scope
 WHERE c.role='user' AND r.created_at >= now()-interval '7 days' AND r.agent_identity_rule_id IS NULL
 AND (COALESCE(r.agent_detection_source,'') IN ('','message_protocol','content','user_agent_runtime')
   OR (r.agent_type IN ('main','default','agent','assistant','unknown') AND r.agent_detection_source IN ('client_header','explicit_header')))
 AND COALESCE(r.session_id,'')=''
), consistent AS (
 SELECT id,tenant_id,request_id,min(btrim(workspace)) AS workspace,(array_agg(previous_identity))[1] AS previous_identity
 FROM candidates WHERE workspace IS NOT NULL AND btrim(workspace)<>''
 GROUP BY id,tenant_id,request_id HAVING count(DISTINCT btrim(workspace))=1
)
SELECT * FROM consistent;
INSERT INTO agent_protocol_repairs(migration,tenant_id,request_id,previous_identity)
 SELECT '831',tenant_id,request_id,previous_identity FROM workbuddy_product_repairs ON CONFLICT DO NOTHING;
UPDATE request_logs r SET agent_type='workbuddy',agent_detection_source='product_identity',agent_detection_confidence=0.98,
 evidence_run_source='workbuddy_workspace',
 evidence_run_id='run_' || substr(encode(sha256(convert_to(r.tenant_id,'UTF8') || decode('00','hex') || convert_to('workbuddy_workspace','UTF8') || decode('00','hex') || convert_to(p.workspace,'UTF8')),'hex'),1,32)
 FROM workbuddy_product_repairs p WHERE r.id=p.id AND r.tenant_id=p.tenant_id;
*/

-- Historical repairs and before-image audit rows are written by
-- workbuddy_identity_v1 in bounded transactions.

COMMIT;
