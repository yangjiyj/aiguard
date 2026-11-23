-- Audit-only identity registration. Original observations are retained for review/revocation.
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS agent_identity_headers jsonb NOT NULL DEFAULT '{}';
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS agent_identity_observed jsonb;
ALTER TABLE request_logs ADD COLUMN IF NOT EXISTS agent_identity_rule_id text;
CREATE TABLE IF NOT EXISTS agent_identity_rules (
 id text PRIMARY KEY, tenant_id text NOT NULL, environment_scope text NOT NULL,
 channel text NOT NULL, client_id text NOT NULL DEFAULT '', request_id text NOT NULL,
 user_agent text NOT NULL DEFAULT '', declared_type text NOT NULL DEFAULT '', declared_name text NOT NULL DEFAULT '',
 scope text NOT NULL CHECK(scope IN ('request','fingerprint','dedicated_key')),
 agent_type text NOT NULL, note text NOT NULL, operator_id text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz, revoked_by text
);
CREATE INDEX IF NOT EXISTS agent_identity_rules_match ON agent_identity_rules(tenant_id,environment_scope,channel,client_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS request_logs_identity_rule ON request_logs(agent_identity_rule_id) WHERE agent_identity_rule_id IS NOT NULL;
CREATE OR REPLACE FUNCTION agent_identity_known(t text) RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
 SELECT COALESCE(t,'') = ANY(ARRAY['claude-code','openai-codex','cursor','windsurf','github-copilot','cline','roo-code','kilo-code','continue','aider','amazon-q-developer','gemini-code-assist','coderabbit','autogpt-babyagi','langchain-llamaindex','crewai-autogen','dify-coze','opencode','devin','amp','goose','gemini-cli','qwen-code','jetbrains-junie','tabnine','qodo','sourcegraph-cody','amazon-kiro','google-antigravity','replit-agent','bolt','lovable','v0','codebuddy','tongyi-lingma','qoder','codearts-snap','deveco-codegenie','trae','marscode','baidu-comate','iflycode','codegeex','codefuse','workbuddy']::text[])
$$;
CREATE OR REPLACE FUNCTION apply_agent_identity_registration() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE obs jsonb; rule agent_identity_rules%ROWTYPE; detected_source text;
BEGIN
 -- For updates that keep our projection, first restore the observed identity.
 IF TG_OP = 'UPDATE' AND NEW.agent_detection_source IN ('manual_confirmation','registered_identity') THEN
   obs := COALESCE(OLD.agent_identity_observed, jsonb_build_object('type',OLD.agent_type,'source',OLD.agent_detection_source,'confidence',OLD.agent_detection_confidence));
   NEW.agent_type := obs->>'type';
   NEW.agent_detection_source := obs->>'source';
   NEW.agent_detection_confidence := (obs->>'confidence')::double precision;
 END IF;
 -- Header provenance is only applicable when the observed type came from those headers.
 detected_source := NEW.agent_identity_headers->>'header_source';
 IF COALESCE(NEW.agent_detection_source,'') = '' AND COALESCE(NEW.agent_type,'') <> '' THEN
   IF NEW.agent_identity_headers->>'header_product' = NEW.agent_type THEN
     NEW.agent_detection_source := detected_source;
   END IF;
 END IF;
 NEW.agent_identity_observed := jsonb_build_object('type',NEW.agent_type,'source',NEW.agent_detection_source,'confidence',NEW.agent_detection_confidence);
 NEW.agent_identity_rule_id := NULL;
 -- Never override a recognised client with a registration for an unknown observation.
 IF agent_identity_known(NEW.agent_type) THEN RETURN NEW; END IF;
 SELECT ar.* INTO rule FROM agent_identity_rules ar
 WHERE ar.revoked_at IS NULL AND ar.tenant_id = NEW.tenant_id
   AND ar.environment_scope = COALESCE(NEW.environment_scope,'') AND ar.channel = COALESCE(NEW.proxy_mode,'')
   AND ((ar.scope = 'request' AND ar.request_id = NEW.request_id)
     OR (ar.scope <> 'request' AND (NEW.created_at >= ar.created_at OR NEW.request_id = ar.request_id) AND ar.client_id <> '' AND ar.client_id = COALESCE(NEW.client_id,'')
       AND (ar.scope = 'dedicated_key' OR (
         ar.user_agent = COALESCE(NEW.proxy_user_agent,'')
         AND ar.declared_type = COALESCE(NEW.agent_identity_headers->>'declared_type',NEW.agent_type,'')
         AND ar.declared_name = COALESCE(NEW.agent_identity_headers->>'declared_name','')
       ))))
 ORDER BY (ar.scope = 'request') DESC, ar.created_at DESC LIMIT 1;
 IF FOUND THEN
   NEW.agent_type := rule.agent_type;
   NEW.agent_detection_source := CASE WHEN rule.scope = 'request' THEN 'manual_confirmation' ELSE 'registered_identity' END;
   NEW.agent_detection_confidence := NULL;
   NEW.agent_identity_rule_id := rule.id;
 END IF;
 RETURN NEW;
END $$;
DROP TRIGGER IF EXISTS a_agent_identity_registration ON request_logs;
CREATE TRIGGER a_agent_identity_registration BEFORE INSERT OR UPDATE OF agent_type,agent_detection_source,agent_identity_headers,agent_identity_rule_id,client_id,proxy_user_agent
 ON request_logs FOR EACH ROW EXECUTE FUNCTION apply_agent_identity_registration();
