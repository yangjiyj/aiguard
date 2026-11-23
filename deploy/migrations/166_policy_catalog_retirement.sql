-- Replace the ambiguous tool-anomaly placeholder with the executable high-risk
-- action signal, then retire only the catalog entries that require unavailable
-- cross-request state or duplicate another managed policy.

BEGIN;

/*
$runtime_policy_capabilities$
[
  {"category":"high_risk_action","name":"高危工具动作","component":"security-engine.agent-guard","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false}
]
$runtime_policy_capabilities$
*/

INSERT INTO security_capabilities(id,category,name,capability_kind,component,selector_json,supported_stages,allowed_actions,mask_capable,enabled,metadata_json)
VALUES ('cap.dynamic.high_risk_action','high_risk_action','高危工具动作','dynamic','security-engine.agent-guard','{"category":"high_risk_action"}'::jsonb,'["input"]'::jsonb,'["audit","block"]'::jsonb,FALSE,TRUE,'{"catalog":"policy_retirement","catalog_version":1}'::jsonb)
ON CONFLICT (category) DO UPDATE SET name=EXCLUDED.name,capability_kind=EXCLUDED.capability_kind,component=EXCLUDED.component,selector_json=EXCLUDED.selector_json,supported_stages=EXCLUDED.supported_stages,allowed_actions=EXCLUDED.allowed_actions,mask_capable=EXCLUDED.mask_capable,metadata_json=EXCLUDED.metadata_json;

UPDATE rules
SET name='高危工具调用检测',
    description='检测 shell_exec 等高危工具动作，并按策略审计或阻断'
WHERE policy_code='builtin.agent_detect.2451a4aa92aae6c4';

/*
$runtime_policy_bindings$
[
  {"rule_type":"agent_detect","name":"高危工具调用检测","policy_code":"builtin.agent_detect.2451a4aa92aae6c4","capability_categories":["high_risk_action"],"binding_mode":"any"}
]
$runtime_policy_bindings$
*/

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,'any',0,'{}'::jsonb
FROM rules r
JOIN security_capabilities c ON c.category='high_risk_action'
WHERE r.policy_code='builtin.agent_detect.2451a4aa92aae6c4'
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

CREATE TEMP TABLE migration_166_retired_codes ON COMMIT DROP AS
SELECT value AS policy_code
FROM jsonb_array_elements_text(
$retired_policy_codes$
[
  "builtin.agent_detect.53e522e6a7b8dac2",
  "builtin.agent_detect.967c7b3cfd32049a",
  "builtin.agent_detect.25c6ba2e41db01e3",
  "builtin.agent_detect.68cabce575a7dafa",
  "builtin.agent_detect.baf350658bb917ff",
  "builtin.agent_detect.4011bbc60f4c286d",
  "builtin.agent_detect.1ec9fa7c05668d6e",
  "builtin.agent_detect.6bb38a327f4ddadd",
  "builtin.content_safety.3cc66da68952eebe",
  "builtin.dos_protection.1d26c44f7b71efac",
  "builtin.dos_protection.e669fe2aeef676da",
  "builtin.prompt_injection.c2bd08c27cf70ea1",
  "builtin.prompt_injection.f45dc17b1e6725b7",
  "builtin.prompt_injection.cbadb8fba1cbd3ce",
  "builtin.prompt_injection.69e7baa759b6c503"
]
$retired_policy_codes$::jsonb
);

CREATE TEMP TABLE migration_166_retire_targets ON COMMIT DROP AS
SELECT r.id AS rule_id
FROM rules r
JOIN rule_sets rs ON rs.id=r.rule_set_id
JOIN migration_166_retired_codes retired ON retired.policy_code=r.policy_code
WHERE rs.source_type='system';

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM migration_166_retire_targets target
        JOIN security_events event ON event.rule_id=target.rule_id
    ) THEN
        RAISE EXCEPTION 'cannot retire policies referenced by security events';
    END IF;
    IF EXISTS (
        SELECT 1 FROM migration_166_retire_targets target
        JOIN builtin_rule_overrides override_row ON override_row.rule_id=target.rule_id
    ) THEN
        RAISE EXCEPTION 'cannot retire policies with tenant overrides';
    END IF;
    IF EXISTS (
        SELECT 1 FROM migration_166_retire_targets target
        JOIN content_audit_exceptions exception_row ON exception_row.rule_id=target.rule_id
    ) THEN
        RAISE EXCEPTION 'cannot retire policies with content exceptions';
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS retired_builtin_policy_catalog (
    migration_id TEXT NOT NULL,
    rule_id VARCHAR(64) NOT NULL,
    rule_set_id VARCHAR(64) NOT NULL,
    policy_code VARCHAR(128) NOT NULL,
    policy_snapshot JSONB NOT NULL,
    retired_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (migration_id,rule_id)
);

INSERT INTO retired_builtin_policy_catalog(migration_id,rule_id,rule_set_id,policy_code,policy_snapshot)
SELECT '166_policy_catalog_retirement',r.id,r.rule_set_id,r.policy_code,to_jsonb(r)
FROM migration_166_retire_targets target
JOIN rules r ON r.id=target.rule_id
ON CONFLICT (migration_id,rule_id) DO NOTHING;

DELETE FROM rules r
USING migration_166_retire_targets target
WHERE r.id=target.rule_id;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM rules r
        JOIN rule_sets rs ON rs.id=r.rule_set_id
        JOIN migration_166_retired_codes retired ON retired.policy_code=r.policy_code
        WHERE rs.source_type='system'
    ) THEN
        RAISE EXCEPTION 'explicit retired policy cleanup incomplete';
    END IF;
END $$;

COMMIT;
