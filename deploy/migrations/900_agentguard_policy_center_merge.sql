-- Migration 900 (W5 5.1 + 5.7): policy-center AgentGuard categories.
--
-- 5.1: before this fix every policy-center category save created its own
-- tenant policy (the managed ID was overwritten with agp_xxx), and the gateway
-- resolves exactly one tenant policy, so only one category took effect. Merge
-- every policy that carries a policy-center managed rule into a single policy
-- per tenant, id = 'policy-center-ag-' || left(sha256(tenant_id),16) (must stay
-- byte-identical to policyCenterAgentGuardPolicyIDFor in control-plane).
--
-- 5.7 (D4): "仅记录" was stored as action=allow, which suppressed the audit
-- trail. It means record-and-forward: managed rules with allow become audit.
--
-- Only rules whose id is one of the four managed ids are merged. For each
-- managed id the most recently updated source wins. Advanced (non-managed)
-- rules found in a merged source are carried over unless their id collides.
-- Source policies are deleted only after the merged row exists; versions and
-- rollouts of deleted sources cascade (they described the broken layout).
-- Idempotent: a second run finds only the merged policy and changes nothing.
BEGIN;

CREATE TEMP TABLE ws5_pc_sources ON COMMIT DROP AS
SELECT p.*,
       'policy-center-ag-' || left(encode(sha256(convert_to(p.tenant_id, 'UTF8')), 'hex'), 16) AS merged_id
FROM agentguard_policies p
WHERE p.scope_type = 'tenant'
  AND COALESCE(p.scope_ref, '') = ''
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(
      CASE WHEN jsonb_typeof(p.rules_json->'rules') = 'array' THEN p.rules_json->'rules' ELSE '[]'::jsonb END
    ) rule
    WHERE rule->>'id' IN ('policy-center-system_command', 'policy-center-sensitive_resource',
                          'policy-center-network_egress', 'policy-center-database_change')
  );

-- One row per (tenant, rule id): the newest source policy wins for managed ids.
CREATE TEMP TABLE ws5_pc_rules ON COMMIT DROP AS
SELECT DISTINCT ON (s.tenant_id, rule->>'id')
       s.tenant_id, s.merged_id, rule->>'id' AS rule_id,
       CASE
         WHEN rule->>'id' LIKE 'policy-center-%' AND rule->>'action' = 'allow'
           THEN jsonb_set(rule, '{action}', '"audit"')
         ELSE rule
       END AS rule,
       (rule->>'id' LIKE 'policy-center-%') AS managed
FROM ws5_pc_sources s,
     jsonb_array_elements(
       CASE WHEN jsonb_typeof(s.rules_json->'rules') = 'array' THEN s.rules_json->'rules' ELSE '[]'::jsonb END
     ) rule
WHERE COALESCE(rule->>'id', '') <> ''
ORDER BY s.tenant_id, rule->>'id', s.updated_at DESC, s.created_at DESC, s.id;

-- Only tenants that actually need a change: several sources, a source that is
-- not the merged row yet, or a managed allow still stored.
CREATE TEMP TABLE ws5_pc_tenants ON COMMIT DROP AS
SELECT s.tenant_id, s.merged_id
FROM ws5_pc_sources s
GROUP BY s.tenant_id, s.merged_id
HAVING COUNT(*) > 1
    OR bool_or(s.id <> s.merged_id)
    OR EXISTS (
      SELECT 1 FROM ws5_pc_sources s2,
        jsonb_array_elements(s2.rules_json->'rules') r2
      WHERE s2.tenant_id = s.tenant_id
        AND r2->>'id' LIKE 'policy-center-%' AND r2->>'action' = 'allow'
    );

-- Upsert the merged policy. Policy-level mode/default stay audit: category
-- enforcement lives in the rules (the gateway applies rules in strict).
INSERT INTO agentguard_policies (
  id, tenant_id, name, scope_type, scope_ref, mode, default_action, fail_policy,
  priority, enabled, template_id, rules_json, behavior_json, dlp_json,
  created_by, updated_by, created_at, updated_at
)
SELECT t.merged_id, t.tenant_id, '策略中心托管规则', 'tenant', '', 'audit', 'audit', 'fail_closed',
       COALESCE((SELECT max(s.priority) FROM ws5_pc_sources s WHERE s.tenant_id = t.tenant_id), 0),
       TRUE, NULL,
       jsonb_build_object('rules', COALESCE((
         SELECT jsonb_agg(r.rule ORDER BY r.managed DESC, r.rule_id)
         FROM ws5_pc_rules r WHERE r.tenant_id = t.tenant_id), '[]'::jsonb)),
       COALESCE((SELECT s.behavior_json FROM ws5_pc_sources s WHERE s.tenant_id = t.tenant_id
                 ORDER BY s.updated_at DESC, s.id LIMIT 1), '{}'::jsonb),
       COALESCE((SELECT s.dlp_json FROM ws5_pc_sources s WHERE s.tenant_id = t.tenant_id
                 ORDER BY s.updated_at DESC, s.id LIMIT 1), '{}'::jsonb),
       'migration_900', 'migration_900', NOW(), NOW()
FROM ws5_pc_tenants t
ON CONFLICT (id) DO UPDATE
SET rules_json = EXCLUDED.rules_json,
    behavior_json = EXCLUDED.behavior_json,
    dlp_json = EXCLUDED.dlp_json,
    enabled = TRUE,
    updated_by = 'migration_900',
    updated_at = NOW();

-- Drop the per-category duplicates (never the merged row itself).
DELETE FROM agentguard_policies p
USING ws5_pc_sources s, ws5_pc_tenants t
WHERE p.id = s.id AND s.tenant_id = t.tenant_id AND p.id <> t.merged_id;

-- The merged policy's old active version (if any) no longer matches its rules;
-- deactivate it so control-plane writes a fresh version on the next save and
-- the gateway falls back to the newest listed version meanwhile.
UPDATE agentguard_policy_versions v
SET active = FALSE
FROM ws5_pc_tenants t
WHERE v.policy_id = t.merged_id AND v.tenant_id = t.tenant_id AND v.active;

COMMIT;
