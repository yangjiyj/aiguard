\set ON_ERROR_STOP on

\if :{?tenant_id}
\else
\echo 'missing -v tenant_id=...'
\quit 3
\endif
\if :{?provider_id}
\else
\echo 'missing -v provider_id=...'
\quit 3
\endif
\if :{?model_name}
\else
\echo 'missing -v model_name=...'
\quit 3
\endif
\if :{?before_capabilities_json}
\else
\echo 'missing -v before_capabilities_json=...'
\quit 3
\endif
\if :{?enabled_capabilities_json}
\else
\echo 'missing -v enabled_capabilities_json=...'
\quit 3
\endif

BEGIN;

CREATE TEMP TABLE native_responses_rollback_values ON COMMIT DROP AS
SELECT :'before_capabilities_json'::jsonb AS before_capabilities,
       :'enabled_capabilities_json'::jsonb AS enabled_capabilities;

CREATE TEMP TABLE native_responses_target ON COMMIT DROP AS
SELECT m.id AS model_id
FROM models m
JOIN providers p ON p.id = m.provider_id
WHERE p.tenant_id = :'tenant_id'
  AND p.id = :'provider_id'
  AND m.model_name = :'model_name';

SELECT m.id
FROM models m
JOIN native_responses_target t ON t.model_id = m.id
FOR UPDATE OF m;

DO $$
DECLARE
  target_count integer;
BEGIN
  SELECT COUNT(*) INTO target_count FROM native_responses_target;
  IF target_count <> 1 THEN
    RAISE EXCEPTION 'expected exactly one route for rollback, found %', target_count;
  END IF;
  IF EXISTS (
    SELECT 1
    FROM native_responses_target t
    JOIN models m ON m.id = t.model_id
    CROSS JOIN native_responses_rollback_values v
    WHERE m.capabilities_json IS DISTINCT FROM v.enabled_capabilities
  ) THEN
    RAISE EXCEPTION 'route capabilities changed after enable; refusing destructive rollback';
  END IF;
END
$$;

UPDATE models m
SET capabilities_json = v.before_capabilities
FROM native_responses_target t
CROSS JOIN native_responses_rollback_values v
WHERE m.id = t.model_id
RETURNING m.id, m.model_name, m.provider_id, m.capabilities_json AS restored_capabilities;

COMMIT;
