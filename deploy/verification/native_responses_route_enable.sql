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

BEGIN;

CREATE TEMP TABLE native_responses_target ON COMMIT DROP AS
SELECT m.id AS model_id
FROM models m
JOIN providers p ON p.id = m.provider_id
WHERE p.tenant_id = :'tenant_id'
  AND p.id = :'provider_id'
  AND m.model_name = :'model_name'
  AND p.status = 'active'
  AND m.status = 'active';

SELECT m.id
FROM models m
JOIN native_responses_target t ON t.model_id = m.id
FOR UPDATE OF m;

ALTER TABLE native_responses_target ADD COLUMN before_capabilities jsonb;
UPDATE native_responses_target t
SET before_capabilities = m.capabilities_json
FROM models m
WHERE m.id = t.model_id;

DO $$
DECLARE
  target_count integer;
BEGIN
  SELECT COUNT(*) INTO target_count FROM native_responses_target;
  IF target_count <> 1 THEN
    RAISE EXCEPTION 'expected exactly one active route, found %', target_count;
  END IF;
  IF EXISTS (
    SELECT 1 FROM native_responses_target
    WHERE before_capabilities ? 'protocols'
      AND jsonb_typeof(before_capabilities->'protocols') <> 'object'
  ) THEN
    RAISE EXCEPTION 'capabilities_json.protocols must be an object';
  END IF;
END
$$;

SELECT model_id, before_capabilities
FROM native_responses_target;

UPDATE models m
SET capabilities_json = jsonb_set(
  COALESCE(m.capabilities_json, '{}'::jsonb),
  '{protocols}',
  COALESCE(m.capabilities_json->'protocols', '{}'::jsonb)
    || jsonb_build_object('responses_native', true),
  true
)
FROM native_responses_target t
WHERE m.id = t.model_id
RETURNING m.id, m.model_name, m.provider_id, m.capabilities_json AS after_capabilities;

COMMIT;
