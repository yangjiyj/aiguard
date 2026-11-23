-- 2.9.2 does not enforce model_allowlist. Run while ingress and writes are blocked.
-- psql -v ON_ERROR_STOP=1 -f deploy/verification/acme_key_model_rollback_gate.sql
-- This gate is read-only and never clears restrictions or revokes keys.
BEGIN READ ONLY;
DO $gate$
BEGIN
 IF EXISTS(SELECT 1 FROM internal_keys WHERE status='active' AND cardinality(model_allowlist)>0) THEN
  RAISE EXCEPTION 'ROLLBACK_BLOCKED: active keys require model allowlist enforcement; keep compatible gateway and recover forward';
 END IF;
END
$gate$;
COMMIT;
