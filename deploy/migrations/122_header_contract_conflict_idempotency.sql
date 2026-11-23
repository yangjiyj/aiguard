-- Dedicated idempotency constraints for critical header-conflict evidence.
-- Refuse to hide pre-existing duplicate WORM identities behind index creation.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM audit_chain
        WHERE event_type = 'header_contract_conflict'
        GROUP BY event_id
        HAVING count(*) > 1
    ) THEN
        RAISE EXCEPTION 'duplicate header_contract_conflict event_id exists';
    END IF;
END $$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_operations_header_contract_conflict_id
    ON audit_operations (id)
    WHERE action_type = 'header_contract_conflict';

CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_chain_header_contract_conflict_event_id
    ON audit_chain (event_id)
    WHERE event_type = 'header_contract_conflict';
