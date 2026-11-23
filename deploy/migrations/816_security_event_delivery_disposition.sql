-- Split the overloaded alerted_at signal into processing, delivery and
-- disposition dimensions. All new columns are nullable for rolling upgrades.
ALTER TABLE security_events
    ADD COLUMN IF NOT EXISTS processed_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS delivery VARCHAR(24),
    ADD COLUMN IF NOT EXISTS disposition VARCHAR(24),
    ADD COLUMN IF NOT EXISTS suppression_reason TEXT;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_security_events_delivery'
          AND conrelid = 'security_events'::regclass
    ) THEN
        ALTER TABLE security_events
            ADD CONSTRAINT ck_security_events_delivery
            CHECK (
                delivery IS NULL
                OR delivery IN ('pending','delivered','suppressed','failed','not_applicable')
            ) NOT VALID;
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_security_events_disposition'
          AND conrelid = 'security_events'::regclass
    ) THEN
        ALTER TABLE security_events
            ADD CONSTRAINT ck_security_events_disposition
            CHECK (
                disposition IS NULL
                OR disposition IN (
                    'action_required','informational','false_positive',
                    'accepted_risk','suppressed'
                )
            ) NOT VALID;
    END IF;
END $$;

-- Historical rows are repaired by security_event_delivery_v1, registered
-- after its supporting concurrent index. Keep this expand step independent of
-- security_events cardinality.

COMMENT ON COLUMN security_events.processed_at IS
    'Bridge lifecycle decision committed; independent from notification delivery.';
COMMENT ON COLUMN security_events.delivery IS
    'Delivery outcome: pending/delivered/suppressed/failed/not_applicable; NULL is legacy unknown.';
COMMENT ON COLUMN security_events.disposition IS
    'Actionability or analyst disposition; independent from transport delivery.';
COMMENT ON COLUMN security_events.suppression_reason IS
    'Stable machine-readable reason when delivery is suppressed; NULL when absent or unknown.';
COMMENT ON COLUMN security_events.alerted_at IS
    'Legacy compatibility timestamp retained for rolling upgrades; new readers use processed_at and delivery.';
