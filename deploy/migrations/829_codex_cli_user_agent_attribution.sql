BEGIN;

-- Historical repair is registered by migration 835 and runs in bounded
-- request_log_compatibility_v1 batches. No conversation text is inspected.

COMMIT;
