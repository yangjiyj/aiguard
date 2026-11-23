-- 942: durable metering evidence columns for billing_usage_facts.
--
-- Goal: full-input idempotency and stable evidence snapshots for the metering
-- showback chain. The gateway already sends raw usage evidence and the original
-- request status with every measurement; until now the control plane dropped
-- both and derived only the outcome status, so replays could not prove the
-- inputs matched and admitted_at drifted out of the record.
--
-- Forward compatible by construction: additive nullable columns, no backfill
-- and no default change. Pre-942 facts keep NULL in these columns; readers and
-- the metering idempotency check treat NULL as "legacy row" and fall back to
-- the conservative family comparison instead of conflicting. No existing
-- INSERT names these columns, so old code runs unchanged against this schema.
ALTER TABLE billing_usage_facts ADD COLUMN IF NOT EXISTS request_status VARCHAR(64);
ALTER TABLE billing_usage_facts ADD COLUMN IF NOT EXISTS admitted_at TIMESTAMPTZ;
ALTER TABLE billing_usage_facts ADD COLUMN IF NOT EXISTS raw_usage_json JSONB;
--
-- admitted_at_supplied records whether the CALLER actually supplied an
-- admission timestamp, as opposed to the store defaulting one. The value alone
-- cannot express that: a defaulted timestamp is a real time, so a later replay
-- omitting the field would compare a caller intent against store bookkeeping
-- and either conflict spuriously or match by accident. Persisting the presence
-- bit makes the comparison exact in both directions:
--   both supplied      -> compare admitted_at at PostgreSQL microseconds
--   both omitted       -> reuse the first write's default (absence matches)
--   supplied vs omitted-> ErrIdempotencyConflict (the replay changed the input)
--
-- Nullable with no default, deliberately: NULL means "written before this
-- column existed" and is never treated as false or backfilled, so a pre-942
-- fact stays an honestly unverified legacy row instead of acquiring a
-- fabricated presence bit.
ALTER TABLE billing_usage_facts ADD COLUMN IF NOT EXISTS admitted_at_supplied BOOLEAN;
