# Security Event Lifecycle Compatibility

## Problem

The security_events.alerted_at field currently carries several meanings: the
bridge saw an event, the event was eligible for an alert group, and a
notification may have been delivered. A NULL value cannot distinguish pending
work from an intentional suppression.

## Additive schema

Migration 816 adds four nullable columns without removing or changing
alerted_at:

- processed_at: the bridge committed a lifecycle decision.
- delivery: pending, delivered, suppressed, failed, or not_applicable.
- disposition: action_required, informational, false_positive, accepted_risk,
  or suppressed.
- suppression_reason: a stable machine-readable reason for suppression.

delivery describes transport/outcome. disposition describes actionability or
analyst judgment. They are intentionally independent.

## Historical compatibility

Rows where alerted_at IS NOT NULL can safely be backfilled as processed and
delivered. Rows where alerted_at IS NULL remain NULL in all four new columns:
legacy data cannot prove whether the event was pending, suppressed, or never
eligible, so migration must not invent a disposition or suppression reason.

Old binaries may continue reading and writing alerted_at during a rolling
upgrade. New readers should prefer the four new columns and use alerted_at only
as a legacy fallback. The column is not dropped in this migration.

## Writer rollout

This change deliberately does not update production writers. A later release
must dual-write in this order:

1. Set processed_at when the bridge commits its decision.
2. Set disposition from lifecycle classification.
3. Set delivery from notification/group delivery outcome.
4. Set suppression_reason only for a known suppression decision.
5. Continue setting alerted_at for a delivered legacy-compatible alert until
   all supported readers have migrated.

Failures must use delivery=failed; they must not be represented as suppressed.
Unknown historical state remains NULL.

## Read compatibility

API responses can add these fields as nullable values. Existing clients remain
compatible because no current field changes meaning or type. Filtering by the
new dimensions should be introduced only after dual-write coverage is
measured. Any dashboard based solely on alerted_at remains a legacy view and
must not claim notification delivery or suppression certainty.
