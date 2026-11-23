-- T15 G1 batch 3 (F1): record every admin that ever rotated a trusted agent principal's
-- credential. A rotator obtains a working agent credential, so separation of duties must
-- treat each rotator like the creator: none of them may resolve that principal's approvals
-- or create exceptions for it. Rows rotated before this migration have credential_rotated_at
-- set but an empty rotated_by; the approval path fails closed for them until the next rotation.
-- Source-only migration; apply only through the normal reviewed deployment sequence.
ALTER TABLE agent_authorization_principals
    ADD COLUMN IF NOT EXISTS rotated_by TEXT[] NOT NULL DEFAULT '{}';
