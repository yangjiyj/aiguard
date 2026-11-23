-- PATCH semantics require an absent action override to continue inheriting the
-- shipped system-policy action. Existing rows remain unchanged.
ALTER TABLE builtin_rule_overrides
    ALTER COLUMN action DROP NOT NULL;

-- A partial override is useful, but an empty override is not: it would shadow
-- nothing while still looking like tenant configuration. Keep the invariant
-- at the database boundary so every writer has the same PATCH semantics.
DELETE FROM builtin_rule_overrides
WHERE action IS NULL AND enabled IS NULL;

ALTER TABLE builtin_rule_overrides
    DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_has_value;

ALTER TABLE builtin_rule_overrides
    ADD CONSTRAINT ck_builtin_rule_overrides_has_value
    CHECK (action IS NOT NULL OR enabled IS NOT NULL);
