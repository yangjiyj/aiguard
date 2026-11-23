-- Tenant overrides must never change the shared system policy definition.
ALTER TABLE builtin_rule_overrides ADD COLUMN IF NOT EXISTS redaction_json JSONB;
ALTER TABLE builtin_rule_overrides DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_has_value;
ALTER TABLE builtin_rule_overrides ADD CONSTRAINT ck_builtin_rule_overrides_has_value
    CHECK (action IS NOT NULL OR enabled IS NOT NULL OR capability_categories IS NOT NULL OR redaction_json IS NOT NULL);
ALTER TABLE builtin_rule_overrides DROP CONSTRAINT IF EXISTS ck_builtin_rule_overrides_redaction;
ALTER TABLE builtin_rule_overrides ADD CONSTRAINT ck_builtin_rule_overrides_redaction CHECK (
    redaction_json IS NULL OR (
        jsonb_typeof(redaction_json) = 'object'
        AND redaction_json ? 'replacement'
        AND jsonb_typeof(redaction_json->'replacement') = 'string'
        AND char_length(redaction_json->>'replacement') BETWEEN 1 AND 128
        AND btrim(redaction_json->>'replacement') <> ''
        AND position(E'\n' IN redaction_json->>'replacement') = 0
        AND position(E'\r' IN redaction_json->>'replacement') = 0
        AND position('<JJD_' IN redaction_json->>'replacement') = 0
        AND redaction_json ? 'restore_response'
        AND jsonb_typeof(redaction_json->'restore_response') = 'boolean'
        AND redaction_json - ARRAY['replacement','restore_response'] = '{}'::jsonb
    )
);
