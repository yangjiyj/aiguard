-- The prompt-injection detector no longer emits encoding_zero_width. The
-- prompt-stego detector remains authoritative through zero_width_char.
-- Preserve the capability row for historical evidence, but remove it from
-- active policy evaluation and prevent it from appearing as configurable.

DROP TABLE IF EXISTS migration_138_retired_capabilities;
CREATE TEMP TABLE migration_138_retired_capabilities (
    category VARCHAR(128) PRIMARY KEY
);

INSERT INTO migration_138_retired_capabilities(category)
SELECT value #>> '{}'
FROM jsonb_array_elements(
$retired_static_capability_categories$
["encoding_zero_width"]
$retired_static_capability_categories$::jsonb
);

DELETE FROM rule_capability_bindings binding
USING security_capabilities capability, migration_138_retired_capabilities retired
WHERE binding.capability_id = capability.id
  AND capability.category = retired.category;

UPDATE security_capabilities capability
SET enabled = FALSE,
    metadata_json = capability.metadata_json || jsonb_build_object(
        'retired', TRUE,
        'retired_reason', 'detector_removed'
    ),
    updated_at = NOW()
FROM migration_138_retired_capabilities retired
WHERE capability.category = retired.category;

DROP TABLE migration_138_retired_capabilities;
