-- Output text is not an instruction source. Running the input-side semantic
-- attack judge on model output produced high-confidence false positives for
-- normal coding answers. Deterministic output DLP detectors remain enabled.
INSERT INTO system_settings (key, value, updated_at)
VALUES ('semantic_output_enabled', 'false', NOW())
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value,
    updated_at = NOW()
WHERE system_settings.value IS DISTINCT FROM EXCLUDED.value;
