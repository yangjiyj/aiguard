-- Semantic runtime truth defaults.
-- Missing UI values must never be interpreted as enabled. Existing operator choices win.
INSERT INTO system_settings (key, value, updated_at)
VALUES
    ('semantic_enabled', 'false', NOW()),
    ('semantic_input_enabled', 'false', NOW()),
    ('semantic_agent_enabled', 'false', NOW()),
    ('semantic_output_enabled', 'false', NOW()),
    ('semantic_sample_rate', '1', NOW()),
    ('semantic_total_timeout', '6', NOW()),
    ('judge_allow_private_egress', 'false', NOW()),
    ('judge_backend', 'bundled', NOW())
ON CONFLICT (key) DO NOTHING;
