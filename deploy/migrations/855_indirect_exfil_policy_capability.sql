-- Register the deterministic lower-trust private-data exfiltration finding as
-- an administrator-selectable capability. No policy action is changed here.
BEGIN;

INSERT INTO security_capabilities (
    id, category, name, capability_kind, component, selector_json,
    supported_stages, allowed_actions, mask_capable, enabled, metadata_json
)
VALUES (
    'cap.static.indirect_private_data_exfil',
    'indirect_private_data_exfil',
    'Untrusted private-data exfiltration instruction',
    'static',
    'security-engine.prompt-injection',
    '{"category":"indirect_private_data_exfil"}'::jsonb,
    '["input"]'::jsonb,
    '["audit","block"]'::jsonb,
    FALSE,
    TRUE,
    '{"catalog":"indirect_exfil_policy","catalog_version":1}'::jsonb
)
ON CONFLICT (category) DO NOTHING;

COMMIT;
