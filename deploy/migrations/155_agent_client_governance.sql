-- Rename executable agent fingerprint policies as client governance controls.
-- Only untouched built-in display names are changed; tenant custom names remain intact.

BEGIN;

CREATE TEMP TABLE migration_155_agent_client_names (
    policy_code TEXT PRIMARY KEY,
    old_name TEXT NOT NULL,
    new_name TEXT NOT NULL,
    new_description TEXT NOT NULL
) ON COMMIT DROP;

INSERT INTO migration_155_agent_client_names(policy_code,old_name,new_name,new_description) VALUES
    ('builtin.agent_detect.f93768ab6617606e','Claude Code 检测','Claude Code 管控','识别 Anthropic Claude Code CLI 客户端指纹，并按策略审计或阻断'),
    ('builtin.agent_detect.b620fc06d06c1fc7','Cursor IDE 检测','Cursor IDE 管控','识别 Cursor IDE 客户端指纹，并按策略审计或阻断'),
    ('builtin.agent_detect.12438c4c568f8c24','GitHub Copilot 检测','GitHub Copilot 管控','识别 GitHub Copilot 客户端指纹，并按策略审计或阻断'),
    ('builtin.agent_detect.60879276c451279a','Cline/Roo Code 检测','Cline/Roo Code 管控','识别 Cline/Roo Code 客户端指纹，并按策略审计或阻断'),
    ('builtin.agent_detect.c1896e0995119428','Windsurf/Cascade 检测','Windsurf/Cascade 管控','识别 Windsurf/Cascade 客户端指纹，并按策略审计或阻断'),
    ('builtin.agent_detect.1d449b7a84677bb2','Continue.dev 检测','Continue.dev 管控','识别 Continue.dev 客户端指纹，并按策略审计或阻断');

UPDATE rules AS rule
SET name = names.new_name,
    description = names.new_description
FROM migration_155_agent_client_names AS names
WHERE rule.policy_code = names.policy_code
  AND rule.name = names.old_name;

COMMIT;
