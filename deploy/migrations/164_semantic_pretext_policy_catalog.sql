-- Register high-confidence pretext and coercion injection policies.

BEGIN;

CREATE TEMP TABLE migration_164_capabilities ON COMMIT DROP AS
SELECT category,name,component,supported_stages,builtin_actions,mask_capable
FROM jsonb_to_recordset(
$runtime_policy_capabilities$
[
  {"category":"injection_few_shot_attack","name":"Few-shot 攻击","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_collaboration_pretext","name":"协作借口绕过","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_academic_pretext","name":"学术研究借口","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_comparison_pretext","name":"对比示例攻击","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_emotional_manipulation","name":"情感操控诱导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_tech_support_impersonation","name":"技术支持冒充","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_permutation_flood","name":"排列组合注入","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_terminology_obfuscation","name":"术语混淆绕过","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_forged_authority","name":"权威引用伪造","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_legal_threat","name":"法律威胁诱导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_privilege_escalation","name":"特权提升检测","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_urgency_coercion","name":"紧急语气绕过","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_fake_security_alert","name":"虚假安全警报","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_logic_puzzle_pretext","name":"逻辑谜题绕过","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_moral_dilemma","name":"道德困境诱导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_moral_authority","name":"道德权威施压","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false}
]
$runtime_policy_capabilities$::jsonb
) AS item(category TEXT,name TEXT,component TEXT,supported_stages JSONB,builtin_actions JSONB,mask_capable BOOLEAN);

INSERT INTO security_capabilities(id,category,name,capability_kind,component,selector_json,supported_stages,allowed_actions,mask_capable,enabled,metadata_json)
SELECT 'cap.static.'||category,category,name,'static',component,jsonb_build_object('category',category),supported_stages,builtin_actions,mask_capable,TRUE,'{"catalog":"semantic_pretext_policy","catalog_version":1}'::jsonb
FROM migration_164_capabilities
ON CONFLICT (category) DO UPDATE SET name=EXCLUDED.name,capability_kind=EXCLUDED.capability_kind,component=EXCLUDED.component,selector_json=EXCLUDED.selector_json,supported_stages=EXCLUDED.supported_stages,allowed_actions=EXCLUDED.allowed_actions,mask_capable=EXCLUDED.mask_capable,metadata_json=EXCLUDED.metadata_json;

CREATE TEMP TABLE migration_164_bindings ON COMMIT DROP AS
SELECT policy_code,rule_type,name,capability_categories,binding_mode
FROM jsonb_to_recordset(
$runtime_policy_bindings$
[
  {"rule_type":"prompt_injection","name":"Few-shot 攻击检测","policy_code":"builtin.prompt_injection.344b93890cdccc3e","capability_categories":["injection_few_shot_attack"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"协作借口绕过","policy_code":"builtin.prompt_injection.13c78c8cb376da98","capability_categories":["injection_collaboration_pretext"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"学术研究借口","policy_code":"builtin.prompt_injection.51e37afc89cb1115","capability_categories":["injection_academic_pretext"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"对比示例攻击","policy_code":"builtin.prompt_injection.af7e6ee3195516c6","capability_categories":["injection_comparison_pretext"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"情感操控诱导","policy_code":"builtin.prompt_injection.b322a14e01c1d5d5","capability_categories":["injection_emotional_manipulation"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"技术支持冒充","policy_code":"builtin.prompt_injection.d29c0062c05c6a04","capability_categories":["injection_tech_support_impersonation"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"排列组合注入","policy_code":"builtin.prompt_injection.7730b3cbd5246f1f","capability_categories":["injection_permutation_flood"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"术语混淆绕过","policy_code":"builtin.prompt_injection.c171230d59d1a27a","capability_categories":["injection_terminology_obfuscation"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"权威引用伪造","policy_code":"builtin.prompt_injection.90324ca72fb4d87a","capability_categories":["injection_forged_authority"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"法律威胁诱导","policy_code":"builtin.prompt_injection.5ce853ec8c7904ab","capability_categories":["injection_legal_threat"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"特权提升检测","policy_code":"builtin.prompt_injection.5e084cbc6cb3c32d","capability_categories":["injection_privilege_escalation"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"紧急语气绕过","policy_code":"builtin.prompt_injection.b2a9904f92b79552","capability_categories":["injection_urgency_coercion"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"虚假安全警报","policy_code":"builtin.prompt_injection.ba1fbb4a4032dc78","capability_categories":["injection_fake_security_alert"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"逻辑谜题绕过","policy_code":"builtin.prompt_injection.8c29ec75bf9c8cc1","capability_categories":["injection_logic_puzzle_pretext"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"道德困境诱导","policy_code":"builtin.prompt_injection.a74e7f1501822fc1","capability_categories":["injection_moral_dilemma"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"道德权威施压","policy_code":"builtin.prompt_injection.4a2869c6bcc5351c","capability_categories":["injection_moral_authority"],"binding_mode":"any"}
]
$runtime_policy_bindings$::jsonb
) AS item(policy_code TEXT,rule_type TEXT,name TEXT,capability_categories JSONB,binding_mode TEXT);

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,b.binding_mode,0,'{}'::jsonb
FROM migration_164_bindings b
JOIN rules r ON r.policy_code=b.policy_code
CROSS JOIN LATERAL jsonb_array_elements_text(b.capability_categories) category(value)
JOIN security_capabilities c ON c.category=category.value
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

COMMIT;
