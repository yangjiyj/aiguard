-- Register high-confidence harmful-content intent policies.

BEGIN;

CREATE TEMP TABLE migration_162_capabilities ON COMMIT DROP AS
SELECT category,name,component,supported_stages,builtin_actions,mask_capable
FROM jsonb_to_recordset(
$runtime_policy_capabilities$
[
  {"category":"content_doxxing_guidance","name":"人肉搜索指导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_personal_assault_guidance","name":"人身攻击指导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_hate_incitement","name":"仇恨言论煽动","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_medical_fraud","name":"医疗欺诈内容","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_domestic_violence","name":"家庭暴力内容","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_sexual_violence","name":"性暴力内容","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_terrorism_propaganda","name":"恐怖主义宣传","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_minor_exploitation","name":"未成年人侵害","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_school_bullying","name":"校园暴力内容","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_weapon_construction","name":"武器制作指导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_discrimination","name":"歧视内容生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_drug_manufacturing","name":"毒品制作指导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_subversion_incitement","name":"煽动颠覆内容","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_pollution_guidance","name":"环境污染指导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_cyberattack_tutorial","name":"网络攻击教程","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_online_mob_attack","name":"网络暴力内容","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_self_harm_encouragement","name":"自残自杀鼓励内容","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_prescription_abuse","name":"药品滥用指导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_animal_abuse","name":"虐待动物内容","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_harmful_rumor_creation","name":"有害谣言生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_contraband_guidance","name":"违禁品指导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_cult_recruitment","name":"邪教宣传招募","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_food_safety_violation","name":"食品安全违规指导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_harassment_bullying","name":"骚扰霸凌内容","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false}
]
$runtime_policy_capabilities$::jsonb
) AS item(category TEXT,name TEXT,component TEXT,supported_stages JSONB,builtin_actions JSONB,mask_capable BOOLEAN);

INSERT INTO security_capabilities(id,category,name,capability_kind,component,selector_json,supported_stages,allowed_actions,mask_capable,enabled,metadata_json)
SELECT 'cap.static.'||category,category,name,'static',component,jsonb_build_object('category',category),supported_stages,builtin_actions,mask_capable,TRUE,'{"catalog":"content_safety_policy","catalog_version":1}'::jsonb
FROM migration_162_capabilities
ON CONFLICT (category) DO UPDATE SET name=EXCLUDED.name,capability_kind=EXCLUDED.capability_kind,component=EXCLUDED.component,selector_json=EXCLUDED.selector_json,supported_stages=EXCLUDED.supported_stages,allowed_actions=EXCLUDED.allowed_actions,mask_capable=EXCLUDED.mask_capable,metadata_json=EXCLUDED.metadata_json;

CREATE TEMP TABLE migration_162_bindings ON COMMIT DROP AS
SELECT policy_code,rule_type,name,capability_categories,binding_mode
FROM jsonb_to_recordset(
$runtime_policy_bindings$
[
  {"rule_type":"content_safety","name":"人肉搜索指导","policy_code":"builtin.content_safety.93a1f2312c974373","capability_categories":["content_doxxing_guidance"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"人身攻击指导","policy_code":"builtin.content_safety.94c8f6138ae0a180","capability_categories":["content_personal_assault_guidance"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"仇恨言论","policy_code":"builtin.content_safety.130064bdc1ae51ab","capability_categories":["content_hate_incitement"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"医疗欺诈内容","policy_code":"builtin.content_safety.f658a2f524585da0","capability_categories":["content_medical_fraud"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"家庭暴力内容","policy_code":"builtin.content_safety.e741adeb0f05ae95","capability_categories":["content_domestic_violence"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"性暴力内容","policy_code":"builtin.content_safety.94cbba62575e32f9","capability_categories":["content_sexual_violence"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"恐怖主义宣传","policy_code":"builtin.content_safety.3f07c132c798a867","capability_categories":["content_terrorism_propaganda"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"未成年人保护","policy_code":"builtin.content_safety.972bcf8de3b4d32d","capability_categories":["content_minor_exploitation"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"校园暴力内容","policy_code":"builtin.content_safety.167af81998f1d9d8","capability_categories":["content_school_bullying"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"武器制作指导","policy_code":"builtin.content_safety.2e163d09b9155752","capability_categories":["content_weapon_construction"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"歧视内容","policy_code":"builtin.content_safety.741b4225c2f0b108","capability_categories":["content_discrimination"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"毒品制作指导","policy_code":"builtin.content_safety.2e7c3d1811c916b4","capability_categories":["content_drug_manufacturing"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"煽动颠覆内容","policy_code":"builtin.content_safety.84b78c69bd854278","capability_categories":["content_subversion_incitement"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"环境污染指导","policy_code":"builtin.content_safety.66f2bb762e173339","capability_categories":["content_pollution_guidance"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"网络攻击教程","policy_code":"builtin.content_safety.fc486a78d9176d14","capability_categories":["content_cyberattack_tutorial"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"网络暴力内容","policy_code":"builtin.content_safety.c529368da553e93d","capability_categories":["content_online_mob_attack"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"自残/自杀内容","policy_code":"builtin.content_safety.8b77e51268536ced","capability_categories":["content_self_harm_encouragement"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"药品滥用指导","policy_code":"builtin.content_safety.bb6ee23a359ce52e","capability_categories":["content_prescription_abuse"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"虐待动物内容","policy_code":"builtin.content_safety.4e2d6940ae0c8718","capability_categories":["content_animal_abuse"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"虚假信息/谣言","policy_code":"builtin.content_safety.948316474cf587e1","capability_categories":["content_harmful_rumor_creation"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"违禁品检测","policy_code":"builtin.content_safety.37e8337d76413856","capability_categories":["content_contraband_guidance"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"邪教宣传内容","policy_code":"builtin.content_safety.430e892402c08738","capability_categories":["content_cult_recruitment"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"食品安全违规","policy_code":"builtin.content_safety.9b130d27ba058baf","capability_categories":["content_food_safety_violation"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"骚扰/霸凌内容","policy_code":"builtin.content_safety.dc547e0b41610cca","capability_categories":["content_harassment_bullying"],"binding_mode":"any"}
]
$runtime_policy_bindings$::jsonb
) AS item(policy_code TEXT,rule_type TEXT,name TEXT,capability_categories JSONB,binding_mode TEXT);

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,b.binding_mode,0,'{}'::jsonb
FROM migration_162_bindings b
JOIN rules r ON r.policy_code=b.policy_code
CROSS JOIN LATERAL jsonb_array_elements_text(b.capability_categories) category(value)
JOIN security_capabilities c ON c.category=category.value
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

COMMIT;
