-- Register request-context and remaining high-confidence input policies.

BEGIN;

CREATE TEMP TABLE migration_165_capabilities ON COMMIT DROP AS
SELECT category,name,component,supported_stages,builtin_actions,mask_capable
FROM jsonb_to_recordset(
$runtime_policy_capabilities$
[
  {"category":"agent_direct_api_call","name":"直接 API 调用","component":"security-engine.policy-context","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_long_session","name":"超长 Session","component":"security-engine.policy-context","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_formatted_response_extraction","name":"格式化响应提取","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_image_steganography","name":"GIF/图像隐写注入","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_multimodal_hidden_instruction","name":"多模态隐藏指令注入","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_leader_defamation","name":"领导人负面造谣","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"content_ethnic_religious_conflict","name":"民族宗教矛盾煽动","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false}
]
$runtime_policy_capabilities$::jsonb
) AS item(category TEXT,name TEXT,component TEXT,supported_stages JSONB,builtin_actions JSONB,mask_capable BOOLEAN);

INSERT INTO security_capabilities(id,category,name,capability_kind,component,selector_json,supported_stages,allowed_actions,mask_capable,enabled,metadata_json)
SELECT 'cap.'||CASE WHEN component='security-engine.policy-context' THEN 'dynamic.' ELSE 'static.' END||category,
       category,name,CASE WHEN component='security-engine.policy-context' THEN 'dynamic' ELSE 'static' END,
       component,jsonb_build_object('category',category),supported_stages,builtin_actions,mask_capable,TRUE,
       '{"catalog":"request_context_policy","catalog_version":1}'::jsonb
FROM migration_165_capabilities
ON CONFLICT (category) DO UPDATE SET name=EXCLUDED.name,capability_kind=EXCLUDED.capability_kind,component=EXCLUDED.component,selector_json=EXCLUDED.selector_json,supported_stages=EXCLUDED.supported_stages,allowed_actions=EXCLUDED.allowed_actions,mask_capable=EXCLUDED.mask_capable,metadata_json=EXCLUDED.metadata_json;

CREATE TEMP TABLE migration_165_bindings ON COMMIT DROP AS
SELECT policy_code,rule_type,name,capability_categories,binding_mode
FROM jsonb_to_recordset(
$runtime_policy_bindings$
[
  {"rule_type":"agent_detect","name":"API 直接调用检测","policy_code":"builtin.agent_detect.e2d7dcc63727dab9","capability_categories":["agent_direct_api_call"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"Session 超长检测","policy_code":"builtin.agent_detect.3b83737794508b03","capability_categories":["agent_long_session"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"格式化响应提取","policy_code":"builtin.agent_detect.b9cbfe2be43132d0","capability_categories":["agent_formatted_response_extraction"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"GIF/图像隐写注入","policy_code":"builtin.prompt_injection.839171ac2965425a","capability_categories":["injection_image_steganography"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"多模态输入注入","policy_code":"builtin.prompt_injection.15004e1e3fd53f86","capability_categories":["injection_multimodal_hidden_instruction"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"领导人负面讨论","policy_code":"builtin.content_safety.f1252b5fafaca83a","capability_categories":["content_leader_defamation"],"binding_mode":"any"},
  {"rule_type":"content_safety","name":"民族宗教问题","policy_code":"builtin.content_safety.b0fa6eb641e7f1c5","capability_categories":["content_ethnic_religious_conflict"],"binding_mode":"any"}
]
$runtime_policy_bindings$::jsonb
) AS item(policy_code TEXT,rule_type TEXT,name TEXT,capability_categories JSONB,binding_mode TEXT);

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,b.binding_mode,0,'{}'::jsonb
FROM migration_165_bindings b
JOIN rules r ON r.policy_code=b.policy_code
CROSS JOIN LATERAL jsonb_array_elements_text(b.capability_categories) category(value)
JOIN security_capabilities c ON c.category=category.value
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

COMMIT;
