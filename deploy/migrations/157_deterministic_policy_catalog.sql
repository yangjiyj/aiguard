-- Register high-confidence prompt-leak and resource-exhaustion detectors.

BEGIN;

CREATE TEMP TABLE migration_157_capabilities ON COMMIT DROP AS
SELECT category,name,component,supported_stages,builtin_actions,mask_capable
FROM jsonb_to_recordset(
$runtime_policy_capabilities$
[
  {"category":"prompt_probe_api_parameters","name":"API 参数探测","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_base64","name":"Base64 提示提取","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_meta_instructions","name":"元指令泄露","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_internal_rules","name":"内部指令查询","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_delimiter_probe","name":"系统分隔符探测","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_initial_instructions","name":"初始指令泄露","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_multilingual","name":"多语言提示提取","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_reverse_induction","name":"提示词反转提取","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_reconstruction","name":"提示词重构提取","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_formatted_export","name":"格式化提示导出","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_progressive","name":"渐进式提示提取","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_probe_system_configuration","name":"系统配置探测","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_encoded_export","name":"编码方式提示提取","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"prompt_leak_role_reversal","name":"角色反转提示提取","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"dos_exponential_expansion","name":"指数膨胀请求","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"dos_infinite_loop_instruction","name":"无限循环指令","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"dos_regex_backtracking","name":"正则灾难性回溯","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"dos_deep_nesting","name":"深层嵌套展开","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"dos_resource_exhaustion_instruction","name":"资源耗尽指令","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"dos_long_context_generation","name":"超长上下文生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"dos_unbounded_recursion","name":"无界递归函数","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"dos_recursive_expansion","name":"递归展开攻击","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false}
]
$runtime_policy_capabilities$::jsonb
) AS item(
    category TEXT,name TEXT,component TEXT,supported_stages JSONB,
    builtin_actions JSONB,mask_capable BOOLEAN
);

INSERT INTO security_capabilities(
    id,category,name,capability_kind,component,selector_json,
    supported_stages,allowed_actions,mask_capable,enabled,metadata_json
)
SELECT
    'cap.static.' || category,category,name,'static',component,
    jsonb_build_object('category',category),supported_stages,builtin_actions,
    mask_capable,TRUE,'{"catalog":"deterministic_policy","catalog_version":1}'::jsonb
FROM migration_157_capabilities
ON CONFLICT (category) DO UPDATE SET
    name=EXCLUDED.name,
    capability_kind=EXCLUDED.capability_kind,
    component=EXCLUDED.component,
    selector_json=EXCLUDED.selector_json,
    supported_stages=EXCLUDED.supported_stages,
    allowed_actions=EXCLUDED.allowed_actions,
    mask_capable=EXCLUDED.mask_capable,
    metadata_json=EXCLUDED.metadata_json;

CREATE TEMP TABLE migration_157_bindings ON COMMIT DROP AS
SELECT policy_code,rule_type,name,capability_categories,binding_mode
FROM jsonb_to_recordset(
$runtime_policy_bindings$
[
  {"rule_type":"prompt_leak","name":"API 参数探测","policy_code":"builtin.prompt_leak.c584e35e5a105858","capability_categories":["prompt_probe_api_parameters"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"Base64 提示提取","policy_code":"builtin.prompt_leak.4e51f1e57aa519c0","capability_categories":["prompt_leak_base64"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"元指令泄露检测","policy_code":"builtin.prompt_leak.4b4745b0d80aa02a","capability_categories":["prompt_leak_meta_instructions"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"内部指令查询","policy_code":"builtin.prompt_leak.2dd388f0575b616c","capability_categories":["prompt_leak_internal_rules"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"分隔符探测攻击","policy_code":"builtin.prompt_leak.ebfe1cb42be3b070","capability_categories":["prompt_leak_delimiter_probe"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"初始指令泄露检测","policy_code":"builtin.prompt_leak.67489bdeaea0573a","capability_categories":["prompt_leak_initial_instructions"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"多语言提示提取","policy_code":"builtin.prompt_leak.0fae073315d29973","capability_categories":["prompt_leak_multilingual"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"提示词反转攻击","policy_code":"builtin.prompt_leak.4fb9d9df2042df28","capability_categories":["prompt_leak_reverse_induction"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"提示词重构攻击","policy_code":"builtin.prompt_leak.0dae0c3ea88dad80","capability_categories":["prompt_leak_reconstruction"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"格式化导出要求","policy_code":"builtin.prompt_leak.81c61518cc032dbd","capability_categories":["prompt_leak_formatted_export"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"渐进式提示提取","policy_code":"builtin.prompt_leak.801e45f28d7a1758","capability_categories":["prompt_leak_progressive"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"系统配置探测","policy_code":"builtin.prompt_leak.7e8a7b334134633b","capability_categories":["prompt_probe_system_configuration"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"编码方式提取","policy_code":"builtin.prompt_leak.aa2cf7f9df399747","capability_categories":["prompt_leak_encoded_export"],"binding_mode":"any"},
  {"rule_type":"prompt_leak","name":"角色反转提取","policy_code":"builtin.prompt_leak.adaf812b35c328aa","capability_categories":["prompt_leak_role_reversal"],"binding_mode":"any"},
  {"rule_type":"dos_protection","name":"指数膨胀请求","policy_code":"builtin.dos_protection.4f43236bc20250dc","capability_categories":["dos_exponential_expansion"],"binding_mode":"any"},
  {"rule_type":"dos_protection","name":"无限循环指令","policy_code":"builtin.dos_protection.762fbe86a6615238","capability_categories":["dos_infinite_loop_instruction"],"binding_mode":"any"},
  {"rule_type":"dos_protection","name":"正则回溯攻击","policy_code":"builtin.dos_protection.c49a1dd5605cb6d1","capability_categories":["dos_regex_backtracking"],"binding_mode":"any"},
  {"rule_type":"dos_protection","name":"深层嵌套展开","policy_code":"builtin.dos_protection.5f096e00aa599617","capability_categories":["dos_deep_nesting"],"binding_mode":"any"},
  {"rule_type":"dos_protection","name":"资源耗尽指令","policy_code":"builtin.dos_protection.4290e5f12c4f81a4","capability_categories":["dos_resource_exhaustion_instruction"],"binding_mode":"any"},
  {"rule_type":"dos_protection","name":"超长上下文消耗","policy_code":"builtin.dos_protection.26b5a56593b2a884","capability_categories":["dos_long_context_generation"],"binding_mode":"any"},
  {"rule_type":"dos_protection","name":"递归函数调用","policy_code":"builtin.dos_protection.6e61ea7c8d2d9a07","capability_categories":["dos_unbounded_recursion"],"binding_mode":"any"},
  {"rule_type":"dos_protection","name":"递归展开攻击","policy_code":"builtin.dos_protection.6f6907dfdbc2ee17","capability_categories":["dos_recursive_expansion"],"binding_mode":"any"}
]
$runtime_policy_bindings$::jsonb
) AS item(
    policy_code TEXT,rule_type TEXT,name TEXT,
    capability_categories JSONB,binding_mode TEXT
);

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,b.binding_mode,0,'{}'::jsonb
FROM migration_157_bindings b
JOIN rules r ON r.policy_code=b.policy_code
CROSS JOIN LATERAL jsonb_array_elements_text(b.capability_categories) category(value)
JOIN security_capabilities c ON c.category=category.value
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

COMMIT;
