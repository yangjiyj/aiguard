-- Register deterministic copyright and plugin/tool security policies.

BEGIN;

CREATE TEMP TABLE migration_161_capabilities ON COMMIT DROP AS
SELECT category,name,component,supported_stages,builtin_actions,mask_capable
FROM jsonb_to_recordset(
$runtime_policy_capabilities$
[
  {"category":"copyright_patent_copy","name":"专利内容复制","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"copyright_image_reproduction","name":"侵权图像描述","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"copyright_character_reproduction","name":"受保护角色再现","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"copyright_text_reproduction","name":"受版权文本生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"copyright_trade_secret_extraction","name":"商业机密提取","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"copyright_academic_plagiarism","name":"学术论文盗用","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"copyright_license_bypass","name":"开源许可绕过","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"copyright_lyrics_bulk_export","name":"歌词批量导出","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"copyright_pirated_content_extraction","name":"盗版内容提取","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"plugin_mcp_permission_bypass","name":"MCP 权限绕过","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"plugin_tool_denial","name":"工具拒绝执行","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"plugin_log_tampering","name":"工具日志篡改","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"plugin_data_theft","name":"工具窃取数据","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"plugin_malicious_install","name":"恶意插件安装","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"plugin_data_leak","name":"插件数据泄露","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"plugin_privilege_escalation","name":"插件权限提升","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"plugin_chain_attack","name":"插件链式攻击","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"plugin_filesystem_overreach","name":"文件系统越权","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"plugin_unauthorized_tool_call","name":"未授权工具调用","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"plugin_network_request_forgery","name":"网络请求伪造","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false}
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
    mask_capable,TRUE,'{"catalog":"copyright_plugin_policy","catalog_version":1}'::jsonb
FROM migration_161_capabilities
ON CONFLICT (category) DO UPDATE SET
    name=EXCLUDED.name,
    capability_kind=EXCLUDED.capability_kind,
    component=EXCLUDED.component,
    selector_json=EXCLUDED.selector_json,
    supported_stages=EXCLUDED.supported_stages,
    allowed_actions=EXCLUDED.allowed_actions,
    mask_capable=EXCLUDED.mask_capable,
    metadata_json=EXCLUDED.metadata_json;

CREATE TEMP TABLE migration_161_bindings ON COMMIT DROP AS
SELECT policy_code,rule_type,name,capability_categories,binding_mode
FROM jsonb_to_recordset(
$runtime_policy_bindings$
[
  {"rule_type":"copyright_protect","name":"专利内容复制","policy_code":"builtin.copyright_protect.9c0b04a17d008a0c","capability_categories":["copyright_patent_copy"],"binding_mode":"any"},
  {"rule_type":"copyright_protect","name":"侵权图像描述","policy_code":"builtin.copyright_protect.7123a899c2158bdb","capability_categories":["copyright_image_reproduction"],"binding_mode":"any"},
  {"rule_type":"copyright_protect","name":"受保护角色再现","policy_code":"builtin.copyright_protect.36cd5135e9429132","capability_categories":["copyright_character_reproduction"],"binding_mode":"any"},
  {"rule_type":"copyright_protect","name":"受版权文本生成","policy_code":"builtin.copyright_protect.8459d0184254fe69","capability_categories":["copyright_text_reproduction"],"binding_mode":"any"},
  {"rule_type":"copyright_protect","name":"商业机密提取","policy_code":"builtin.copyright_protect.1107170cb2c8407a","capability_categories":["copyright_trade_secret_extraction"],"binding_mode":"any"},
  {"rule_type":"copyright_protect","name":"学术论文盗用","policy_code":"builtin.copyright_protect.d971cfcccc10c312","capability_categories":["copyright_academic_plagiarism"],"binding_mode":"any"},
  {"rule_type":"copyright_protect","name":"开源许可绕过","policy_code":"builtin.copyright_protect.e3ded2f4e7620f42","capability_categories":["copyright_license_bypass"],"binding_mode":"any"},
  {"rule_type":"copyright_protect","name":"歌词批量导出","policy_code":"builtin.copyright_protect.a77b346995352c2b","capability_categories":["copyright_lyrics_bulk_export"],"binding_mode":"any"},
  {"rule_type":"copyright_protect","name":"盗版内容提取","policy_code":"builtin.copyright_protect.5bc4433e74d45c13","capability_categories":["copyright_pirated_content_extraction"],"binding_mode":"any"},
  {"rule_type":"plugin_security","name":"MCP 权限绕过","policy_code":"builtin.plugin_security.450758fa39c93507","capability_categories":["plugin_mcp_permission_bypass"],"binding_mode":"any"},
  {"rule_type":"plugin_security","name":"工具拒绝执行","policy_code":"builtin.plugin_security.1024164507834300","capability_categories":["plugin_tool_denial"],"binding_mode":"any"},
  {"rule_type":"plugin_security","name":"工具日志篡改","policy_code":"builtin.plugin_security.b5f7907c68e5bf34","capability_categories":["plugin_log_tampering"],"binding_mode":"any"},
  {"rule_type":"plugin_security","name":"工具窃取数据","policy_code":"builtin.plugin_security.1aa5c9889e5f4e27","capability_categories":["plugin_data_theft"],"binding_mode":"any"},
  {"rule_type":"plugin_security","name":"恶意插件安装","policy_code":"builtin.plugin_security.7f715200f0fa437d","capability_categories":["plugin_malicious_install"],"binding_mode":"any"},
  {"rule_type":"plugin_security","name":"插件数据泄露","policy_code":"builtin.plugin_security.0e486a2f5576a9b0","capability_categories":["plugin_data_leak"],"binding_mode":"any"},
  {"rule_type":"plugin_security","name":"插件权限提升","policy_code":"builtin.plugin_security.ba997217f9b54e40","capability_categories":["plugin_privilege_escalation"],"binding_mode":"any"},
  {"rule_type":"plugin_security","name":"插件链式攻击","policy_code":"builtin.plugin_security.fb49d223f677b0ac","capability_categories":["plugin_chain_attack"],"binding_mode":"any"},
  {"rule_type":"plugin_security","name":"文件系统越权","policy_code":"builtin.plugin_security.e9d082e3a9566521","capability_categories":["plugin_filesystem_overreach"],"binding_mode":"any"},
  {"rule_type":"plugin_security","name":"未授权工具调用","policy_code":"builtin.plugin_security.5c66059903fe2cab","capability_categories":["plugin_unauthorized_tool_call"],"binding_mode":"any"},
  {"rule_type":"plugin_security","name":"网络请求伪造","policy_code":"builtin.plugin_security.2932cca214e98d4e","capability_categories":["plugin_network_request_forgery"],"binding_mode":"any"}
]
$runtime_policy_bindings$::jsonb
) AS item(
    policy_code TEXT,rule_type TEXT,name TEXT,
    capability_categories JSONB,binding_mode TEXT
);

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,b.binding_mode,0,'{}'::jsonb
FROM migration_161_bindings b
JOIN rules r ON r.policy_code=b.policy_code
CROSS JOIN LATERAL jsonb_array_elements_text(b.capability_categories) category(value)
JOIN security_capabilities c ON c.category=category.value
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

COMMIT;
