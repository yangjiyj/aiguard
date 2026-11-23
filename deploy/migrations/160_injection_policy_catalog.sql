-- Register deterministic encoded and structured prompt-injection policies.

BEGIN;

CREATE TEMP TABLE migration_160_capabilities ON COMMIT DROP AS
SELECT category,name,component,supported_stages,builtin_actions,mask_capable
FROM jsonb_to_recordset(
$runtime_policy_capabilities$
[
  {"category":"injection_ascii_art","name":"ASCII 艺术注入","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_base32_base16","name":"Base32/Base16 编码注入","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_emoji_encoding","name":"Emoji 编码注入","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_structured_json_xml","name":"JSON/XML 结构注入","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_markdown_rendering","name":"Markdown 渲染注入","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_payload_splitting","name":"Payload 拆分注入","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_rot13_atbash","name":"ROT13/Atbash 编码绕过","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_token_smuggling","name":"Token 走私攻击","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_url_encoding","name":"URL 编码绕过","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_context_truncation","name":"上下文截断攻击","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_binary_octal","name":"二进制/八进制编码注入","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_pseudocode","name":"伪代码注入","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_delimiter_confusion","name":"分隔符混淆攻击","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_double_encoding","name":"双重编码检测","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_homoglyph","name":"同形字符替换","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_adversarial_suffix","name":"对抗性后缀攻击","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"injection_morse_custom_encoding","name":"自定义编码/莫尔斯电码","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false}
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
    mask_capable,TRUE,'{"catalog":"injection_policy","catalog_version":1}'::jsonb
FROM migration_160_capabilities
ON CONFLICT (category) DO UPDATE SET
    name=EXCLUDED.name,
    capability_kind=EXCLUDED.capability_kind,
    component=EXCLUDED.component,
    selector_json=EXCLUDED.selector_json,
    supported_stages=EXCLUDED.supported_stages,
    allowed_actions=EXCLUDED.allowed_actions,
    mask_capable=EXCLUDED.mask_capable,
    metadata_json=EXCLUDED.metadata_json;

CREATE TEMP TABLE migration_160_bindings ON COMMIT DROP AS
SELECT policy_code,rule_type,name,capability_categories,binding_mode
FROM jsonb_to_recordset(
$runtime_policy_bindings$
[
  {"rule_type":"prompt_injection","name":"ASCII 艺术注入","policy_code":"builtin.prompt_injection.c2cc41c645d6e802","capability_categories":["injection_ascii_art"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"Base32/Base16 编码注入","policy_code":"builtin.prompt_injection.9f67a6da54bce276","capability_categories":["injection_base32_base16"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"Emoji 编码注入","policy_code":"builtin.prompt_injection.467da79f0b886cd8","capability_categories":["injection_emoji_encoding"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"JSON/XML 结构注入","policy_code":"builtin.prompt_injection.7264c727a4fc2ed4","capability_categories":["injection_structured_json_xml"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"Markdown 渲染注入","policy_code":"builtin.prompt_injection.75f29627a37e0d01","capability_categories":["injection_markdown_rendering"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"Payload 拆分注入","policy_code":"builtin.prompt_injection.4326456f74d43796","capability_categories":["injection_payload_splitting"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"ROT13/Atbash 编码绕过","policy_code":"builtin.prompt_injection.4b465e70a6377330","capability_categories":["injection_rot13_atbash"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"Token 走私攻击","policy_code":"builtin.prompt_injection.f28adec4733f37d1","capability_categories":["injection_token_smuggling"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"URL 编码绕过","policy_code":"builtin.prompt_injection.57767f0750a92dfa","capability_categories":["injection_url_encoding"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"上下文截断攻击","policy_code":"builtin.prompt_injection.ba9a8699a54af996","capability_categories":["injection_context_truncation"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"二进制/八进制编码注入","policy_code":"builtin.prompt_injection.5ab93c096487f735","capability_categories":["injection_binary_octal"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"伪代码注入","policy_code":"builtin.prompt_injection.90eebdc9900c34be","capability_categories":["injection_pseudocode"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"分隔符混淆攻击","policy_code":"builtin.prompt_injection.d2484f0152f1f577","capability_categories":["injection_delimiter_confusion"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"双重编码检测","policy_code":"builtin.prompt_injection.4fb2be0130d3f3f1","capability_categories":["injection_double_encoding"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"同形字符替换","policy_code":"builtin.prompt_injection.3c2c8a296f39670e","capability_categories":["injection_homoglyph"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"对抗性后缀攻击","policy_code":"builtin.prompt_injection.73644306e4dfbcf4","capability_categories":["injection_adversarial_suffix"],"binding_mode":"any"},
  {"rule_type":"prompt_injection","name":"自定义编码/莫尔斯电码","policy_code":"builtin.prompt_injection.b167772e4c27e54b","capability_categories":["injection_morse_custom_encoding"],"binding_mode":"any"}
]
$runtime_policy_bindings$::jsonb
) AS item(
    policy_code TEXT,rule_type TEXT,name TEXT,
    capability_categories JSONB,binding_mode TEXT
);

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,b.binding_mode,0,'{}'::jsonb
FROM migration_160_bindings b
JOIN rules r ON r.policy_code=b.policy_code
CROSS JOIN LATERAL jsonb_array_elements_text(b.capability_categories) category(value)
JOIN security_capabilities c ON c.category=category.value
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

COMMIT;
