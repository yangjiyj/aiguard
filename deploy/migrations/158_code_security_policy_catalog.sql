-- Register deterministic code-generation security policies.

BEGIN;

CREATE TEMP TABLE migration_158_capabilities ON COMMIT DROP AS
SELECT category,name,component,supported_stages,builtin_actions,mask_capable
FROM jsonb_to_recordset(
$runtime_policy_capabilities$
[
  {"category":"code_sql_injection_generation","name":"SQL 注入代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_ldap_injection_generation","name":"LDAP 注入代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_nosql_injection_generation","name":"NoSQL 注入代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_ssrf_generation","name":"SSRF 代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_xxe_generation","name":"XXE 代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_xss_generation","name":"XSS 代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_unsafe_file_handling","name":"不安全文件处理代码","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_insecure_random","name":"不安全随机数代码","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_memory_overflow_generation","name":"内存溢出代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_insecure_deserialization","name":"不安全反序列化代码","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_command_injection_generation","name":"命令注入代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_weak_crypto_generation","name":"弱加密代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_log_injection_generation","name":"日志注入代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_auth_bypass_generation","name":"权限绕过代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_template_injection_generation","name":"模板注入代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_hardcoded_credential_generation","name":"硬编码凭据示例生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"code_path_traversal_generation","name":"路径遍历代码生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false}
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
    mask_capable,TRUE,'{"catalog":"code_security_policy","catalog_version":1}'::jsonb
FROM migration_158_capabilities
ON CONFLICT (category) DO UPDATE SET
    name=EXCLUDED.name,
    capability_kind=EXCLUDED.capability_kind,
    component=EXCLUDED.component,
    selector_json=EXCLUDED.selector_json,
    supported_stages=EXCLUDED.supported_stages,
    allowed_actions=EXCLUDED.allowed_actions,
    mask_capable=EXCLUDED.mask_capable,
    metadata_json=EXCLUDED.metadata_json;

CREATE TEMP TABLE migration_158_bindings ON COMMIT DROP AS
SELECT policy_code,rule_type,name,capability_categories,binding_mode
FROM jsonb_to_recordset(
$runtime_policy_bindings$
[
  {"rule_type":"code_security","name":"SQL 注入代码生成","policy_code":"builtin.code_security.d82567ae4c6cba2a","capability_categories":["code_sql_injection_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"LDAP 注入代码","policy_code":"builtin.code_security.c0bf948ca3c9ebe2","capability_categories":["code_ldap_injection_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"NoSQL 注入代码","policy_code":"builtin.code_security.2da958a010ca4303","capability_categories":["code_nosql_injection_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"SSRF 代码生成","policy_code":"builtin.code_security.eea7475d95f58dd5","capability_categories":["code_ssrf_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"XML 外部实体注入","policy_code":"builtin.code_security.d6121b4e9c6b3639","capability_categories":["code_xxe_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"XSS 代码生成","policy_code":"builtin.code_security.46a74885f15123bb","capability_categories":["code_xss_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"不安全的文件处理","policy_code":"builtin.code_security.0234e3099d41f98b","capability_categories":["code_unsafe_file_handling"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"不安全的随机数","policy_code":"builtin.code_security.3e1454b49ab95b46","capability_categories":["code_insecure_random"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"内存溢出代码","policy_code":"builtin.code_security.d4bd0d8e0c6c9857","capability_categories":["code_memory_overflow_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"反序列化漏洞代码","policy_code":"builtin.code_security.83c72801873c89c6","capability_categories":["code_insecure_deserialization"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"命令注入代码生成","policy_code":"builtin.code_security.2e8190e3871e45d6","capability_categories":["code_command_injection_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"弱加密代码生成","policy_code":"builtin.code_security.829c9fe3cbc3a792","capability_categories":["code_weak_crypto_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"日志注入代码","policy_code":"builtin.code_security.be648ff0048d7877","capability_categories":["code_log_injection_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"权限绕过代码","policy_code":"builtin.code_security.4f2a28590d7747f6","capability_categories":["code_auth_bypass_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"模板注入代码","policy_code":"builtin.code_security.3f67649cc24121a3","capability_categories":["code_template_injection_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"硬编码凭据示例","policy_code":"builtin.code_security.9640acf0d1083905","capability_categories":["code_hardcoded_credential_generation"],"binding_mode":"any"},
  {"rule_type":"code_security","name":"路径遍历代码生成","policy_code":"builtin.code_security.389ee9cb3cb7c789","capability_categories":["code_path_traversal_generation"],"binding_mode":"any"}
]
$runtime_policy_bindings$::jsonb
) AS item(
    policy_code TEXT,rule_type TEXT,name TEXT,
    capability_categories JSONB,binding_mode TEXT
);

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,b.binding_mode,0,'{}'::jsonb
FROM migration_158_bindings b
JOIN rules r ON r.policy_code=b.policy_code
CROSS JOIN LATERAL jsonb_array_elements_text(b.capability_categories) category(value)
JOIN security_capabilities c ON c.category=category.value
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

COMMIT;
