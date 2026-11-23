-- Register deterministic RAG and model-supply-chain policies.

BEGIN;

CREATE TEMP TABLE migration_163_capabilities ON COMMIT DROP AS
SELECT category,name,component,supported_stages,builtin_actions,mask_capable
FROM jsonb_to_recordset(
$runtime_policy_capabilities$
[
  {"category":"rag_sensitive_data_exfiltration","name":"RAG 数据泄露","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"rag_cache_poisoning","name":"RAG 缓存投毒","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"rag_embedding_manipulation","name":"向量嵌入操纵","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"rag_external_knowledge_poisoning","name":"外部知识投毒","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"rag_document_source_spoofing","name":"文档源欺骗","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"rag_context_hijacking","name":"检索上下文劫持","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"rag_result_tampering","name":"检索结果篡改","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"rag_unauthorized_knowledge_query","name":"知识库越权查询","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"rag_fake_citation","name":"虚假文档引用","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"supply_compliance_label_bypass","name":"合规标签绕过","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"supply_shadow_model_use","name":"影子模型使用","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"supply_malicious_model_load","name":"恶意模型加载","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"supply_unauthorized_model_call","name":"未授权模型调用","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"supply_model_weight_theft","name":"模型权重窃取","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"supply_model_version_vulnerability_probe","name":"模型版本漏洞探测","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"supply_model_behavior_probe","name":"模型行为探测","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"supply_dependency_vulnerability","name":"第三方依赖漏洞利用","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false}
]
$runtime_policy_capabilities$::jsonb
) AS item(category TEXT,name TEXT,component TEXT,supported_stages JSONB,builtin_actions JSONB,mask_capable BOOLEAN);

INSERT INTO security_capabilities(id,category,name,capability_kind,component,selector_json,supported_stages,allowed_actions,mask_capable,enabled,metadata_json)
SELECT 'cap.static.'||category,category,name,'static',component,jsonb_build_object('category',category),supported_stages,builtin_actions,mask_capable,TRUE,'{"catalog":"rag_supply_policy","catalog_version":1}'::jsonb
FROM migration_163_capabilities
ON CONFLICT (category) DO UPDATE SET name=EXCLUDED.name,capability_kind=EXCLUDED.capability_kind,component=EXCLUDED.component,selector_json=EXCLUDED.selector_json,supported_stages=EXCLUDED.supported_stages,allowed_actions=EXCLUDED.allowed_actions,mask_capable=EXCLUDED.mask_capable,metadata_json=EXCLUDED.metadata_json;

CREATE TEMP TABLE migration_163_bindings ON COMMIT DROP AS
SELECT policy_code,rule_type,name,capability_categories,binding_mode
FROM jsonb_to_recordset(
$runtime_policy_bindings$
[
  {"rule_type":"rag_security","name":"RAG 数据泄露","policy_code":"builtin.rag_security.467a622e0be8d906","capability_categories":["rag_sensitive_data_exfiltration"],"binding_mode":"any"},
  {"rule_type":"rag_security","name":"RAG 缓存投毒","policy_code":"builtin.rag_security.74a9f1e667ced7cf","capability_categories":["rag_cache_poisoning"],"binding_mode":"any"},
  {"rule_type":"rag_security","name":"向量嵌入操纵","policy_code":"builtin.rag_security.13154dbf8dc32f3f","capability_categories":["rag_embedding_manipulation"],"binding_mode":"any"},
  {"rule_type":"rag_security","name":"外部知识投毒","policy_code":"builtin.rag_security.af8adaef83896e2d","capability_categories":["rag_external_knowledge_poisoning"],"binding_mode":"any"},
  {"rule_type":"rag_security","name":"文档源欺骗","policy_code":"builtin.rag_security.659584df2cd2be3d","capability_categories":["rag_document_source_spoofing"],"binding_mode":"any"},
  {"rule_type":"rag_security","name":"检索上下文劫持","policy_code":"builtin.rag_security.d42179890c2b8967","capability_categories":["rag_context_hijacking"],"binding_mode":"any"},
  {"rule_type":"rag_security","name":"检索结果篡改","policy_code":"builtin.rag_security.08b9b614ab365989","capability_categories":["rag_result_tampering"],"binding_mode":"any"},
  {"rule_type":"rag_security","name":"知识库越权查询","policy_code":"builtin.rag_security.0c2992f0a6665641","capability_categories":["rag_unauthorized_knowledge_query"],"binding_mode":"any"},
  {"rule_type":"rag_security","name":"虚假文档引用","policy_code":"builtin.rag_security.1723128d6f171f69","capability_categories":["rag_fake_citation"],"binding_mode":"any"},
  {"rule_type":"supply_chain","name":"合规标签绕过","policy_code":"builtin.supply_chain.91151fe7a133df12","capability_categories":["supply_compliance_label_bypass"],"binding_mode":"any"},
  {"rule_type":"supply_chain","name":"影子模型使用","policy_code":"builtin.supply_chain.9e3f687b97ec8ae3","capability_categories":["supply_shadow_model_use"],"binding_mode":"any"},
  {"rule_type":"supply_chain","name":"恶意模型加载","policy_code":"builtin.supply_chain.26bc51020d532aaf","capability_categories":["supply_malicious_model_load"],"binding_mode":"any"},
  {"rule_type":"supply_chain","name":"未授权模型调用","policy_code":"builtin.supply_chain.98c244cb0345cb0d","capability_categories":["supply_unauthorized_model_call"],"binding_mode":"any"},
  {"rule_type":"supply_chain","name":"模型权重窃取","policy_code":"builtin.supply_chain.dd2a34c2c0d63125","capability_categories":["supply_model_weight_theft"],"binding_mode":"any"},
  {"rule_type":"supply_chain","name":"模型版本漏洞探测","policy_code":"builtin.supply_chain.e88a49da94a0a712","capability_categories":["supply_model_version_vulnerability_probe"],"binding_mode":"any"},
  {"rule_type":"supply_chain","name":"模型行为探测","policy_code":"builtin.supply_chain.cc3faf3e41ecaaa8","capability_categories":["supply_model_behavior_probe"],"binding_mode":"any"},
  {"rule_type":"supply_chain","name":"第三方依赖漏洞","policy_code":"builtin.supply_chain.575265dc58c794c7","capability_categories":["supply_dependency_vulnerability"],"binding_mode":"any"}
]
$runtime_policy_bindings$::jsonb
) AS item(policy_code TEXT,rule_type TEXT,name TEXT,capability_categories JSONB,binding_mode TEXT);

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,b.binding_mode,0,'{}'::jsonb
FROM migration_163_bindings b
JOIN rules r ON r.policy_code=b.policy_code
CROSS JOIN LATERAL jsonb_array_elements_text(b.capability_categories) category(value)
JOIN security_capabilities c ON c.category=category.value
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

COMMIT;
