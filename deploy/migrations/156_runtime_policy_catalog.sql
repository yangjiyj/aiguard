-- Add an OpenSSH-specific capability so the SSH policy does not misclassify
-- RSA, DSA, or EC private keys as OpenSSH keys.

BEGIN;

/*
$runtime_policy_capabilities$
[
  {"category":"openssh_private_key","name":"OpenSSH 私钥","component":"security-engine.code-patterns","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"agent_openai_codex","name":"OpenAI Codex 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_aider","name":"Aider 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_amazon_q_developer","name":"Amazon Q Developer 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_gemini_code_assist","name":"Gemini Code Assist 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_tabnine","name":"Tabnine 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_sourcegraph_cody","name":"Sourcegraph Cody 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_replit_ai","name":"Replit AI 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_coderabbit","name":"CodeRabbit 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_autogpt_babyagi","name":"AutoGPT/BabyAGI 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_langchain_llamaindex","name":"LangChain/LlamaIndex 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_crewai_autogen","name":"CrewAI/AutoGen 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_dify_coze","name":"Dify/Coze 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false}
]
$runtime_policy_capabilities$
*/

INSERT INTO security_capabilities(
    id,category,name,capability_kind,component,selector_json,
    supported_stages,allowed_actions,mask_capable,enabled,metadata_json
) VALUES (
    'cap.static.openssh_private_key','openssh_private_key','OpenSSH 私钥','static',
    'security-engine.code-patterns','{"category":"openssh_private_key"}'::jsonb,
    '["input","output"]'::jsonb,'["audit","mask","block"]'::jsonb,
    TRUE,TRUE,'{"catalog":"runtime_policy","catalog_version":1}'::jsonb
)
ON CONFLICT (category) DO UPDATE SET
    name=EXCLUDED.name,
    capability_kind=EXCLUDED.capability_kind,
    component=EXCLUDED.component,
    selector_json=EXCLUDED.selector_json,
    supported_stages=EXCLUDED.supported_stages,
    allowed_actions=EXCLUDED.allowed_actions,
    mask_capable=EXCLUDED.mask_capable,
    metadata_json=EXCLUDED.metadata_json;

INSERT INTO security_capabilities(
    id,category,name,capability_kind,component,selector_json,
    supported_stages,allowed_actions,mask_capable,enabled,metadata_json
)
SELECT
    'cap.dynamic.' || item.category,item.category,item.name,'dynamic',
    'security-engine.agent-detect',jsonb_build_object('category',item.category),
    '["input"]'::jsonb,'["audit","block"]'::jsonb,
    FALSE,TRUE,'{"catalog":"runtime_policy","catalog_version":1}'::jsonb
FROM (VALUES
    ('agent_openai_codex','OpenAI Codex 客户端指纹'),
    ('agent_aider','Aider 客户端指纹'),
    ('agent_amazon_q_developer','Amazon Q Developer 客户端指纹'),
    ('agent_gemini_code_assist','Gemini Code Assist 客户端指纹'),
    ('agent_tabnine','Tabnine 客户端指纹'),
    ('agent_sourcegraph_cody','Sourcegraph Cody 客户端指纹'),
    ('agent_replit_ai','Replit AI 客户端指纹'),
    ('agent_coderabbit','CodeRabbit 客户端指纹'),
    ('agent_autogpt_babyagi','AutoGPT/BabyAGI 客户端指纹'),
    ('agent_langchain_llamaindex','LangChain/LlamaIndex 客户端指纹'),
    ('agent_crewai_autogen','CrewAI/AutoGen 客户端指纹'),
    ('agent_dify_coze','Dify/Coze 客户端指纹')
) AS item(category,name)
ON CONFLICT (category) DO UPDATE SET
    name=EXCLUDED.name,
    capability_kind=EXCLUDED.capability_kind,
    component=EXCLUDED.component,
    selector_json=EXCLUDED.selector_json,
    supported_stages=EXCLUDED.supported_stages,
    allowed_actions=EXCLUDED.allowed_actions,
    mask_capable=EXCLUDED.mask_capable,
    metadata_json=EXCLUDED.metadata_json;

/*
$runtime_policy_bindings$
[
  {"rule_type":"data_leak","name":"SSH 密钥检测","policy_code":"builtin.data_leak.db6cefda8798cab2","capability_categories":["openssh_private_key"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"OpenAI Codex CLI 检测","policy_code":"builtin.agent_detect.223c40ba05f83647","capability_categories":["agent_openai_codex"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"Aider 检测","policy_code":"builtin.agent_detect.008356aa358e9978","capability_categories":["agent_aider"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"Amazon Q Developer 检测","policy_code":"builtin.agent_detect.a5d24299196cf4f3","capability_categories":["agent_amazon_q_developer"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"Google Gemini Code Assist","policy_code":"builtin.agent_detect.f539af0c43cb3787","capability_categories":["agent_gemini_code_assist"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"Tabnine 检测","policy_code":"builtin.agent_detect.6cada6a14d0a4263","capability_categories":["agent_tabnine"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"Sourcegraph Cody 检测","policy_code":"builtin.agent_detect.79ae5816a3bf3ee5","capability_categories":["agent_sourcegraph_cody"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"Replit AI 检测","policy_code":"builtin.agent_detect.3aa45df74b2de7a8","capability_categories":["agent_replit_ai"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"CodeRabbit 检测","policy_code":"builtin.agent_detect.c1759598ed72a0d2","capability_categories":["agent_coderabbit"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"AutoGPT/BabyAGI 检测","policy_code":"builtin.agent_detect.c124e717941b210c","capability_categories":["agent_autogpt_babyagi"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"LangChain/LlamaIndex SDK","policy_code":"builtin.agent_detect.364d6d282e3fd912","capability_categories":["agent_langchain_llamaindex"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"CrewAI/AutoGen 检测","policy_code":"builtin.agent_detect.5a691bbd627d263a","capability_categories":["agent_crewai_autogen"],"binding_mode":"any"},
  {"rule_type":"agent_detect","name":"Dify/Coze 平台检测","policy_code":"builtin.agent_detect.6f490afdd7023369","capability_categories":["agent_dify_coze"],"binding_mode":"any"}
]
$runtime_policy_bindings$
*/

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,'any',0,'{}'::jsonb
FROM rules r
JOIN security_capabilities c ON c.category='openssh_private_key'
WHERE r.policy_code='builtin.data_leak.db6cefda8798cab2'
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,'any',0,'{}'::jsonb
FROM (VALUES
    ('builtin.agent_detect.223c40ba05f83647','agent_openai_codex'),
    ('builtin.agent_detect.008356aa358e9978','agent_aider'),
    ('builtin.agent_detect.a5d24299196cf4f3','agent_amazon_q_developer'),
    ('builtin.agent_detect.f539af0c43cb3787','agent_gemini_code_assist'),
    ('builtin.agent_detect.6cada6a14d0a4263','agent_tabnine'),
    ('builtin.agent_detect.79ae5816a3bf3ee5','agent_sourcegraph_cody'),
    ('builtin.agent_detect.3aa45df74b2de7a8','agent_replit_ai'),
    ('builtin.agent_detect.c1759598ed72a0d2','agent_coderabbit'),
    ('builtin.agent_detect.c124e717941b210c','agent_autogpt_babyagi'),
    ('builtin.agent_detect.364d6d282e3fd912','agent_langchain_llamaindex'),
    ('builtin.agent_detect.5a691bbd627d263a','agent_crewai_autogen'),
    ('builtin.agent_detect.6f490afdd7023369','agent_dify_coze')
) AS binding(policy_code,category)
JOIN rules r ON r.policy_code=binding.policy_code
JOIN security_capabilities c ON c.category=binding.category
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

COMMIT;
