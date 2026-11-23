-- Policy assets remain in rules. Detector categories are registered only as
-- underlying capabilities and never inserted as additional policy rows.

ALTER TABLE rules ADD COLUMN IF NOT EXISTS policy_code VARCHAR(128);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'ck_rules_policy_code_format'
          AND conrelid = 'rules'::regclass
    ) THEN
        ALTER TABLE rules ADD CONSTRAINT ck_rules_policy_code_format
            CHECK (policy_code IS NULL OR policy_code ~ '^[a-z0-9][a-z0-9._:-]{2,127}$');
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS security_capabilities (
    id VARCHAR(160) PRIMARY KEY,
    category VARCHAR(128) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    capability_kind VARCHAR(32) NOT NULL CHECK (capability_kind IN ('static', 'dynamic')),
    component VARCHAR(128) NOT NULL,
    selector_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    supported_stages JSONB NOT NULL,
    allowed_actions JSONB NOT NULL,
    mask_capable BOOLEAN NOT NULL DEFAULT FALSE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT ck_security_capability_id_nonblank CHECK (btrim(id) <> ''),
    CONSTRAINT ck_security_capability_category_nonblank CHECK (btrim(category) <> ''),
    CONSTRAINT ck_security_capability_name_nonblank CHECK (btrim(name) <> ''),
    CONSTRAINT ck_security_capability_component_nonblank CHECK (btrim(component) <> ''),
    CONSTRAINT ck_security_capability_selector_object CHECK (jsonb_typeof(selector_json) = 'object'),
    CONSTRAINT ck_security_capability_stages_array CHECK (
        jsonb_typeof(supported_stages) = 'array' AND jsonb_array_length(supported_stages) > 0
    ),
    CONSTRAINT ck_security_capability_actions_array CHECK (
        jsonb_typeof(allowed_actions) = 'array'
        AND jsonb_array_length(allowed_actions) > 0
        AND allowed_actions <@ '["audit","mask","block"]'::jsonb
    ),
    CONSTRAINT ck_security_capability_mask_action CHECK (
        NOT mask_capable OR allowed_actions @> '["mask"]'::jsonb
    ),
    CONSTRAINT ck_security_capability_metadata_object CHECK (jsonb_typeof(metadata_json) = 'object')
);

CREATE TABLE IF NOT EXISTS rule_capability_bindings (
    rule_id VARCHAR(64) NOT NULL REFERENCES rules(id) ON DELETE CASCADE,
    capability_id VARCHAR(160) NOT NULL REFERENCES security_capabilities(id) ON DELETE RESTRICT,
    binding_mode VARCHAR(8) NOT NULL DEFAULT 'any' CHECK (binding_mode IN ('any', 'all')),
    priority INTEGER NOT NULL DEFAULT 0 CHECK (priority BETWEEN -1000 AND 1000),
    config_json JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(config_json) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (rule_id, capability_id)
);

CREATE INDEX IF NOT EXISTS idx_rule_capability_bindings_capability
    ON rule_capability_bindings(capability_id);

-- This JSON block is also consumed by the repository contract test. It must
-- stay exactly equal to apps/web-console/src/utils/engine_categories.json.
WITH static_categories AS (
    SELECT value #>> '{}' AS category
    FROM jsonb_array_elements(
$static_capability_categories$
["agent_canary_token_leak","anthropic_key","apostrophe_variant","aws_access_key","aws_secret_key","bank_card_cn","classified_classified_cn","classified_classified_en","code_leak_access_key","code_leak_api_key_leak","code_leak_cloud_credential","code_leak_database_url","code_leak_password_in_code","code_leak_token_leak","config_file","date_separator_variant","debug_secret_template","discrimination_gender_discrimination","discrimination_racial_discrimination","discrimination_regional_discrimination","email","encoding_base64","encoding_hex_escape","encoding_unicode_escape","encoding_zero_width","env_file","generic_api_key","github_token","id_card_cn","illegal_cyber_attack","illegal_drugs","illegal_fraud","illegal_gambling","illegal_hazardous_chemical_instructions","illegal_pornography","illegal_system_command_instructions","illegal_violence_terror","jwt_token","keyword_assume_no_rules","keyword_bypass_restriction","keyword_classic_injection","keyword_classic_injection_en","keyword_conditional_bypass","keyword_dev_mode","keyword_dev_mode_en","keyword_forget_restriction","keyword_persona_unrestricted","keyword_reverse_induction","keyword_roleplay","keyword_roleplay_en","keyword_system_prompt_leak_en","multilingual_arabic","multilingual_cyrillic","multilingual_mongolian","multilingual_tibetan","multilingual_uyghur_kazakh","openai_key","phone_cn","political_ethnic_separatism","political_historical_nihilism","political_leader_name","political_sensitive_event","political_territory_split","political_territory_taiwan","quote_variant","self_harm_actionable_guidance","semantic_hypothetical_bypass","semantic_negation_bypass","semantic_step_by_step_bypass","semantic_translation_bypass","sensitive_file_customer_data","sensitive_file_financial_data","sensitive_file_hr_data","sensitive_file_internal_doc","ssh_private_key","ssrf_metadata_instruction","structured_code_block_injection","structured_html_comment","structured_template_injection","zero_width_char"]
$static_capability_categories$::jsonb
    )
)
INSERT INTO security_capabilities (
    id, category, name, capability_kind, component, selector_json,
    supported_stages, allowed_actions, mask_capable, enabled, metadata_json
)
SELECT
    'cap.static.' || category,
    category,
    category,
    'static',
    'security-engine.static-detectors',
    jsonb_build_object('category', category),
    '["input","output"]'::jsonb,
    CASE WHEN category IN ('phone_cn','id_card_cn','bank_card_cn','email')
         THEN '["audit","mask","block"]'::jsonb
         ELSE '["audit","block"]'::jsonb END,
    category IN ('phone_cn','id_card_cn','bank_card_cn','email'),
    TRUE,
    '{"catalog":"engine_categories","catalog_version":1}'::jsonb
FROM static_categories
ON CONFLICT (category) DO NOTHING;

WITH dynamic_catalog AS (
    SELECT *
    FROM jsonb_to_recordset(
$dynamic_capability_catalog$
[
  {"category":"semantic_roleplay","name":"语义角色扮演绕过","component":"security-engine.semantic","supported_stages":["input","output"],"allowed_actions":["audit","block"],"mask_capable":false},
  {"category":"semantic_instruction_override","name":"语义指令覆盖","component":"security-engine.semantic","supported_stages":["input","output"],"allowed_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_claude_code","name":"Claude Code 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"allowed_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_cursor","name":"Cursor 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"allowed_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_github_copilot","name":"GitHub Copilot 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"allowed_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_cline","name":"Cline/Roo Code 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"allowed_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_windsurf","name":"Windsurf/Cascade 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"allowed_actions":["audit","block"],"mask_capable":false},
  {"category":"agent_continue_dev","name":"Continue.dev 客户端指纹","component":"security-engine.agent-detect","supported_stages":["input"],"allowed_actions":["audit","block"],"mask_capable":false},
  {"category":"file_oversized","name":"超大文件检测","component":"security-engine.file-inspector","supported_stages":["input","output"],"allowed_actions":["audit","block"],"mask_capable":false}
]
$dynamic_capability_catalog$::jsonb
    ) AS x(
        category TEXT,
        name TEXT,
        component TEXT,
        supported_stages JSONB,
        allowed_actions JSONB,
        mask_capable BOOLEAN
    )
)
INSERT INTO security_capabilities (
    id, category, name, capability_kind, component, selector_json,
    supported_stages, allowed_actions, mask_capable, enabled, metadata_json
)
SELECT
    'cap.dynamic.' || category,
    category,
    name,
    'dynamic',
    component,
    jsonb_build_object('category', category),
    supported_stages,
    allowed_actions,
    mask_capable,
    TRUE,
    '{"catalog":"stable_dynamic_findings","catalog_version":1}'::jsonb
FROM dynamic_catalog
ON CONFLICT (category) DO NOTHING;

DO $$
BEGIN
    IF (
        SELECT COUNT(*)
        FROM security_capabilities capability
        WHERE capability.capability_kind='static'
          AND capability.id='cap.static.'||capability.category
          AND capability.name=capability.category
          AND capability.component='security-engine.static-detectors'
          AND capability.selector_json=jsonb_build_object('category',capability.category)
          AND capability.supported_stages='["input","output"]'::jsonb
          AND capability.allowed_actions=CASE
              WHEN capability.category IN ('phone_cn','id_card_cn','bank_card_cn','email')
              THEN '["audit","mask","block"]'::jsonb
              ELSE '["audit","block"]'::jsonb
          END
          AND capability.mask_capable=(capability.category IN ('phone_cn','id_card_cn','bank_card_cn','email'))
          AND capability.metadata_json='{"catalog":"engine_categories","catalog_version":1}'::jsonb
    ) <> 80 THEN
        RAISE EXCEPTION 'static capability catalog conflicts with the frozen 80-item contract';
    END IF;
    IF (
        SELECT COUNT(*)
        FROM security_capabilities capability
        WHERE capability.category IN (
            'semantic_roleplay','semantic_instruction_override',
            'agent_claude_code','agent_cursor','agent_github_copilot',
            'agent_cline','agent_windsurf','agent_continue_dev','file_oversized'
        )
          AND capability.capability_kind='dynamic'
          AND capability.id='cap.dynamic.'||capability.category
          AND capability.selector_json=jsonb_build_object('category',capability.category)
          AND capability.allowed_actions='["audit","block"]'::jsonb
          AND NOT capability.mask_capable
          AND capability.metadata_json='{"catalog":"stable_dynamic_findings","catalog_version":1}'::jsonb
    ) <> 9 THEN
        RAISE EXCEPTION 'dynamic capability catalog conflicts with the frozen 9-item contract';
    END IF;
END $$;

-- The full 255-item identity catalog is frozen here. Only these rows may
-- receive builtin policy codes; customer-created matcherless rows are excluded.
DROP TABLE IF EXISTS migration_125_default_policy_catalog;
CREATE TEMP TABLE migration_125_default_policy_catalog (
    rule_type TEXT NOT NULL,
    name TEXT NOT NULL,
    policy_code TEXT NOT NULL PRIMARY KEY,
    UNIQUE(rule_type, name)
);

INSERT INTO migration_125_default_policy_catalog(rule_type,name,policy_code)
SELECT rule_type,name,policy_code
FROM jsonb_to_recordset(
$default_policy_catalog$
[
  {
    "name": "API 直接调用检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.e2d7dcc63727dab9"
  },
  {
    "name": "Aider 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.008356aa358e9978"
  },
  {
    "name": "Amazon Q Developer 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.a5d24299196cf4f3"
  },
  {
    "name": "AutoGPT/BabyAGI 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.c124e717941b210c"
  },
  {
    "name": "Claude Code 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.f93768ab6617606e"
  },
  {
    "name": "Cline/Roo Code 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.60879276c451279a"
  },
  {
    "name": "CodeRabbit 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.c1759598ed72a0d2"
  },
  {
    "name": "Continue.dev 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.1d449b7a84677bb2"
  },
  {
    "name": "Copilot Chat/CLI 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.53e522e6a7b8dac2"
  },
  {
    "name": "CrewAI/AutoGen 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.5a691bbd627d263a"
  },
  {
    "name": "Cursor IDE 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.b620fc06d06c1fc7"
  },
  {
    "name": "Dify/Coze 平台检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.6f490afdd7023369"
  },
  {
    "name": "GitHub Copilot 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.12438c4c568f8c24"
  },
  {
    "name": "Google Gemini Code Assist",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.f539af0c43cb3787"
  },
  {
    "name": "LangChain/LlamaIndex SDK",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.364d6d282e3fd912"
  },
  {
    "name": "OpenAI Codex CLI 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.223c40ba05f83647"
  },
  {
    "name": "Replit AI 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.3aa45df74b2de7a8"
  },
  {
    "name": "Session 超长检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.3b83737794508b03"
  },
  {
    "name": "Sourcegraph Cody 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.79ae5816a3bf3ee5"
  },
  {
    "name": "Tabnine 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.6cada6a14d0a4263"
  },
  {
    "name": "Windsurf/Cascade 检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.c1896e0995119428"
  },
  {
    "name": "代理轮换检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.967c7b3cfd32049a"
  },
  {
    "name": "多身份并发检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.25c6ba2e41db01e3"
  },
  {
    "name": "异常地理位置请求",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.68cabce575a7dafa"
  },
  {
    "name": "异常工具调用检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.2451a4aa92aae6c4"
  },
  {
    "name": "异常时间窗口请求",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.baf350658bb917ff"
  },
  {
    "name": "批量请求模式检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.4011bbc60f4c286d"
  },
  {
    "name": "格式化响应提取",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.b9cbfe2be43132d0"
  },
  {
    "name": "设备指纹异常检测",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.1ec9fa7c05668d6e"
  },
  {
    "name": "请求频率限制",
    "rule_type": "agent_detect",
    "policy_code": "builtin.agent_detect.6bb38a327f4ddadd"
  },
  {
    "name": "LDAP 注入代码",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.c0bf948ca3c9ebe2"
  },
  {
    "name": "NoSQL 注入代码",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.2da958a010ca4303"
  },
  {
    "name": "SQL 注入代码生成",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.d82567ae4c6cba2a"
  },
  {
    "name": "SSRF 代码生成",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.eea7475d95f58dd5"
  },
  {
    "name": "XML 外部实体注入",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.d6121b4e9c6b3639"
  },
  {
    "name": "XSS 代码生成",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.46a74885f15123bb"
  },
  {
    "name": "不安全的文件处理",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.0234e3099d41f98b"
  },
  {
    "name": "不安全的随机数",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.3e1454b49ab95b46"
  },
  {
    "name": "内存溢出代码",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.d4bd0d8e0c6c9857"
  },
  {
    "name": "反序列化漏洞代码",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.83c72801873c89c6"
  },
  {
    "name": "命令注入代码生成",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.2e8190e3871e45d6"
  },
  {
    "name": "弱加密代码生成",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.829c9fe3cbc3a792"
  },
  {
    "name": "日志注入代码",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.be648ff0048d7877"
  },
  {
    "name": "权限绕过代码",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.4f2a28590d7747f6"
  },
  {
    "name": "模板注入代码",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.3f67649cc24121a3"
  },
  {
    "name": "硬编码凭据示例",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.9640acf0d1083905"
  },
  {
    "name": "路径遍历代码生成",
    "rule_type": "code_security",
    "policy_code": "builtin.code_security.389ee9cb3cb7c789"
  },
  {
    "name": "人肉搜索指导",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.93a1f2312c974373"
  },
  {
    "name": "人身攻击指导",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.94c8f6138ae0a180"
  },
  {
    "name": "仇恨言论",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.130064bdc1ae51ab"
  },
  {
    "name": "医疗欺诈内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.f658a2f524585da0"
  },
  {
    "name": "历史虚无主义",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.295e1c9330cfd201"
  },
  {
    "name": "家庭暴力内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.e741adeb0f05ae95"
  },
  {
    "name": "性暴力内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.94cbba62575e32f9"
  },
  {
    "name": "恐怖主义宣传",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.3f07c132c798a867"
  },
  {
    "name": "敏感人物/组织",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.3cc66da68952eebe"
  },
  {
    "name": "敏感政治事件",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.d6d189ffdd19c725"
  },
  {
    "name": "暴力恐怖内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.a33fdb67d98f1e9d"
  },
  {
    "name": "未成年人保护",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.972bcf8de3b4d32d"
  },
  {
    "name": "校园暴力内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.167af81998f1d9d8"
  },
  {
    "name": "武器制作指导",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.2e163d09b9155752"
  },
  {
    "name": "歧视内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.741b4225c2f0b108"
  },
  {
    "name": "毒品制作指导",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.2e7c3d1811c916b4"
  },
  {
    "name": "民族宗教问题",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.b0fa6eb641e7f1c5"
  },
  {
    "name": "煽动颠覆内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.84b78c69bd854278"
  },
  {
    "name": "环境污染指导",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.66f2bb762e173339"
  },
  {
    "name": "网络攻击教程",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.fc486a78d9176d14"
  },
  {
    "name": "网络暴力内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.c529368da553e93d"
  },
  {
    "name": "自杀方法指导",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.50e1338e3f0a2d02"
  },
  {
    "name": "自残/自杀内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.8b77e51268536ced"
  },
  {
    "name": "色情低俗内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.58663e6bd52f1ade"
  },
  {
    "name": "药品滥用指导",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.bb6ee23a359ce52e"
  },
  {
    "name": "虐待动物内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.4e2d6940ae0c8718"
  },
  {
    "name": "虚假信息/谣言",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.948316474cf587e1"
  },
  {
    "name": "赌博/诈骗内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.3b524e3893a7da4f"
  },
  {
    "name": "违禁品检测",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.37e8337d76413856"
  },
  {
    "name": "邪教宣传内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.430e892402c08738"
  },
  {
    "name": "领土主权检测",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.aeeb1eb209b9046e"
  },
  {
    "name": "领导人负面讨论",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.f1252b5fafaca83a"
  },
  {
    "name": "食品安全违规",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.9b130d27ba058baf"
  },
  {
    "name": "骚扰/霸凌内容",
    "rule_type": "content_safety",
    "policy_code": "builtin.content_safety.dc547e0b41610cca"
  },
  {
    "name": "专利内容复制",
    "rule_type": "copyright_protect",
    "policy_code": "builtin.copyright_protect.9c0b04a17d008a0c"
  },
  {
    "name": "侵权图像描述",
    "rule_type": "copyright_protect",
    "policy_code": "builtin.copyright_protect.7123a899c2158bdb"
  },
  {
    "name": "受保护角色再现",
    "rule_type": "copyright_protect",
    "policy_code": "builtin.copyright_protect.36cd5135e9429132"
  },
  {
    "name": "受版权文本生成",
    "rule_type": "copyright_protect",
    "policy_code": "builtin.copyright_protect.8459d0184254fe69"
  },
  {
    "name": "商业机密提取",
    "rule_type": "copyright_protect",
    "policy_code": "builtin.copyright_protect.1107170cb2c8407a"
  },
  {
    "name": "学术论文盗用",
    "rule_type": "copyright_protect",
    "policy_code": "builtin.copyright_protect.d971cfcccc10c312"
  },
  {
    "name": "开源许可绕过",
    "rule_type": "copyright_protect",
    "policy_code": "builtin.copyright_protect.e3ded2f4e7620f42"
  },
  {
    "name": "歌词批量导出",
    "rule_type": "copyright_protect",
    "policy_code": "builtin.copyright_protect.a77b346995352c2b"
  },
  {
    "name": "盗版内容提取",
    "rule_type": "copyright_protect",
    "policy_code": "builtin.copyright_protect.5bc4433e74d45c13"
  },
  {
    "name": "API Key 检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.aa4bbf915707ff15"
  },
  {
    "name": "AWS/GCP 凭据检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.4cf7caaec6252ac7"
  },
  {
    "name": "IP 地址检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.0cce2cce8b7bc217"
  },
  {
    "name": "JWT/Token 检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.87358f1a6d000590"
  },
  {
    "name": "SSH 密钥检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.db6cefda8798cab2"
  },
  {
    "name": "位置/GPS 数据",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.a9ac5ee3d220e157"
  },
  {
    "name": "保险信息检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.7399a414eb30dbb9"
  },
  {
    "name": "信用卡CVV检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.afa8b93679b66cb2"
  },
  {
    "name": "内部项目代号检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.e40d55f61d111133"
  },
  {
    "name": "军官证检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.9a6811b786b7618f"
  },
  {
    "name": "出生日期检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.b37eae3f56e3d8f4"
  },
  {
    "name": "医疗记录检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.cd7cd3f962c8a7c1"
  },
  {
    "name": "基因数据检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.f21dc3ac3d94c0f3"
  },
  {
    "name": "家庭地址检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.aa6a72765f3d1d2b"
  },
  {
    "name": "密码明文检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.98cc238bfbf6babb"
  },
  {
    "name": "手机号检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.e5821efde7585cbb"
  },
  {
    "name": "护照号检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.2348426d637af519"
  },
  {
    "name": "敏感代码片段检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.85d7d239c670bab5"
  },
  {
    "name": "教育背景检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.55e2d913ee8746b4"
  },
  {
    "name": "数据库连接串检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.67728f5a17e4a70a"
  },
  {
    "name": "涉密文件标记检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.17723b156cfa7533"
  },
  {
    "name": "港澳台证件检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.63ae19f7cd1834bf"
  },
  {
    "name": "犯罪记录检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.1a873ce1a4f5e91e"
  },
  {
    "name": "生物特征检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.65f151cdf48b5404"
  },
  {
    "name": "社保卡号检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.e18afae0f9594164"
  },
  {
    "name": "证书/私钥检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.a0891acf6ebc39c0"
  },
  {
    "name": "身份证号检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.ee20059e4c9fbf2f"
  },
  {
    "name": "通信记录检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.3512cd70e182c979"
  },
  {
    "name": "邮箱地址检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.261854a33ac6da17"
  },
  {
    "name": "银行卡号检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.a3048f2177b99395"
  },
  {
    "name": "银行流水检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.d85734a727cce7b8"
  },
  {
    "name": "驾驶证检测",
    "rule_type": "data_leak",
    "policy_code": "builtin.data_leak.86c5bbeff12d7c44"
  },
  {
    "name": "大文件处理攻击",
    "rule_type": "dos_protection",
    "policy_code": "builtin.dos_protection.1c7e9f9970f83177"
  },
  {
    "name": "批量并发请求",
    "rule_type": "dos_protection",
    "policy_code": "builtin.dos_protection.1d26c44f7b71efac"
  },
  {
    "name": "指数膨胀请求",
    "rule_type": "dos_protection",
    "policy_code": "builtin.dos_protection.4f43236bc20250dc"
  },
  {
    "name": "无限循环指令",
    "rule_type": "dos_protection",
    "policy_code": "builtin.dos_protection.762fbe86a6615238"
  },
  {
    "name": "正则回溯攻击",
    "rule_type": "dos_protection",
    "policy_code": "builtin.dos_protection.c49a1dd5605cb6d1"
  },
  {
    "name": "深层嵌套展开",
    "rule_type": "dos_protection",
    "policy_code": "builtin.dos_protection.5f096e00aa599617"
  },
  {
    "name": "资源耗尽指令",
    "rule_type": "dos_protection",
    "policy_code": "builtin.dos_protection.4290e5f12c4f81a4"
  },
  {
    "name": "超长上下文消耗",
    "rule_type": "dos_protection",
    "policy_code": "builtin.dos_protection.26b5a56593b2a884"
  },
  {
    "name": "递归函数调用",
    "rule_type": "dos_protection",
    "policy_code": "builtin.dos_protection.6e61ea7c8d2d9a07"
  },
  {
    "name": "递归展开攻击",
    "rule_type": "dos_protection",
    "policy_code": "builtin.dos_protection.6f6907dfdbc2ee17"
  },
  {
    "name": "重复提交攻击",
    "rule_type": "dos_protection",
    "policy_code": "builtin.dos_protection.e669fe2aeef676da"
  },
  {
    "name": "假冒公检法话术",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.eafd99decc56bca2"
  },
  {
    "name": "假冒银行通知",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.6ff312032520747d"
  },
  {
    "name": "冒充客服话术",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.9dbfbdb60934fd8e"
  },
  {
    "name": "冒充领导诈骗",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.eadf367494293780"
  },
  {
    "name": "刷单诈骗话术",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.9414bd270d35d512"
  },
  {
    "name": "加密货币骗局",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.7e0c55725773bdb8"
  },
  {
    "name": "庞氏骗局话术",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.c99081d7ce4ae6de"
  },
  {
    "name": "杀猪盘话术",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.5b7e940a2a8800b2"
  },
  {
    "name": "虚假中奖信息",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.e6509942afa78488"
  },
  {
    "name": "虚假众筹文案",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.5924fd3912c0e21c"
  },
  {
    "name": "虚假投资平台",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.e8c52e0bae177488"
  },
  {
    "name": "虚假投资话术",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.85094af4238a5149"
  },
  {
    "name": "虚假招聘诈骗",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.193da7504db91d7c"
  },
  {
    "name": "虚假购物网站",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.5fdc9f9c064a22a1"
  },
  {
    "name": "虚假贷款推广",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.98e22b1a3a71ca52"
  },
  {
    "name": "退款诈骗话术",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.8515194cb5e180de"
  },
  {
    "name": "钓鱼邮件生成",
    "rule_type": "fraud_detect",
    "policy_code": "builtin.fraud_detect.31114886164ee6ac"
  },
  {
    "name": "人体器官交易",
    "rule_type": "illegal_trade",
    "policy_code": "builtin.illegal_trade.2baa4f43c99678c0"
  },
  {
    "name": "人口贩卖内容",
    "rule_type": "illegal_trade",
    "policy_code": "builtin.illegal_trade.b42c9e2d1d6a1cdb"
  },
  {
    "name": "假冒证件制作",
    "rule_type": "illegal_trade",
    "policy_code": "builtin.illegal_trade.41681caad5e30153"
  },
  {
    "name": "假货制造指导",
    "rule_type": "illegal_trade",
    "policy_code": "builtin.illegal_trade.17afa89cca4e8954"
  },
  {
    "name": "处方药违规销售",
    "rule_type": "illegal_trade",
    "policy_code": "builtin.illegal_trade.3a11e5702d46e089"
  },
  {
    "name": "毒品交易引导",
    "rule_type": "illegal_trade",
    "policy_code": "builtin.illegal_trade.103b0604b9ae8e51"
  },
  {
    "name": "走私方法咨询",
    "rule_type": "illegal_trade",
    "policy_code": "builtin.illegal_trade.5ed755f877e035f9"
  },
  {
    "name": "违禁品交易引导",
    "rule_type": "illegal_trade",
    "policy_code": "builtin.illegal_trade.36d483957d6bc246"
  },
  {
    "name": "野生动物交易",
    "rule_type": "illegal_trade",
    "policy_code": "builtin.illegal_trade.3f55b904e1900e0d"
  },
  {
    "name": "非法武器交易",
    "rule_type": "illegal_trade",
    "policy_code": "builtin.illegal_trade.b5eab46d920f0a59"
  },
  {
    "name": "黑市交易引导",
    "rule_type": "illegal_trade",
    "policy_code": "builtin.illegal_trade.4f6d018cc6d7ee00"
  },
  {
    "name": "MCP 权限绕过",
    "rule_type": "plugin_security",
    "policy_code": "builtin.plugin_security.450758fa39c93507"
  },
  {
    "name": "工具拒绝执行",
    "rule_type": "plugin_security",
    "policy_code": "builtin.plugin_security.1024164507834300"
  },
  {
    "name": "工具日志篡改",
    "rule_type": "plugin_security",
    "policy_code": "builtin.plugin_security.b5f7907c68e5bf34"
  },
  {
    "name": "工具窃取数据",
    "rule_type": "plugin_security",
    "policy_code": "builtin.plugin_security.1aa5c9889e5f4e27"
  },
  {
    "name": "恶意插件安装",
    "rule_type": "plugin_security",
    "policy_code": "builtin.plugin_security.7f715200f0fa437d"
  },
  {
    "name": "插件数据泄露",
    "rule_type": "plugin_security",
    "policy_code": "builtin.plugin_security.0e486a2f5576a9b0"
  },
  {
    "name": "插件权限提升",
    "rule_type": "plugin_security",
    "policy_code": "builtin.plugin_security.ba997217f9b54e40"
  },
  {
    "name": "插件链式攻击",
    "rule_type": "plugin_security",
    "policy_code": "builtin.plugin_security.fb49d223f677b0ac"
  },
  {
    "name": "文件系统越权",
    "rule_type": "plugin_security",
    "policy_code": "builtin.plugin_security.e9d082e3a9566521"
  },
  {
    "name": "未授权工具调用",
    "rule_type": "plugin_security",
    "policy_code": "builtin.plugin_security.5c66059903fe2cab"
  },
  {
    "name": "网络请求伪造",
    "rule_type": "plugin_security",
    "policy_code": "builtin.plugin_security.2932cca214e98d4e"
  },
  {
    "name": "ASCII 艺术注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.c2cc41c645d6e802"
  },
  {
    "name": "Base32/Base16 编码注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.9f67a6da54bce276"
  },
  {
    "name": "Base64 编码注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.f4809d017dfbf3a6"
  },
  {
    "name": "Emoji 编码注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.467da79f0b886cd8"
  },
  {
    "name": "Few-shot 攻击检测",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.344b93890cdccc3e"
  },
  {
    "name": "GIF/图像隐写注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.839171ac2965425a"
  },
  {
    "name": "Hex 编码注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.ac6042efdf14b49c"
  },
  {
    "name": "JSON/XML 结构注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.7264c727a4fc2ed4"
  },
  {
    "name": "Markdown 渲染注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.75f29627a37e0d01"
  },
  {
    "name": "Payload 拆分注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.4326456f74d43796"
  },
  {
    "name": "ROT13/Atbash 编码绕过",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.4b465e70a6377330"
  },
  {
    "name": "Token 走私攻击",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.f28adec4733f37d1"
  },
  {
    "name": "URL 编码绕过",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.57767f0750a92dfa"
  },
  {
    "name": "Unicode 编码绕过",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.8a4cfd4d54e80e99"
  },
  {
    "name": "上下文截断攻击",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.ba9a8699a54af996"
  },
  {
    "name": "二进制/八进制编码注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.5ab93c096487f735"
  },
  {
    "name": "伪代码注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.90eebdc9900c34be"
  },
  {
    "name": "假设场景绕过",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.fec82263fa576a55"
  },
  {
    "name": "分隔符混淆攻击",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.d2484f0152f1f577"
  },
  {
    "name": "协作借口绕过",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.13c78c8cb376da98"
  },
  {
    "name": "双重编码检测",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.4fb2be0130d3f3f1"
  },
  {
    "name": "同形字符替换",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.3c2c8a296f39670e"
  },
  {
    "name": "否定式注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.1ac9559c46501ff8"
  },
  {
    "name": "多模态输入注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.15004e1e3fd53f86"
  },
  {
    "name": "多轮铺垫攻击",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.c2bd08c27cf70ea1"
  },
  {
    "name": "学术研究借口",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.51e37afc89cb1115"
  },
  {
    "name": "对抗性后缀攻击",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.73644306e4dfbcf4"
  },
  {
    "name": "对比示例攻击",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.af7e6ee3195516c6"
  },
  {
    "name": "小语种注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.f45dc17b1e6725b7"
  },
  {
    "name": "情感操控诱导",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.b322a14e01c1d5d5"
  },
  {
    "name": "技术支持冒充",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.d29c0062c05c6a04"
  },
  {
    "name": "排列组合注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.7730b3cbd5246f1f"
  },
  {
    "name": "术语混淆绕过",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.c171230d59d1a27a"
  },
  {
    "name": "权威引用伪造",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.90324ca72fb4d87a"
  },
  {
    "name": "模板填充注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.bfbe6a1eccdb32ef"
  },
  {
    "name": "法律威胁诱导",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.5ce853ec8c7904ab"
  },
  {
    "name": "混合语种绕过",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.cbadb8fba1cbd3ce"
  },
  {
    "name": "渐进式脱敏诱导",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.69e7baa759b6c503"
  },
  {
    "name": "特权提升检测",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.5e084cbc6cb3c32d"
  },
  {
    "name": "系统提示覆写检测",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.594c6d42965bb1d1"
  },
  {
    "name": "紧急语气绕过",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.b2a9904f92b79552"
  },
  {
    "name": "经典注入指令检测",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.8894ce9a632bada9"
  },
  {
    "name": "翻译绕过",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.752acd8e33f82f2d"
  },
  {
    "name": "自定义编码/莫尔斯电码",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.b167772e4c27e54b"
  },
  {
    "name": "虚假安全警报",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.ba1fbb4a4032dc78"
  },
  {
    "name": "角色扮演注入检测",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.7396b867d7156f96"
  },
  {
    "name": "逐步诱导检测",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.6e0c3ca0b2eaf8a8"
  },
  {
    "name": "逻辑谜题绕过",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.8c29ec75bf9c8cc1"
  },
  {
    "name": "道德困境诱导",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.a74e7f1501822fc1"
  },
  {
    "name": "道德权威施压",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.4a2869c6bcc5351c"
  },
  {
    "name": "零宽字符注入",
    "rule_type": "prompt_injection",
    "policy_code": "builtin.prompt_injection.ba9bbb9f63e7b514"
  },
  {
    "name": "API 参数探测",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.c584e35e5a105858"
  },
  {
    "name": "Base64 提示提取",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.4e51f1e57aa519c0"
  },
  {
    "name": "元指令泄露检测",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.4b4745b0d80aa02a"
  },
  {
    "name": "内部指令查询",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.2dd388f0575b616c"
  },
  {
    "name": "分隔符探测攻击",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.ebfe1cb42be3b070"
  },
  {
    "name": "初始指令泄露检测",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.67489bdeaea0573a"
  },
  {
    "name": "多语言提示提取",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.0fae073315d29973"
  },
  {
    "name": "提示词反转攻击",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.4fb9d9df2042df28"
  },
  {
    "name": "提示词重构攻击",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.0dae0c3ea88dad80"
  },
  {
    "name": "格式化导出要求",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.81c61518cc032dbd"
  },
  {
    "name": "渐进式提示提取",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.801e45f28d7a1758"
  },
  {
    "name": "系统提示提取检测",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.00e21ecc7d791885"
  },
  {
    "name": "系统配置探测",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.7e8a7b334134633b"
  },
  {
    "name": "编码方式提取",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.aa2cf7f9df399747"
  },
  {
    "name": "角色反转提取",
    "rule_type": "prompt_leak",
    "policy_code": "builtin.prompt_leak.adaf812b35c328aa"
  },
  {
    "name": "RAG 数据泄露",
    "rule_type": "rag_security",
    "policy_code": "builtin.rag_security.467a622e0be8d906"
  },
  {
    "name": "RAG 缓存投毒",
    "rule_type": "rag_security",
    "policy_code": "builtin.rag_security.74a9f1e667ced7cf"
  },
  {
    "name": "向量嵌入操纵",
    "rule_type": "rag_security",
    "policy_code": "builtin.rag_security.13154dbf8dc32f3f"
  },
  {
    "name": "外部知识投毒",
    "rule_type": "rag_security",
    "policy_code": "builtin.rag_security.af8adaef83896e2d"
  },
  {
    "name": "文档源欺骗",
    "rule_type": "rag_security",
    "policy_code": "builtin.rag_security.659584df2cd2be3d"
  },
  {
    "name": "检索上下文劫持",
    "rule_type": "rag_security",
    "policy_code": "builtin.rag_security.d42179890c2b8967"
  },
  {
    "name": "检索结果篡改",
    "rule_type": "rag_security",
    "policy_code": "builtin.rag_security.08b9b614ab365989"
  },
  {
    "name": "知识库越权查询",
    "rule_type": "rag_security",
    "policy_code": "builtin.rag_security.0c2992f0a6665641"
  },
  {
    "name": "虚假文档引用",
    "rule_type": "rag_security",
    "policy_code": "builtin.rag_security.1723128d6f171f69"
  },
  {
    "name": "合规标签绕过",
    "rule_type": "supply_chain",
    "policy_code": "builtin.supply_chain.91151fe7a133df12"
  },
  {
    "name": "影子模型使用",
    "rule_type": "supply_chain",
    "policy_code": "builtin.supply_chain.9e3f687b97ec8ae3"
  },
  {
    "name": "恶意模型加载",
    "rule_type": "supply_chain",
    "policy_code": "builtin.supply_chain.26bc51020d532aaf"
  },
  {
    "name": "未授权模型调用",
    "rule_type": "supply_chain",
    "policy_code": "builtin.supply_chain.98c244cb0345cb0d"
  },
  {
    "name": "模型权重窃取",
    "rule_type": "supply_chain",
    "policy_code": "builtin.supply_chain.dd2a34c2c0d63125"
  },
  {
    "name": "模型版本漏洞探测",
    "rule_type": "supply_chain",
    "policy_code": "builtin.supply_chain.e88a49da94a0a712"
  },
  {
    "name": "模型行为探测",
    "rule_type": "supply_chain",
    "policy_code": "builtin.supply_chain.cc3faf3e41ecaaa8"
  },
  {
    "name": "第三方依赖漏洞",
    "rule_type": "supply_chain",
    "policy_code": "builtin.supply_chain.575265dc58c794c7"
  }
]
$default_policy_catalog$::jsonb
) AS x(rule_type TEXT,name TEXT,policy_code TEXT);

DO $$
BEGIN
    IF (SELECT COUNT(*) FROM migration_125_default_policy_catalog) <> 255 THEN
        RAISE EXCEPTION 'default policy identity catalog must contain exactly 255 rows';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM rule_sets rs
        WHERE rs.source_type='system'
          AND rs.name='默认安全策略'
          AND EXISTS (
              SELECT 1 FROM rules candidate
              WHERE candidate.rule_set_id=rs.id
                AND candidate.rule_type IN (
                    'prompt_injection','content_safety','agent_detect','data_leak',
                    'prompt_leak','code_security','fraud_detect','dos_protection',
                    'plugin_security','illegal_trade','copyright_protect','rag_security','supply_chain'
                )
                AND COALESCE(candidate.match_config_json,'{}'::jsonb)='{}'::jsonb
          )
          AND (
              SELECT COUNT(*)
              FROM rules policy
              JOIN migration_125_default_policy_catalog catalog
                ON catalog.rule_type=policy.rule_type
               AND catalog.name=policy.name
              WHERE policy.rule_set_id=rs.id
                AND COALESCE(policy.match_config_json,'{}'::jsonb)='{}'::jsonb
          ) <> 255
    ) THEN
        RAISE EXCEPTION 'default policy set does not match the frozen 255-item identity catalog';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM rules policy
        JOIN rule_sets rs ON rs.id=policy.rule_set_id
        JOIN migration_125_default_policy_catalog catalog
          ON catalog.rule_type=policy.rule_type
         AND catalog.name=policy.name
        WHERE rs.source_type='system'
          AND rs.name='默认安全策略'
          AND COALESCE(policy.match_config_json,'{}'::jsonb)='{}'::jsonb
        GROUP BY policy.rule_set_id,catalog.policy_code
        HAVING COUNT(*) > 1
    ) THEN
        RAISE EXCEPTION 'ambiguous duplicate default policy rows';
    END IF;
END $$;

UPDATE rules policy
SET policy_code=catalog.policy_code
FROM rule_sets rs,migration_125_default_policy_catalog catalog
WHERE rs.id=policy.rule_set_id
  AND rs.source_type='system'
  AND rs.name='默认安全策略'
  AND policy.rule_type=catalog.rule_type
  AND policy.name=catalog.name
  AND COALESCE(policy.match_config_json,'{}'::jsonb)='{}'::jsonb
  AND policy.policy_code IS NULL;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM rules policy
        JOIN rule_sets rs ON rs.id=policy.rule_set_id
        JOIN migration_125_default_policy_catalog catalog
          ON catalog.rule_type=policy.rule_type
         AND catalog.name=policy.name
        WHERE rs.source_type='system'
          AND rs.name='默认安全策略'
          AND COALESCE(policy.match_config_json,'{}'::jsonb)='{}'::jsonb
          AND policy.policy_code IS DISTINCT FROM catalog.policy_code
    ) THEN
        RAISE EXCEPTION 'default policy code conflicts with frozen identity catalog';
    END IF;
END $$;

-- The five generic executable rules keep their stable rule IDs and receive a
-- namespaced policy code. No additional rules are created.
UPDATE rules r
SET policy_code = 'system.generic.' || r.id
FROM rule_sets rs
WHERE rs.id = r.rule_set_id
  AND rs.id = 'ruleset_builtin_generic'
  AND rs.tenant_id = 'tenant_system'
  AND rs.source_type = 'builtin'
  AND r.id IN ('rule_g_phone','rule_g_idcard','rule_g_bankcard','rule_g_email','rule_g_passport')
  AND r.policy_code IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_rules_rule_set_policy_code
    ON rules(rule_set_id, policy_code)
    WHERE policy_code IS NOT NULL;

DROP TABLE IF EXISTS migration_125_exact_bindings;
CREATE TEMP TABLE migration_125_exact_bindings (
    policy_code TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    name TEXT NOT NULL,
    capability_categories JSONB NOT NULL,
    binding_mode TEXT NOT NULL
);

INSERT INTO migration_125_exact_bindings(
    policy_code,rule_type,name,capability_categories,binding_mode
)
SELECT policy_code,rule_type,name,capability_categories,binding_mode
FROM jsonb_to_recordset(
$exact_policy_capability_bindings$
[
  {
    "rule_type": "prompt_injection",
    "name": "经典注入指令检测",
    "capability_categories": [
      "keyword_classic_injection",
      "keyword_classic_injection_en"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.8894ce9a632bada9"
  },
  {
    "rule_type": "prompt_injection",
    "name": "角色扮演注入检测",
    "capability_categories": [
      "keyword_roleplay",
      "keyword_roleplay_en",
      "semantic_roleplay"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.7396b867d7156f96"
  },
  {
    "rule_type": "prompt_injection",
    "name": "否定式注入",
    "capability_categories": [
      "semantic_negation_bypass"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.1ac9559c46501ff8"
  },
  {
    "rule_type": "prompt_injection",
    "name": "假设场景绕过",
    "capability_categories": [
      "semantic_hypothetical_bypass"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.fec82263fa576a55"
  },
  {
    "rule_type": "prompt_injection",
    "name": "系统提示覆写检测",
    "capability_categories": [
      "semantic_instruction_override"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.594c6d42965bb1d1"
  },
  {
    "rule_type": "prompt_injection",
    "name": "Base64 编码注入",
    "capability_categories": [
      "encoding_base64"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.f4809d017dfbf3a6"
  },
  {
    "rule_type": "prompt_injection",
    "name": "Hex 编码注入",
    "capability_categories": [
      "encoding_hex_escape"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.ac6042efdf14b49c"
  },
  {
    "rule_type": "prompt_injection",
    "name": "Unicode 编码绕过",
    "capability_categories": [
      "encoding_unicode_escape"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.8a4cfd4d54e80e99"
  },
  {
    "rule_type": "prompt_injection",
    "name": "零宽字符注入",
    "capability_categories": [
      "encoding_zero_width",
      "zero_width_char"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.ba9bbb9f63e7b514"
  },
  {
    "rule_type": "prompt_injection",
    "name": "逐步诱导检测",
    "capability_categories": [
      "semantic_step_by_step_bypass"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.6e0c3ca0b2eaf8a8"
  },
  {
    "rule_type": "prompt_injection",
    "name": "翻译绕过",
    "capability_categories": [
      "semantic_translation_bypass"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.752acd8e33f82f2d"
  },
  {
    "rule_type": "prompt_injection",
    "name": "模板填充注入",
    "capability_categories": [
      "structured_template_injection"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_injection.bfbe6a1eccdb32ef"
  },
  {
    "rule_type": "content_safety",
    "name": "敏感政治事件",
    "capability_categories": [
      "political_sensitive_event"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.content_safety.d6d189ffdd19c725"
  },
  {
    "rule_type": "content_safety",
    "name": "领土主权检测",
    "capability_categories": [
      "political_territory_taiwan",
      "political_territory_split"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.content_safety.aeeb1eb209b9046e"
  },
  {
    "rule_type": "content_safety",
    "name": "历史虚无主义",
    "capability_categories": [
      "political_historical_nihilism"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.content_safety.295e1c9330cfd201"
  },
  {
    "rule_type": "content_safety",
    "name": "色情低俗内容",
    "capability_categories": [
      "illegal_pornography"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.content_safety.58663e6bd52f1ade"
  },
  {
    "rule_type": "content_safety",
    "name": "暴力恐怖内容",
    "capability_categories": [
      "illegal_violence_terror"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.content_safety.a33fdb67d98f1e9d"
  },
  {
    "rule_type": "content_safety",
    "name": "自杀方法指导",
    "capability_categories": [
      "self_harm_actionable_guidance"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.content_safety.50e1338e3f0a2d02"
  },
  {
    "rule_type": "content_safety",
    "name": "赌博/诈骗内容",
    "capability_categories": [
      "illegal_gambling",
      "illegal_fraud"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.content_safety.3b524e3893a7da4f"
  },
  {
    "rule_type": "agent_detect",
    "name": "Claude Code 检测",
    "capability_categories": [
      "agent_claude_code"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.agent_detect.f93768ab6617606e"
  },
  {
    "rule_type": "agent_detect",
    "name": "Cursor IDE 检测",
    "capability_categories": [
      "agent_cursor"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.agent_detect.b620fc06d06c1fc7"
  },
  {
    "rule_type": "agent_detect",
    "name": "GitHub Copilot 检测",
    "capability_categories": [
      "agent_github_copilot"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.agent_detect.12438c4c568f8c24"
  },
  {
    "rule_type": "agent_detect",
    "name": "Cline/Roo Code 检测",
    "capability_categories": [
      "agent_cline"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.agent_detect.60879276c451279a"
  },
  {
    "rule_type": "agent_detect",
    "name": "Windsurf/Cascade 检测",
    "capability_categories": [
      "agent_windsurf"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.agent_detect.c1896e0995119428"
  },
  {
    "rule_type": "agent_detect",
    "name": "Continue.dev 检测",
    "capability_categories": [
      "agent_continue_dev"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.agent_detect.1d449b7a84677bb2"
  },
  {
    "rule_type": "data_leak",
    "name": "手机号检测",
    "capability_categories": [
      "phone_cn"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.data_leak.e5821efde7585cbb"
  },
  {
    "rule_type": "data_leak",
    "name": "身份证号检测",
    "capability_categories": [
      "id_card_cn"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.data_leak.ee20059e4c9fbf2f"
  },
  {
    "rule_type": "data_leak",
    "name": "银行卡号检测",
    "capability_categories": [
      "bank_card_cn"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.data_leak.a3048f2177b99395"
  },
  {
    "rule_type": "data_leak",
    "name": "邮箱地址检测",
    "capability_categories": [
      "email"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.data_leak.261854a33ac6da17"
  },
  {
    "rule_type": "data_leak",
    "name": "API Key 检测",
    "capability_categories": [
      "generic_api_key",
      "openai_key",
      "anthropic_key",
      "github_token"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.data_leak.aa4bbf915707ff15"
  },
  {
    "rule_type": "data_leak",
    "name": "JWT/Token 检测",
    "capability_categories": [
      "jwt_token"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.data_leak.87358f1a6d000590"
  },
  {
    "rule_type": "data_leak",
    "name": "证书/私钥检测",
    "capability_categories": [
      "ssh_private_key"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.data_leak.a0891acf6ebc39c0"
  },
  {
    "rule_type": "data_leak",
    "name": "数据库连接串检测",
    "capability_categories": [
      "code_leak_database_url"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.data_leak.67728f5a17e4a70a"
  },
  {
    "rule_type": "data_leak",
    "name": "涉密文件标记检测",
    "capability_categories": [
      "classified_classified_cn",
      "classified_classified_en"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.data_leak.17723b156cfa7533"
  },
  {
    "rule_type": "prompt_leak",
    "name": "系统提示提取检测",
    "capability_categories": [
      "keyword_system_prompt_leak_en"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.prompt_leak.00e21ecc7d791885"
  },
  {
    "rule_type": "dos_protection",
    "name": "大文件处理攻击",
    "capability_categories": [
      "file_oversized"
    ],
    "binding_mode": "any",
    "policy_code": "builtin.dos_protection.1c7e9f9970f83177"
  }
]
$exact_policy_capability_bindings$::jsonb
) AS x(
    policy_code TEXT,
    rule_type TEXT,
    name TEXT,
    capability_categories JSONB,
    binding_mode TEXT
);

WITH expanded AS (
    SELECT
        exact.policy_code,
        exact.binding_mode,
        jsonb_array_elements_text(exact.capability_categories) AS category
    FROM migration_125_exact_bindings exact
)
INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT policy.id,capability.id,expanded.binding_mode,0,'{}'::jsonb
FROM expanded
JOIN rules policy ON policy.policy_code=expanded.policy_code
JOIN rule_sets rs
  ON rs.id=policy.rule_set_id
 AND rs.source_type='system'
 AND rs.name='默认安全策略'
JOIN security_capabilities capability ON capability.category=expanded.category
ON CONFLICT (rule_id,capability_id) DO NOTHING;

DO $$
BEGIN
    IF (SELECT COUNT(*) FROM migration_125_exact_bindings) <> 36 THEN
        RAISE EXCEPTION 'exact policy catalog must contain exactly 36 policies';
    END IF;
    IF EXISTS (
        SELECT policy.rule_set_id,exact.policy_code,category.value
        FROM rules policy
        JOIN rule_sets rs
          ON rs.id=policy.rule_set_id
         AND rs.source_type='system'
         AND rs.name='默认安全策略'
        JOIN migration_125_exact_bindings exact
          ON exact.policy_code=policy.policy_code
        CROSS JOIN LATERAL jsonb_array_elements_text(exact.capability_categories) category(value)
        LEFT JOIN security_capabilities capability ON capability.category=category.value
        LEFT JOIN rule_capability_bindings binding
          ON binding.rule_id=policy.id
         AND binding.capability_id=capability.id
        WHERE binding.rule_id IS NULL
    ) THEN
        RAISE EXCEPTION 'exact policy capability binding set is incomplete';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM rule_capability_bindings binding
        JOIN rules policy ON policy.id = binding.rule_id
        JOIN security_capabilities capability ON capability.id = binding.capability_id
        WHERE NOT (capability.allowed_actions ? policy.action)
           OR (policy.action = 'mask' AND NOT capability.mask_capable)
    ) THEN
        RAISE EXCEPTION 'policy action is not supported by its capability binding';
    END IF;
END $$;

DROP TABLE IF EXISTS migration_125_exact_bindings;
DROP TABLE IF EXISTS migration_125_default_policy_catalog;
