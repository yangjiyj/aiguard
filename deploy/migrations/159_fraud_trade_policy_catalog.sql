-- Register deterministic fraud and illegal-trade intent policies.

BEGIN;

CREATE TEMP TABLE migration_159_capabilities ON COMMIT DROP AS
SELECT category,name,component,supported_stages,builtin_actions,mask_capable
FROM jsonb_to_recordset(
$runtime_policy_capabilities$
[
  {"category":"fraud_law_enforcement_impersonation","name":"假冒公检法话术","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_bank_notice","name":"假冒银行通知","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_customer_service_impersonation","name":"冒充客服话术","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_executive_impersonation","name":"冒充领导诈骗","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_task_scam","name":"刷单诈骗话术","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_crypto_scam","name":"加密货币骗局","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_ponzi_scheme","name":"庞氏骗局话术","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_pig_butchering","name":"杀猪盘话术","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_fake_prize","name":"虚假中奖信息","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_crowdfunding","name":"虚假众筹文案","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_fake_investment_platform","name":"虚假投资平台","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_investment_pitch","name":"虚假投资话术","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_recruitment","name":"虚假招聘诈骗","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_fake_shop","name":"虚假购物网站","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_loan","name":"虚假贷款推广","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_refund","name":"退款诈骗话术","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"fraud_phishing_email","name":"钓鱼邮件生成","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"illegal_organ_trade","name":"人体器官交易","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"illegal_human_trafficking","name":"人口贩卖内容","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"illegal_forged_document","name":"假冒证件制作","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"illegal_counterfeit_goods","name":"假货制造指导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"illegal_prescription_drug_trade","name":"处方药违规销售","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"illegal_drug_trade","name":"毒品交易引导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"illegal_smuggling","name":"走私方法咨询","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"illegal_contraband_trade","name":"违禁品交易引导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"illegal_wildlife_trade","name":"野生动物交易","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"illegal_weapon_trade","name":"非法武器交易","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false},
  {"category":"illegal_black_market","name":"黑市交易引导","component":"security-engine.policy-catalog","supported_stages":["input"],"builtin_actions":["audit","block"],"mask_capable":false}
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
    mask_capable,TRUE,'{"catalog":"fraud_trade_policy","catalog_version":1}'::jsonb
FROM migration_159_capabilities
ON CONFLICT (category) DO UPDATE SET
    name=EXCLUDED.name,
    capability_kind=EXCLUDED.capability_kind,
    component=EXCLUDED.component,
    selector_json=EXCLUDED.selector_json,
    supported_stages=EXCLUDED.supported_stages,
    allowed_actions=EXCLUDED.allowed_actions,
    mask_capable=EXCLUDED.mask_capable,
    metadata_json=EXCLUDED.metadata_json;

CREATE TEMP TABLE migration_159_bindings ON COMMIT DROP AS
SELECT policy_code,rule_type,name,capability_categories,binding_mode
FROM jsonb_to_recordset(
$runtime_policy_bindings$
[
  {"rule_type":"fraud_detect","name":"假冒公检法话术","policy_code":"builtin.fraud_detect.eafd99decc56bca2","capability_categories":["fraud_law_enforcement_impersonation"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"假冒银行通知","policy_code":"builtin.fraud_detect.6ff312032520747d","capability_categories":["fraud_bank_notice"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"冒充客服话术","policy_code":"builtin.fraud_detect.9dbfbdb60934fd8e","capability_categories":["fraud_customer_service_impersonation"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"冒充领导诈骗","policy_code":"builtin.fraud_detect.eadf367494293780","capability_categories":["fraud_executive_impersonation"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"刷单诈骗话术","policy_code":"builtin.fraud_detect.9414bd270d35d512","capability_categories":["fraud_task_scam"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"加密货币骗局","policy_code":"builtin.fraud_detect.7e0c55725773bdb8","capability_categories":["fraud_crypto_scam"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"庞氏骗局话术","policy_code":"builtin.fraud_detect.c99081d7ce4ae6de","capability_categories":["fraud_ponzi_scheme"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"杀猪盘话术","policy_code":"builtin.fraud_detect.5b7e940a2a8800b2","capability_categories":["fraud_pig_butchering"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"虚假中奖信息","policy_code":"builtin.fraud_detect.e6509942afa78488","capability_categories":["fraud_fake_prize"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"虚假众筹文案","policy_code":"builtin.fraud_detect.5924fd3912c0e21c","capability_categories":["fraud_crowdfunding"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"虚假投资平台","policy_code":"builtin.fraud_detect.e8c52e0bae177488","capability_categories":["fraud_fake_investment_platform"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"虚假投资话术","policy_code":"builtin.fraud_detect.85094af4238a5149","capability_categories":["fraud_investment_pitch"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"虚假招聘诈骗","policy_code":"builtin.fraud_detect.193da7504db91d7c","capability_categories":["fraud_recruitment"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"虚假购物网站","policy_code":"builtin.fraud_detect.5fdc9f9c064a22a1","capability_categories":["fraud_fake_shop"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"虚假贷款推广","policy_code":"builtin.fraud_detect.98e22b1a3a71ca52","capability_categories":["fraud_loan"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"退款诈骗话术","policy_code":"builtin.fraud_detect.8515194cb5e180de","capability_categories":["fraud_refund"],"binding_mode":"any"},
  {"rule_type":"fraud_detect","name":"钓鱼邮件生成","policy_code":"builtin.fraud_detect.31114886164ee6ac","capability_categories":["fraud_phishing_email"],"binding_mode":"any"},
  {"rule_type":"illegal_trade","name":"人体器官交易","policy_code":"builtin.illegal_trade.2baa4f43c99678c0","capability_categories":["illegal_organ_trade"],"binding_mode":"any"},
  {"rule_type":"illegal_trade","name":"人口贩卖内容","policy_code":"builtin.illegal_trade.b42c9e2d1d6a1cdb","capability_categories":["illegal_human_trafficking"],"binding_mode":"any"},
  {"rule_type":"illegal_trade","name":"假冒证件制作","policy_code":"builtin.illegal_trade.41681caad5e30153","capability_categories":["illegal_forged_document"],"binding_mode":"any"},
  {"rule_type":"illegal_trade","name":"假货制造指导","policy_code":"builtin.illegal_trade.17afa89cca4e8954","capability_categories":["illegal_counterfeit_goods"],"binding_mode":"any"},
  {"rule_type":"illegal_trade","name":"处方药违规销售","policy_code":"builtin.illegal_trade.3a11e5702d46e089","capability_categories":["illegal_prescription_drug_trade"],"binding_mode":"any"},
  {"rule_type":"illegal_trade","name":"毒品交易引导","policy_code":"builtin.illegal_trade.103b0604b9ae8e51","capability_categories":["illegal_drug_trade"],"binding_mode":"any"},
  {"rule_type":"illegal_trade","name":"走私方法咨询","policy_code":"builtin.illegal_trade.5ed755f877e035f9","capability_categories":["illegal_smuggling"],"binding_mode":"any"},
  {"rule_type":"illegal_trade","name":"违禁品交易引导","policy_code":"builtin.illegal_trade.36d483957d6bc246","capability_categories":["illegal_contraband_trade"],"binding_mode":"any"},
  {"rule_type":"illegal_trade","name":"野生动物交易","policy_code":"builtin.illegal_trade.3f55b904e1900e0d","capability_categories":["illegal_wildlife_trade"],"binding_mode":"any"},
  {"rule_type":"illegal_trade","name":"非法武器交易","policy_code":"builtin.illegal_trade.b5eab46d920f0a59","capability_categories":["illegal_weapon_trade"],"binding_mode":"any"},
  {"rule_type":"illegal_trade","name":"黑市交易引导","policy_code":"builtin.illegal_trade.4f6d018cc6d7ee00","capability_categories":["illegal_black_market"],"binding_mode":"any"}
]
$runtime_policy_bindings$::jsonb
) AS item(
    policy_code TEXT,rule_type TEXT,name TEXT,
    capability_categories JSONB,binding_mode TEXT
);

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode,priority,config_json)
SELECT r.id,c.id,b.binding_mode,0,'{}'::jsonb
FROM migration_159_bindings b
JOIN rules r ON r.policy_code=b.policy_code
CROSS JOIN LATERAL jsonb_array_elements_text(b.capability_categories) category(value)
JOIN security_capabilities c ON c.category=category.value
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

COMMIT;
