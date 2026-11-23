-- Complete the customer-visible 31-item sensitive-data catalog with executable
-- detector capabilities. This migration is idempotent and preserves an
-- administrator's existing enabled/disabled choice on rerun.

BEGIN;

CREATE TEMP TABLE migration_154_sensitive_capabilities (
    category TEXT NOT NULL,
    name TEXT NOT NULL,
    component TEXT NOT NULL,
    supported_stages JSONB NOT NULL,
    allowed_actions JSONB NOT NULL,
    mask_capable BOOLEAN NOT NULL
) ON COMMIT DROP;

INSERT INTO migration_154_sensitive_capabilities
SELECT category,name,component,supported_stages,builtin_actions,mask_capable
FROM jsonb_to_recordset(
$sensitive_data_capabilities$
[
  {"category":"passport_cn","name":"中国护照号码","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"hk_macao_taiwan_id","name":"港澳台居民证件号码","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"officer_id_cn","name":"军警人员证件号码","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"driver_license_cn","name":"中国驾驶证号码","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"social_security_cn","name":"中国社会保障卡号码","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"home_address_cn","name":"中国家庭住址","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"ip_address","name":"IP 地址","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"birth_date","name":"个人出生日期","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"communication_record","name":"个人通信记录","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"gps_location","name":"GPS 经纬度位置","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"plain_password","name":"明文登录密码","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"cloud_credential","name":"云平台访问凭据","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"credit_card_cvv","name":"信用卡安全码","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"bank_statement","name":"银行账户流水明细","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"insurance_info","name":"保险保单与理赔信息","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"medical_record","name":"医疗病历与诊疗记录","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"genetic_data","name":"基因与核酸序列数据","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"biometric_data","name":"生物特征模板数据","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"internal_project_code","name":"企业内部项目代号","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"sensitive_code","name":"企业敏感源代码片段","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"education_background","name":"个人教育背景信息","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true},
  {"category":"criminal_record","name":"个人犯罪与刑事记录","component":"security-engine.sensitive-data","supported_stages":["input","output"],"builtin_actions":["audit","mask","block"],"mask_capable":true}
]
$sensitive_data_capabilities$::jsonb
) AS item(
    category TEXT,
    name TEXT,
    component TEXT,
    supported_stages JSONB,
    builtin_actions JSONB,
    mask_capable BOOLEAN
);

INSERT INTO security_capabilities(
    id,category,name,capability_kind,component,selector_json,
    supported_stages,allowed_actions,mask_capable,enabled,metadata_json
)
SELECT
    'cap.static.' || category, category, name, 'static', component,
    jsonb_build_object('category',category), supported_stages, allowed_actions,
    mask_capable, TRUE, '{"catalog":"sensitive_data_complete","catalog_version":1}'::jsonb
FROM migration_154_sensitive_capabilities
ON CONFLICT (category) DO UPDATE SET
    name=EXCLUDED.name,
    capability_kind=EXCLUDED.capability_kind,
    component=EXCLUDED.component,
    selector_json=EXCLUDED.selector_json,
    supported_stages=EXCLUDED.supported_stages,
    allowed_actions=EXCLUDED.allowed_actions,
    mask_capable=EXCLUDED.mask_capable,
    metadata_json=EXCLUDED.metadata_json;

CREATE TEMP TABLE migration_154_sensitive_bindings (
    policy_code TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    name TEXT NOT NULL,
    capability_categories JSONB NOT NULL,
    binding_mode TEXT NOT NULL
) ON COMMIT DROP;

INSERT INTO migration_154_sensitive_bindings
SELECT policy_code,rule_type,name,capability_categories,binding_mode
FROM jsonb_to_recordset(
$sensitive_data_policy_bindings$
[
  {"rule_type":"data_leak","name":"护照号检测","policy_code":"builtin.data_leak.2348426d637af519","capability_categories":["passport_cn"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"港澳台证件检测","policy_code":"builtin.data_leak.63ae19f7cd1834bf","capability_categories":["hk_macao_taiwan_id"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"军官证检测","policy_code":"builtin.data_leak.9a6811b786b7618f","capability_categories":["officer_id_cn"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"驾驶证检测","policy_code":"builtin.data_leak.86c5bbeff12d7c44","capability_categories":["driver_license_cn"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"社保卡号检测","policy_code":"builtin.data_leak.e18afae0f9594164","capability_categories":["social_security_cn"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"家庭地址检测","policy_code":"builtin.data_leak.aa6a72765f3d1d2b","capability_categories":["home_address_cn"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"IP 地址检测","policy_code":"builtin.data_leak.0cce2cce8b7bc217","capability_categories":["ip_address"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"出生日期检测","policy_code":"builtin.data_leak.b37eae3f56e3d8f4","capability_categories":["birth_date"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"通信记录检测","policy_code":"builtin.data_leak.3512cd70e182c979","capability_categories":["communication_record"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"位置/GPS 数据","policy_code":"builtin.data_leak.a9ac5ee3d220e157","capability_categories":["gps_location"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"密码明文检测","policy_code":"builtin.data_leak.98cc238bfbf6babb","capability_categories":["plain_password","code_leak_password_in_code"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"AWS/GCP 凭据检测","policy_code":"builtin.data_leak.4cf7caaec6252ac7","capability_categories":["cloud_credential","aws_access_key","aws_secret_key","code_leak_cloud_credential"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"信用卡CVV检测","policy_code":"builtin.data_leak.afa8b93679b66cb2","capability_categories":["credit_card_cvv"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"银行流水检测","policy_code":"builtin.data_leak.d85734a727cce7b8","capability_categories":["bank_statement"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"保险信息检测","policy_code":"builtin.data_leak.7399a414eb30dbb9","capability_categories":["insurance_info"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"医疗记录检测","policy_code":"builtin.data_leak.cd7cd3f962c8a7c1","capability_categories":["medical_record"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"基因数据检测","policy_code":"builtin.data_leak.f21dc3ac3d94c0f3","capability_categories":["genetic_data"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"生物特征检测","policy_code":"builtin.data_leak.65f151cdf48b5404","capability_categories":["biometric_data"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"内部项目代号检测","policy_code":"builtin.data_leak.e40d55f61d111133","capability_categories":["internal_project_code"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"敏感代码片段检测","policy_code":"builtin.data_leak.85d7d239c670bab5","capability_categories":["sensitive_code"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"教育背景检测","policy_code":"builtin.data_leak.55e2d913ee8746b4","capability_categories":["education_background"],"binding_mode":"any"},
  {"rule_type":"data_leak","name":"犯罪记录检测","policy_code":"builtin.data_leak.1a873ce1a4f5e91e","capability_categories":["criminal_record"],"binding_mode":"any"}
]
$sensitive_data_policy_bindings$::jsonb
) AS item(
    policy_code TEXT,
    rule_type TEXT,
    name TEXT,
    capability_categories JSONB,
    binding_mode TEXT
);

INSERT INTO rule_capability_bindings(rule_id,capability_id,binding_mode)
SELECT DISTINCT r.id,c.id,b.binding_mode
FROM migration_154_sensitive_bindings b
JOIN rules r ON r.policy_code=b.policy_code AND r.rule_type=b.rule_type AND r.name=b.name
CROSS JOIN LATERAL jsonb_array_elements_text(b.capability_categories) category(value)
JOIN security_capabilities c ON c.category=category.value
ON CONFLICT (rule_id,capability_id) DO UPDATE SET binding_mode=EXCLUDED.binding_mode;

DO $$
DECLARE
    capability_count INTEGER;
    bound_policy_count INTEGER;
    existing_policy_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO capability_count
    FROM security_capabilities c
    JOIN migration_154_sensitive_capabilities expected ON expected.category=c.category;
    IF capability_count <> 22 THEN
        RAISE EXCEPTION 'sensitive-data capability catalog incomplete: %', capability_count;
    END IF;

    SELECT COUNT(DISTINCT r.policy_code) INTO existing_policy_count
    FROM rules r
    JOIN migration_154_sensitive_bindings expected ON expected.policy_code=r.policy_code;

    SELECT COUNT(DISTINCT r.policy_code) INTO bound_policy_count
    FROM rules r
    JOIN migration_154_sensitive_bindings expected ON expected.policy_code=r.policy_code
    JOIN rule_capability_bindings binding ON binding.rule_id=r.id;
    IF bound_policy_count <> existing_policy_count THEN
        RAISE EXCEPTION 'sensitive-data policy binding incomplete: bound=% existing=%',
            bound_policy_count, existing_policy_count;
    END IF;
END $$;

COMMIT;
