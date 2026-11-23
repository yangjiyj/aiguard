-- Migration: 068_industry_data_security_packs
-- Purpose: 行业预置数据安全规则包（通用 PII / 医疗影像 / 金融）+ 数据分级（L1–L4）
-- Part of: 轨道3 内容和数据安全可按客户行业自定义
--
-- 设计要点：
--   * 双轴扩展——tenants/rule_sets 各加 industry 列；租户行业驱动「叠加哪些内置包」。
--   * 内置包挂在保留系统租户 tenant_system 名下（rule_sets.tenant_id NOT NULL 外键）；
--     编译期（buildCompilableRulesQuery）按 industry∈{generic,本租户行业} 过滤，引擎保持无状态。
--   * 分级写在 scope_json.data_level（L1–L4），编译器原样透传，无需改 schema。
--   * match_config 仅用 {regex|keywords|field_names}（旧 {"patterns":[…]} 不编译会被跳过）。
--   * 所有正则 ReDoS 安全：OID 风格 UID 一律用 keywords/field_names，不写贪婪嵌套量词。
--   * action 一律 audit（留存放行，保证网页大模型仍可正常响应；客户后续可自行升级为 block）。
-- 幂等：ADD COLUMN IF NOT EXISTS / CREATE INDEX IF NOT EXISTS / ON CONFLICT DO NOTHING。

-- 1) 双轴扩展：行业列
ALTER TABLE tenants   ADD COLUMN IF NOT EXISTS industry VARCHAR(64) NOT NULL DEFAULT 'generic';
ALTER TABLE rule_sets ADD COLUMN IF NOT EXISTS industry VARCHAR(64) NOT NULL DEFAULT 'generic';
CREATE INDEX IF NOT EXISTS idx_rule_sets_industry ON rule_sets(industry);

-- 2) 承载内置预置包的保留系统租户（rule_sets.tenant_id 是 NOT NULL 外键）
INSERT INTO tenants (id, name, edition, status, industry)
VALUES ('tenant_system', '系统内置', 'cloud', 'active', 'generic')
ON CONFLICT (id) DO NOTHING;

-- 3) 三套预置规则集（builtin + published）
INSERT INTO rule_sets (id, tenant_id, name, version, source_type, published, industry, created_by)
VALUES
  ('ruleset_builtin_generic',  'tenant_system', '通用数据安全（PII）', '1.0', 'builtin', TRUE, 'generic',         'system'),
  ('ruleset_builtin_medical',  'tenant_system', '医疗影像数据安全',     '1.0', 'builtin', TRUE, 'medical_imaging', 'system'),
  ('ruleset_builtin_finance',  'tenant_system', '金融数据安全',         '1.0', 'builtin', TRUE, 'finance',         'system')
ON CONFLICT (id) DO NOTHING;

-- 4) 通用 PII 规则（generic）——所有租户恒挂载
INSERT INTO rules (id, rule_set_id, rule_type, name, priority, severity, scope_json, match_config_json, action, enabled, description)
VALUES
  ('rule_g_idcard', 'ruleset_builtin_generic', 'pii', '身份证号', 100, 'high',
   '{"data_level":"L4"}',
   '{"regex":"[1-9]\\d{5}(18|19|20)\\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\\d|3[01])\\d{3}[0-9Xx]","category":"pii_idcard"}',
   'audit', TRUE, '中国大陆 18 位身份证号'),
  ('rule_g_phone', 'ruleset_builtin_generic', 'pii', '手机号', 90, 'medium',
   '{"data_level":"L3"}',
   '{"regex":"1[3-9]\\d{9}","category":"pii_phone"}',
   'audit', TRUE, '中国大陆手机号'),
  ('rule_g_bankcard', 'ruleset_builtin_generic', 'pii', '银行卡号', 95, 'high',
   '{"data_level":"L4"}',
   '{"regex":"[1-9]\\d{15,18}","category":"pii_bankcard"}',
   'audit', TRUE, '银行卡/借记贷记卡号（16-19 位）'),
  ('rule_g_email', 'ruleset_builtin_generic', 'pii', '电子邮箱', 80, 'low',
   '{"data_level":"L2"}',
   '{"regex":"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}","category":"pii_email"}',
   'audit', TRUE, '电子邮箱地址'),
  ('rule_g_passport', 'ruleset_builtin_generic', 'pii', '护照号', 85, 'high',
   '{"data_level":"L4"}',
   '{"regex":"[EeGgPpSsDdHhKk]\\d{8}","category":"pii_passport"}',
   'audit', TRUE, '中国普通护照号')
ON CONFLICT (id) DO NOTHING;

-- 5) 医疗影像规则（medical_imaging）——医疗客户在 generic 之上叠加
INSERT INTO rules (id, rule_set_id, rule_type, name, priority, severity, scope_json, match_config_json, action, enabled, description)
VALUES
  ('rule_m_mrn', 'ruleset_builtin_medical', 'field_name', '病历号/住院号/门诊号', 100, 'high',
   '{"data_level":"L4"}',
   '{"field_names":["病历号","住院号","门诊号","就诊卡号","patient_id","mrn","medical_record_no"],"keywords":["病历号","住院号","门诊号"],"category":"medical_record_id"}',
   'audit', TRUE, '患者主索引/病案标识'),
  ('rule_m_ssc', 'ruleset_builtin_medical', 'keyword', '社保卡/医保卡号', 90, 'high',
   '{"data_level":"L4"}',
   '{"keywords":["社保卡","医保卡","社会保障卡"],"field_names":["social_security_card","medical_insurance_no"],"category":"medical_insurance_id"}',
   'audit', TRUE, '社保/医保卡标识'),
  ('rule_m_accession', 'ruleset_builtin_medical', 'field_name', 'DICOM Accession Number', 95, 'high',
   '{"data_level":"L4"}',
   '{"field_names":["AccessionNumber","accession_number"],"keywords":["Accession Number","检查号"],"category":"medical_dicom_accession"}',
   'audit', TRUE, 'DICOM 检查流水号'),
  ('rule_m_studyuid', 'ruleset_builtin_medical', 'field_name', 'DICOM Study/Series UID', 95, 'high',
   '{"data_level":"L4"}',
   '{"field_names":["StudyInstanceUID","SeriesInstanceUID","SOPInstanceUID"],"keywords":["Study Instance UID","Series Instance UID"],"category":"medical_dicom_uid"}',
   'audit', TRUE, 'DICOM 唯一标识（OID 风格，用字段名/关键词识别避免 ReDoS）'),
  ('rule_m_diagnosis', 'ruleset_builtin_medical', 'keyword', '诊断结果', 80, 'medium',
   '{"data_level":"L4"}',
   '{"keywords":["诊断结果","病理诊断","诊断证明","影像所见","印象诊断"],"field_names":["diagnosis","impression"],"category":"medical_diagnosis"}',
   'audit', TRUE, '诊断/病理/影像结论文本'),
  ('rule_m_device', 'ruleset_builtin_medical', 'field_name', '影像设备序列号', 70, 'low',
   '{"data_level":"L2"}',
   '{"field_names":["DeviceSerialNumber","device_serial_number"],"keywords":["设备序列号"],"category":"medical_device_serial"}',
   'audit', TRUE, '成像设备序列号')
ON CONFLICT (id) DO NOTHING;

-- 6) 金融规则（finance）
INSERT INTO rules (id, rule_set_id, rule_type, name, priority, severity, scope_json, match_config_json, action, enabled, description)
VALUES
  ('rule_f_uscc', 'ruleset_builtin_finance', 'regex', '统一社会信用代码', 90, 'medium',
   '{"data_level":"L3"}',
   '{"regex":"[0-9A-HJ-NPQRTUWXY]{18}","category":"finance_uscc"}',
   'audit', TRUE, '法人统一社会信用代码（18 位）'),
  ('rule_f_account', 'ruleset_builtin_finance', 'keyword', '银行账户/开户行', 85, 'high',
   '{"data_level":"L4"}',
   '{"keywords":["开户行","银行账户","对公账户","账户名","账号"],"field_names":["bank_account","account_no","opening_bank"],"category":"finance_account"}',
   'audit', TRUE, '对公/对私银行账户信息'),
  ('rule_f_txn', 'ruleset_builtin_finance', 'field_name', '交易流水号', 70, 'low',
   '{"data_level":"L2"}',
   '{"field_names":["transaction_id","txn_no","trade_no","serial_no"],"keywords":["交易流水号","交易流水"],"category":"finance_txn"}',
   'audit', TRUE, '交易/支付流水标识')
ON CONFLICT (id) DO NOTHING;
