"""训练语料扫描的类型中文名。

内容必须与控制台 apps/web-console/src/utils/risk.ts 的 RISK_CATEGORY_LABELS 一致，
tests/test_corpus_scan.py 会解析 risk.ts 逐项比对，并检查扫描器可能产出的每个类型都有中文名。
脱敏副本里的替换文本就是 `[中文名]`，例如 `[身份证号]`。
"""
from __future__ import annotations

CORPUS_LABELS: dict[str, str] = {
    # 内置个人信息（engine._detect_regex_pii）
    "phone_cn": "手机号",
    "id_card_cn": "身份证号",
    "bank_card_cn": "银行卡号",
    "email": "邮箱地址",
    # 内置密钥（engine._detect_secrets）
    "aws_access_key": "敏感凭据泄露",
    "aws_secret_key": "敏感凭据泄露",
    "github_token": "敏感凭据泄露",
    "generic_api_key": "敏感凭据泄露",
    "jwt_token": "敏感凭据泄露",
    "openai_key": "敏感凭据泄露",
    "anthropic_key": "敏感凭据泄露：Anthropic 密钥",
    # sensitive_data 检测器
    "passport_cn": "护照号码",
    "hk_macao_taiwan_id": "港澳台居民证件",
    "officer_id_cn": "军警人员证件",
    "driver_license_cn": "驾驶证号码",
    "social_security_cn": "社会保障卡号",
    "home_address_cn": "家庭住址",
    "ip_address": "IP 地址",
    "birth_date": "出生日期",
    "communication_record": "通信记录",
    "gps_location": "GPS 位置数据",
    "plain_password": "明文密码",
    "cloud_credential": "云平台凭据",
    "credit_card_cvv": "信用卡安全码",
    "bank_statement": "银行流水",
    "insurance_info": "保险与理赔信息",
    "medical_record": "医疗病历",
    "genetic_data": "基因数据",
    "biometric_data": "生物特征数据",
    "internal_project_code": "内部项目代号",
    "sensitive_code": "敏感源代码",
    "education_background": "教育背景",
    "criminal_record": "犯罪与刑事记录",
    # data_leak 检测器（category = <大类>_<type>）
    "classified_classified_cn": "涉密标识外发（中文）",
    "classified_classified_en": "涉密标识外发（英文）",
    "sensitive_file_internal_doc": "内部文档外发",
    "sensitive_file_customer_data": "客户资料外发",
    "sensitive_file_hr_data": "HR 数据外发",
    "sensitive_file_financial_data": "财务数据外发",
    "code_leak_password_in_code": "代码中的明文密码",
    "code_leak_access_key": "代码中的访问密钥",
    "code_leak_database_url": "数据库连接串外泄",
    "code_leak_api_key_leak": "代码中的 API 密钥",
    "code_leak_token_leak": "代码中的令牌泄露",
    "code_leak_cloud_credential": "云平台凭据外泄",
    # 租户自定义规则未命名时的兜底
    "custom": "客户敏感数据",
}

FALLBACK_LABEL = CORPUS_LABELS["custom"]


def corpus_label(category: str) -> str:
    return CORPUS_LABELS.get(category, FALLBACK_LABEL)
