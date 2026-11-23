import pytest

from app.detectors.engine import SecurityEngine
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet


SENSITIVE_DATA_CASES = [
    ("phone_cn", "联系电话：13812345678"),
    ("id_card_cn", "身份证号：11010519491231002X"),
    ("passport_cn", "护照号：E12345678"),
    ("hk_macao_taiwan_id", "香港身份证：A123456(3)"),
    ("officer_id_cn", "军官证号：军字第12345678号"),
    ("driver_license_cn", "驾驶证号：11010519491231002X"),
    ("social_security_cn", "社保卡号：11010519491231002X"),
    ("email", "邮箱：security@example.com"),
    ("home_address_cn", "家庭住址：上海市浦东新区世纪大道88号1201室"),
    ("ip_address", "客户端 IP：192.168.10.24"),
    ("birth_date", "出生日期：1990-06-15"),
    ("communication_record", "通话记录：2026-08-27 10:30 与 13812345678 通话 120 秒"),
    ("gps_location", "GPS 坐标：31.2304,121.4737"),
    ("generic_api_key", "api_key = AbC9xY7mN2pQ5rT8vW4z"),
    ("plain_password", "登录密码：N3w-Passw0rd!"),
    ("jwt_token", "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.signature123"),
    ("ssh_private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA"),
    ("openssh_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA"),
    ("cloud_credential", "Azure AccountKey：QWJjRGVmR2hpSmtMbW5PcFFyc1R1VndYeXoxMjM0NTY="),
    ("code_leak_database_url", 'connection = "postgresql://admin:secret@db.example/prod"'),
    ("bank_card_cn", "银行卡号：4111111111111111"),
    ("credit_card_cvv", "信用卡 CVV：123"),
    ("bank_statement", "银行流水：2026-08-26 转账金额 12800.00 元，对方账号 622202******1234"),
    ("insurance_info", "保单号：PICC202608270001，理赔金额 5600 元"),
    ("medical_record", "病历号：MR20260827001，诊断：高血压，处方：氯沙坦"),
    ("genetic_data", "DNA 序列：ACGTACGTTGCAACGTACGTTGCAACGTACGT"),
    ("biometric_data", "指纹模板：A94F20C18B77D903E5A14C86F03B9D12"),
    ("classified_classified_cn", "绝密客户名单文件，禁止外发"),
    ("internal_project_code", "内部项目代号：NOVA-27B"),
    ("sensitive_code", "敏感代码片段：def derive_master_key(seed): return hmac.new(seed, b'root', sha256).digest()"),
    ("education_background", "教育背景：清华大学计算机系硕士研究生"),
    ("criminal_record", "犯罪记录：2021 年因盗窃罪被判处有期徒刑三年"),
]

DEFAULT_MASK_CATEGORIES = {
    "phone_cn", "id_card_cn", "passport_cn", "hk_macao_taiwan_id",
    "officer_id_cn", "driver_license_cn", "social_security_cn", "bank_card_cn",
    "bank_statement", "home_address_cn", "communication_record", "medical_record",
    "biometric_data", "sensitive_code", "criminal_record", "insurance_info",
}


@pytest.fixture
def engine():
    return SecurityEngine()


@pytest.mark.parametrize(("category", "content"), SENSITIVE_DATA_CASES)
def test_all_sensitive_data_catalog_items_have_executable_detection(engine, category, content):
    result = engine.check_input("req-sensitive-complete", content, skip_semantic=True)
    finding = next((item for item in result.findings if item.category == category), None)

    assert finding is not None, f"missing executable detector for {category}"
    assert finding.matched_location.startswith("content[")
    assert finding.matched_text_preview
    assert finding.raw_evidence not in finding.matched_text_preview


@pytest.mark.parametrize(
    "content",
    [
        "请介绍护照和驾驶证的申请流程，不包含任何真实证件号。",
        "系统支持 IPv4 和 IPv6，示例地址请使用 example.com。",
        "本地服务监听 127.0.0.1:8080，数据库使用 192.168.10.20:5432。",
        "客户端 IP：999.999.999.999",
        "出生日期字段应使用 YYYY-MM-DD 格式。",
        "GPS 坐标是由纬度和经度组成的位置数据。",
        "password = your-password-here",
        "password: z.string().min(8, 'password must be at least 8 chars')",
        "password: Joi.string().required()",
        "CVV 是信用卡背面的安全码，请勿在聊天中发送。",
        "请生成一份不含真实数据的银行流水模板。",
        "这是医疗数据和基因数据保护的政策说明。",
        "项目代号和敏感代码都应纳入企业数据分级。",
        "教育背景和犯罪记录属于个人敏感信息。",
    ],
)
def test_sensitive_data_detector_rejects_policy_discussion_and_placeholders(engine, content):
    result = engine.check_input("req-sensitive-negative", content, skip_semantic=True)
    new_categories = {
        "passport_cn", "hk_macao_taiwan_id", "officer_id_cn", "driver_license_cn",
        "social_security_cn", "home_address_cn", "ip_address", "birth_date",
        "communication_record", "gps_location", "plain_password", "cloud_credential",
        "credit_card_cvv", "bank_statement", "insurance_info", "medical_record",
        "genetic_data", "biometric_data", "internal_project_code", "sensitive_code",
        "education_background", "criminal_record",
    }
    assert new_categories.isdisjoint({item.category for item in result.findings})


def test_openssh_detector_does_not_misclassify_other_private_key_formats(engine):
    result = engine.check_input(
        "req-rsa-private-key",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA",
        skip_semantic=True,
    )

    assert any(item.category == "ssh_private_key" for item in result.findings)
    assert all(item.category != "openssh_private_key" for item in result.findings)


def compiled_policy(category: str, action: str) -> CompiledPolicy:
    return CompiledPolicy(
        policy_code=f"builtin.data_leak.{category}",
        policy_id=f"policy.{category}",
        policy_name=f"{category} policy",
        policy_type="scene_policy",
        scene="data_leak",
        action=action,
        enabled=True,
        binding_mode="any",
        capabilities=[CompiledPolicyCapability(
            category=category,
            supported_stages=["input", "output"],
            allowed_actions=["audit", "mask", "block"],
            mask_capable=True,
        )],
    )


def test_sensitive_data_policy_executes_mask_without_leaking_original():
    detector = SecurityEngine()
    detector.audit_only = False
    detector.load_policies(PolicySet([compiled_policy("passport_cn", "mask")]))

    content = "护照号：E12345678"
    result = detector.check_input("req-passport-mask", content, skip_semantic=True)

    assert result.action == "mask"
    assert result.masked_content is not None
    assert "E12345678" not in result.masked_content
    assert "<MASKED>" in result.masked_content


@pytest.mark.parametrize(
    ("category", "content"),
    [case for case in SENSITIVE_DATA_CASES if case[0] in DEFAULT_MASK_CATEGORIES],
)
def test_default_mask_policy_categories_rewrite_their_sensitive_value(category, content):
    detector = SecurityEngine()
    detector.audit_only = False
    detector.load_policies(PolicySet([compiled_policy(category, "mask")]))

    result = detector.check_input("req-default-mask-category", content, skip_semantic=True)

    assert result.action == "mask"
    assert result.masked_content is not None
    assert result.masked_content != content
    assert "<MASKED>" in result.masked_content


def test_sensitive_data_policy_executes_block():
    detector = SecurityEngine()
    detector.audit_only = False
    detector.load_policies(PolicySet([compiled_policy("credit_card_cvv", "block")]))

    result = detector.check_input("req-cvv-block", "信用卡 CVV：123", skip_semantic=True)

    assert result.action == "block"
    assert any(item.policy_code.endswith("credit_card_cvv") for item in result.findings)


def test_sensitive_data_detector_runs_on_model_output():
    detector = SecurityEngine()
    result = detector.check_output(
        "req-genetic-output",
        "DNA 序列：ACGTACGTTGCAACGTACGTTGCAACGTACGT",
        skip_semantic=True,
    )

    assert any(item.category == "genetic_data" for item in result.findings)
