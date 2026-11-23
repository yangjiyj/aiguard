"""数字类 PII 写法变体在代码/日志/日常文本里的误报（集成审查 I3）。

变体识别只接受真正的分组位置：一个号码内分隔符一致；"." 只在有电话类上下文时
作手机号分隔符；号码前紧挨标识符/版本/trace/key=value 时排除；银行卡上下文必须是
完整词（卡号、银行卡、账号……），"显卡/打卡/卡顿"不算。
"""
import pytest

from app import feature_flags as ff
from app.detectors.engine import SecurityEngine
from app.detectors.pii_variants import find_numeric_pii
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet, RedactionSettings

TAGS = {"phone_cn": "[手机号]", "bank_card_cn": "[银行卡]", "id_card_cn": "[身份证]"}


def _policy(category, replacement):
    return CompiledPolicy(
        policy_code=f"test.{category}", policy_id=f"policy-{category}",
        policy_name=category, policy_type="data_leak", scene="data_security",
        severity="high", action="mask", enabled=True, binding_mode="any",
        redaction=RedactionSettings(replacement=replacement),
        capabilities=[CompiledPolicyCapability(
            category=category, supported_stages=["input", "output"],
            allowed_actions=["audit", "mask", "block"], mask_capable=True,
        )],
    )


@pytest.fixture(autouse=True)
def _no_leaked_overrides():
    # 其它用例（如 test_main_lifespan）会把 SECURITY_AUDIT_ONLY 等写进进程级 override 不清理；
    # 本文件按默认配置跑，结束后原样恢复，不改变后续用例看到的状态。
    previous = ff.snapshot_overrides()
    ff.apply_overrides({})
    yield
    ff.apply_overrides(previous)


@pytest.fixture(scope="module")
def engine():
    previous = ff.snapshot_overrides()
    ff.apply_overrides({})
    eng = SecurityEngine()
    ff.apply_overrides(previous)
    eng.pii_checksum_enabled = True
    eng.load_policies(PolicySet([_policy(c, r) for c, r in TAGS.items()]))
    return eng


FALSE_POSITIVES = [
    "v138.0013.8000",
    "版本 v138.0013.8000 已发布",
    "构建号 139.1234.5600",
    "构建号 139.1234.5600 已归档",
    "req-138-0013-8000",
    "trace_id=138-0013-8000",
    "trace_id = 138-0013-8000",
    "key=139 1234 5600",
    "订单 2024-139-1234-5600",
    "订单 2024.139.1234.5600",
    "数据 1380013 8000",
    "数据 138 00138000",
    "号码 138-0013 8000",
    "这个显卡跑分 4173 1752 7506 7299 分",
    "每天打卡 4173 1752 7506 7299 次",
    "卡顿 4173-1752-7506-7299 毫秒",
    "id 110101.19900307.1233",
    "卡号 4111.1111.1111.1111",
    "x_110101-19900307-1233",
]


@pytest.mark.parametrize("text", FALSE_POSITIVES)
def test_code_and_log_numbers_are_not_pii(engine, text):
    assert not find_numeric_pii(text), text
    for result in (engine.check_input("req-i3", text, skip_semantic=True), engine.check_output("req-i3", text)):
        assert not {f.category for f in result.findings} & set(TAGS), text
        assert result.action != "mask", (text, result.masked_content)


STILL_PII = [
    ("电话 138.0013.8000 请回电", "电话 [手机号] 请回电"),
    ("手机：138-0013-8000", "手机：[手机号]"),
    ("phone=138-0013-8000", "phone=[手机号]"),
    ("mobile: 138 0013 8000", "mobile: [手机号]"),
    ("+86 138 0013 8000", "[手机号]"),
    ("银行卡 4111 1111 1111 1111", "银行卡 [银行卡]"),
    ("信用卡：4111-1111-1111-1111", "信用卡：[银行卡]"),
    ("储蓄卡 4111 1111 1111 1111", "储蓄卡 [银行卡]"),
    ("开户 4111 1111 1111 1111", "开户 [银行卡]"),
    ("身份证 110101 1990 0307 1233", "身份证 [身份证]"),
]


@pytest.mark.parametrize("text, expected", STILL_PII)
def test_real_grouped_numbers_are_still_masked(engine, text, expected):
    result = engine.check_input("req-i3-pos", text, skip_semantic=True)
    assert result.action == "mask", [(f.category, f.matched_location) for f in result.findings]
    assert result.masked_content == expected
