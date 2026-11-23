"""同值/同预览号码的第二处写法变体也必须脱敏（集成审查 B1）。

去重按 (type, category, 预览) 合并 pii 命中，脱敏兜底此前只用字面正则找"其它出现"，
认不出分隔符/全角/零宽写法，第二处变体原样发往上游。修复后脱敏对数字类 PII 重新跑
find_numeric_pii，同类别所有候选区间一起替换。
"""
import base64
import io
import re
import unicodedata
import zipfile

import pytest

from app import feature_flags as ff
from app.detectors.engine import SecurityEngine  # 先导入引擎，避免 custom_rules 循环导入
from app.custom_rules import CompiledRule
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet, RedactionSettings

TAGS = {"phone_cn": "[手机号]", "bank_card_cn": "[银行卡]", "id_card_cn": "[身份证]"}
DOCX = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"


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


def _digits(text):
    return re.sub(r"\D", "", unicodedata.normalize("NFKC", text))


ZW = "\u200b"

CASES = [
    ("手机 13800138000，备用 138-0013-8000", "手机 [手机号]，备用 [手机号]"),
    ("手机 138-0013-8000，备用 13800138000", "手机 [手机号]，备用 [手机号]"),
    ("138 0013 8000 / 138 0013 8000", "[手机号] / [手机号]"),
    ("联系 138-0013-8000 或 139-1234-5600", "联系 [手机号] 或 [手机号]"),
    ("联系 13800138000 或 139-1234-5600", "联系 [手机号] 或 [手机号]"),
    ("电话 １３８００１３８０００ 和 １３８００１３８０００", "电话 [手机号] 和 [手机号]"),
    ("电话 １３８００１３８０００，１３９１２３４５６００", "电话 [手机号]，[手机号]"),
    (f"电话 138{ZW}0013{ZW}8000，再说一遍 138{ZW}0013{ZW}8000", "电话 [手机号]，再说一遍 [手机号]"),
    ("卡号 6222 0212 3456 7890 128，再确认 6222-0212-3456-7890-128", "卡号 [银行卡]，再确认 [银行卡]"),
    ("卡号 6222 0212 3456 7890 128，再确认 6222 0212 3456 7890 128", "卡号 [银行卡]，再确认 [银行卡]"),
    ("身份证 110101 19900307 1233，复核 110101 19900307 1233", "身份证 [身份证]，复核 [身份证]"),
    ("身份证 110101199003071233，复核 110101-19900307-1233", "身份证 [身份证]，复核 [身份证]"),
]


@pytest.mark.parametrize("text, expected", CASES)
@pytest.mark.parametrize("stage", ["input", "output"])
def test_same_value_or_same_preview_variants_are_all_masked(engine, text, expected, stage):
    if stage == "input":
        result = engine.check_input("req-b1", text, skip_semantic=True)
    else:
        result = engine.check_output("req-b1", text)
    assert result.action == "mask", [(f.category, f.matched_location) for f in result.findings]
    assert result.masked_content == expected
    assert _digits(result.masked_content) == ""


def _docx(text: str) -> bytes:
    ns = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
    body = f'<w:body xmlns:w="{ns}"><w:p><w:r><w:t>{text}</w:t></w:r></w:p></w:body>'
    doc = f'<?xml version="1.0"?><w:document xmlns:w="{ns}">{body}</w:document>'
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="xml" ContentType="text/xml"/></Types>',
        )
        archive.writestr("word/document.xml", doc)
    return buf.getvalue()


@pytest.mark.parametrize("attachment", ["备用 138-0013-8000", "备用 138 0013 8000", "备用 １３８００１３８０００"])
def test_same_value_variant_in_attachment_is_flagged_unmaskable(monkeypatch, attachment):
    monkeypatch.setenv(ff.ENV_FILE_CONTENT_DLP, "true")
    monkeypatch.setenv(ff.ENV_PII_CHECKSUM, "true")
    eng = SecurityEngine()
    eng.load_file_policy({"content_dlp_enabled": True})
    eng.load_policies(PolicySet([_policy("phone_cn", "[手机号]")]))
    ctx = {"tenant_id": "t1", "attachments": [{
        "file_name": "a.docx", "content_type": DOCX,
        "data_base64": base64.b64encode(_docx(attachment)).decode(),
    }]}
    result = eng.check_input("req-b1-file", "手机号13800138000", context=ctx)
    assert result.action == "mask"
    assert result.masked_content == "手机号[手机号]"
    attachment_masks = [f for f in result.findings
                        if f.action == "mask" and f.content_source == "file_attachment"]
    assert attachment_masks, [(f.category, f.content_source, f.matched_location) for f in result.findings]
    assert all(f.triage.get("mask_unavailable") for f in attachment_masks)


@pytest.mark.parametrize("rule_type, matcher, content", [
    ("keyword", {"keywords": ["玄武网关"]}, "玄武网关 手机 13800138000，备用 138-0013-8000"),
    ("field_name", {"field_names": ["password"]}, 'password: "x"，手机 13800138000'),
])
def test_unlocatable_custom_mask_does_not_stop_other_masks(engine, rule_type, matcher, content):
    """自定义关键字/字段名的"脱敏"无法安全替换：只对它告警，同消息里的号码照常脱敏。"""
    unsafe = CompiledRule.model_construct(
        rule_id="rule_unsafe_mask", rule_name="unsafe mask", rule_type=rule_type,
        category="custom_unsafe_mask", severity="high", action="mask", enabled=True,
        regex=None, keywords=matcher.get("keywords"), field_names=matcher.get("field_names"),
        scope={},
    )
    eng = SecurityEngine()
    eng.pii_checksum_enabled = True
    eng.load_policies(PolicySet([_policy("phone_cn", "[手机号]")]))
    eng.load_custom_rules([unsafe])
    for result in (eng.check_input("req-b1-kw", content, skip_semantic=True),
                   eng.check_output("req-b1-kw", content)):
        assert result.action == "mask"
        assert "13800138000" not in _digits(result.masked_content)
        assert "[手机号]" in result.masked_content
        custom = [f for f in result.findings if f.rule_id == "rule_unsafe_mask"]
        assert custom and all(f.triage.get("mask_unavailable") for f in custom)
        phones = [f for f in result.findings if f.category == "phone_cn"]
        assert phones and not any(f.triage.get("mask_unavailable") for f in phones)
