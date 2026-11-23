"""Replay of 2026-09-21 forward-proxy model outputs that raised alerts on 8793b7417.

Every row is the retained response text of one production request. The only
credential-shaped literals inside are the synthetic controls the recorded test
code itself contains; prose about passwords, i18n labels, quoted code
expressions, escaped decorators, URL userinfo, numeric constants and the common
noun 秘密 are not leaks. Positive controls are generated in-process.
"""
import json
import secrets
from pathlib import Path

import pytest

from app.detectors.config_evidence import read_credential_value, is_prose_value
from app.detectors.data_leak import DataLeakDetector
from app.detectors.engine import SecurityEngine
from app.detectors.pii_checksum import validate_phone_cn_segment

ROWS = json.loads((Path(__file__).parent / "fixtures/credential_replay/production_prose_group.json").read_text())
CREDENTIALS = {"plain_password", "code_leak_password_in_code", "code_leak_database_url"}
SYNTHETIC_CONTROLS = ("RealSynthetic42!pZ", "db.internal")


def counted(text, categories=None):
    result = SecurityEngine().check_output("prose-replay", text, context={"agent_type": "openai-codex", "access_type": "ai_ide"})
    return [f for f in result.raw_findings if f.counts_as_security_finding and (categories is None or f.category in categories)]


@pytest.fixture
def literal():
    return secrets.token_urlsafe(24) + "aA9!"


# ---- full production texts -------------------------------------------------

@pytest.mark.parametrize("row", ROWS, ids=lambda r: r["request_id"][:8])
def test_production_outputs_only_flag_synthetic_credential_controls(row):
    unexpected = [f for f in counted(row["content"], CREDENTIALS)
                  if not any(control in f.raw_evidence for control in SYNTHETIC_CONTROLS)]
    assert not unexpected, [(f.category, f.matched_location, f.raw_evidence[:40]) for f in unexpected]


@pytest.mark.parametrize("row", ROWS, ids=lambda r: r["request_id"][:8])
def test_production_outputs_raise_no_email_phone_or_classified_findings(row):
    hits = counted(row["content"], {"email", "pii_email", "phone_cn", "pii_phone", "classified_classified_cn"})
    assert not hits, [(f.category, f.rule_id, f.matched_location, f.raw_evidence) for f in hits]


# ---- credential value grammar ----------------------------------------------

@pytest.mark.parametrize("text", [
    "- 修复 SSH password: 提示后吞入中文说明。",
    "正则把 `password:` 后面的反引号、中文说明一起当成了“密码值”。这段只是 SSH 等待输入密码的提示，**没有实际密码**。",
    "s.replace(\"  pii_email:\", \"  plain_password: '疑似明文密码', code_leak_password_in_code: '代码中的凭据候选'\")",
    "labels = {plain_password: '疑似明文密码', openai_key: '疑似 OpenAI 密钥'}",
    "密码：请在底部终端中输入密码并回车",
])
def test_prose_after_a_password_label_is_not_a_secret(text):
    assert not counted(text, CREDENTIALS), counted(text, CREDENTIALS)


@pytest.mark.parametrize("text", [
    'password="密码甲乙丙丁戊己"',
    "password: '疑似明文密码'",
])
def test_lone_quoted_cjk_value_is_still_a_literal_candidate(text):
    # Without a sibling label pair this is indistinguishable from a CJK password.
    assert counted(text, CREDENTIALS)


@pytest.mark.parametrize("value,kind", [
    ("疑似明文密码", "prose"),
    ("提示后吞入中文说明", "prose"),
    ("这段只是 SSH 等待输入密码的提示", "prose"),
    ("密码123", "literal"),
    ("abc密码", "literal"),
    ("hunter2!", "literal"),
    ("123456", "literal"),
])
def test_prose_value_grammar_keeps_ascii_bearing_values(value, kind):
    assert read_credential_value("password=" + value, len("password=")).kind == kind
    assert is_prose_value(value) == (kind == "prose")


@pytest.mark.parametrize("field", ["password", "PASSWORD", "db_password"])
def test_cjk_password_without_spaces_is_still_a_literal_candidate(field):
    hits = counted(field + "='我的密码Ab12'", CREDENTIALS)
    assert hits and all("我的密码Ab12" in f.raw_evidence for f in hits)


@pytest.mark.parametrize("text", [
    "命中片段是带多层转义换行的 `PASSWORD=$ADMIN_PASSWORD…WEB_PORT=$WEB_PORT…`；复现 SHA-256 为 642c2241",
    "PASSWORD=$ADMIN_PASSWORD…",
    "password=$env:DB_PASSWORD-suffix",
    "password=%DB_PASSWORD%extra",
])
def test_variable_expansion_followed_by_ellipsis_or_suffix_is_a_reference(text):
    assert not counted(text, CREDENTIALS)


def test_braced_default_value_is_still_a_literal(literal):
    hits = counted("password=${DB_PASSWORD:-" + literal + "}", CREDENTIALS)
    assert hits and any(literal in f.raw_evidence for f in hits)


@pytest.mark.parametrize("text", [
    "把代码拼接表达式 `PASSWORD=' + value + '` 当成密码。",
    "`PASSWORD=\" + value + \"`",
    "`password=' . $name . '`",
    "PASSWORD=' + value",
])
def test_quoted_concatenation_gap_is_source_code_not_a_secret(text):
    assert not counted(text, CREDENTIALS), counted(text, CREDENTIALS)


@pytest.mark.parametrize("value", ["a+b", "+abc", " +a", "x + y"])
def test_operator_bearing_quoted_literals_remain_detectable(value):
    text = "password='" + value + "'"
    assert read_credential_value(text, len("password=")).kind == "literal"


def test_direct_literal_concatenation_after_prose_is_still_detected(literal):
    text = "如上所述 `PASSWORD=' + value + '` 不是密码；但 password='" + literal + "' 是。"
    hits = counted(text, CREDENTIALS)
    assert hits and any(literal in f.raw_evidence for f in hits)
    assert all("+ value +" not in f.raw_evidence for f in hits)


# ---- classified marker syntax ----------------------------------------------

def classified(text):
    return [f for f in DataLeakDetector().detect(text) if f["category"] == "classified_classified_cn"]


@pytest.mark.parametrize("text", [
    "不能靠“看到 password/key”证明存在秘密，也不能靠“位于代码/测试中”豁免真实秘密。应先按协议和语言结构提取具体值。",
    "每个人都有秘密，数据表里也是。",
    "请解释如何防止商业机密被窃取，报告要写清楚。",
    "保守秘密是合同附件里的义务。",
])
def test_common_noun_secrecy_in_prose_is_not_a_classification_marking(text):
    assert not classified(text)


@pytest.mark.parametrize("text", [
    "秘密★10年 本文件包含客户名单",
    "密级：机密。附件为财务数据。",
    "【绝密】客户清单.xlsx",
    "本文件属于秘密级，内含合同数据",
    "这是机密文件，包含客户名单和财务数据",
    "绝密客户名单文件，禁止外发",
    "机密资料：员工工资表",
])
def test_classification_markings_remain_detected(text):
    assert classified(text)


# ---- phone segments and email structure ------------------------------------

@pytest.mark.parametrize("number,valid", [
    ("14236948480", False), ("14012345678", False), ("15412345678", False), ("17912345678", False), ("19412345678", False),
    ("13812345678", True), ("14712345678", True), ("15012345678", True), ("16612345678", True), ("17012345678", True),
    ("18912345678", True), ("19912345678", True),
])
def test_phone_segment_validation_follows_allocated_segments(number, valid):
    assert validate_phone_cn_segment(number) is valid
    hits = counted("联系电话 " + number, {"phone_cn", "pii_phone"})
    assert bool(hits) is valid


def test_numeric_constant_in_unallocated_segment_is_not_a_phone():
    assert not counted("【工具】const total = 14236948480;", {"phone_cn", "pii_phone"})


@pytest.mark.parametrize("text", [
    "s=p.read_text()+'''\\n@pytest.mark.parametrize(\"depth\", range(5))",
    "'\\n@pytest.fixture\\ndef literal():'",
    "dsn='postgres://postgres:test@db.internal/test'",
    "mysql://root:pw@db.corp.example:3306/app",
])
def test_escaped_decorators_and_url_userinfo_are_not_mailboxes(text):
    assert not counted(text, {"email", "pii_email"}), counted(text, {"email", "pii_email"})


@pytest.mark.parametrize("text", [
    "contact: ops@corp.example",
    "'\\nadmin@corp.example'",
    "http://host/path?e=user@corp.example",
    "mailto:someone@corp.example",
])
def test_real_mailboxes_remain_detected(text):
    assert counted(text, {"email", "pii_email"})
