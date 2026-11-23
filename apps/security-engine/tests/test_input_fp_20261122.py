"""2026-11-22 用户口径：以不误报为先，只看员工输入和模型输出。

这里钉住员工输入里几类基线遗留的误报，以及对应的真命中不能丢。
"""
import pytest

from app import feature_flags
from app.detectors.engine import SecurityEngine


@pytest.fixture(scope="module")
def engine():
    patch = pytest.MonkeyPatch()
    patch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
    patch.setenv("SECURITY_PII_CHECKSUM_ENABLED", "true")
    patch.setenv("SECURITY_PII_CHECKSUM_DROP_INVALID", "true")
    try:
        feature_flags.apply_overrides({})
        yield SecurityEngine()
    finally:
        patch.undo()


def _cats(engine, text, agent="claude-code"):
    result = engine.check_input(
        "fp1122", text, context={"agent_type": agent}, agent_type=agent,
        content_source="user", skip_semantic=True,
    )
    return {f.category for f in result.findings if f.counts_as_security_finding is not False}


CLASSIFIED_EN_NOISE = [
    "**机密**计算（confidential computing）是什么？给我一份资料",
    "帮我整理一份 Confidential Computing 和 confidential VM 的对比文档",
    "/*\n * Copyright 2026 Example Corp. All rights reserved.\n * This file is proprietary and confidential to Example Corp.\n */\npackage app",
    "# Copyright (c) Example Corp.\n# Proprietary and confidential. Unauthorized copying of this file is prohibited.\nimport os",
    "数据分级取值：\nCONFIDENTIAL\nPUBLIC\nINTERNAL",
    "enum DataLevel { PUBLIC, INTERNAL, CONFIDENTIAL, RESTRICTED }  // 数据分级，写进文档",
]


@pytest.mark.parametrize("text", CLASSIFIED_EN_NOISE)
def test_classified_en_noise_not_flagged(engine, text):
    assert not {c for c in _cats(engine, text) if c.startswith("classified")}


@pytest.mark.parametrize("text", [
    "STRICTLY CONFIDENTIAL\nBoard minutes",
    "CONFIDENTIAL - DO NOT DISTRIBUTE\nProject roadmap",
    "This document is confidential, please review the attached contract",
    "# COMPANY CONFIDENTIAL - PROPRIETARY\n2027 pricing",
])
def test_classified_en_marker_still_detected(engine, text):
    assert {c for c in _cats(engine, text, agent="") if c.startswith("classified")}


@pytest.mark.parametrize("text", [
    "review 一下：user.password = request.form['password'] 之后直接 save 了，是不是应该先 bcrypt？",
    "password = os.environ[\"DB_PASSWORD\"]",
    "pwd = getpass.getpass(\"Password: \")",
    "password = hash_password(form.password.data)",
])
def test_password_expression_is_not_hardcoded(engine, text):
    assert "code_leak_password_in_code" not in _cats(engine, text)


@pytest.mark.parametrize("text", [
    "password = \"Xk9#mP2$vL8qRt\"",
    "DB_PASSWORD=Xk9#mP2$vL8qRt",
])
def test_password_literal_still_detected(engine, text):
    assert _cats(engine, text) & {"code_leak_password_in_code", "plain_password"}


@pytest.mark.parametrize("text", [
    "安全码 2026 是活动口令，订单号 4111111111111111",
    "流水号：4111111111111111 这笔为什么对不上",
    "order_id=4111111111111111 查不到物流",
    "tracking no 4111111111111111",
])
def test_labelled_serial_number_is_not_bank_card(engine, text):
    assert "bank_card_cn" not in _cats(engine, text)


@pytest.mark.parametrize("text", [
    "卡号 4111111111111111",
    "银行卡：4111111111111111，帮我填进报销单",
    "4111111111111111 是我的工资卡",
])
def test_bank_card_still_detected(engine, text):
    assert "bank_card_cn" in _cats(engine, text)
