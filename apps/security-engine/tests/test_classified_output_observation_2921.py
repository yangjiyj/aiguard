"""2.9.21：网关原生路径声明的模型输出里，密级标记只留证，不拦截、不计入告警。

现场：员工让编码助手给内部项目加“内部专有声明”版权头，写文件的工具调用参数里的 CONFIDENTIAL
被「涉密文件标记检测」（内置 block）拦了两次；助手解释为什么被拦时说到这个词，整条回答又被拦一次。
11-09 另有一次代码回答里的 Level.Confidential 被拦。现场 30 天这条规则真正拦下的 4 次全在网关原生路径的
模型输出方向。

按写法开窄例外历经四轮复查都能被绕过，最后整段收回，改按方向判断。5ae11371 曾把 check_output 的所有密级
命中一律留证，复核确认越界（反代、正代会把文件内容、知识库、会话历史送进输出检查；客户 all 组合、客户自建的
输出侧拦截被覆盖），已收窄：
- 只有网关原生路径声明的模型回答（output_projection=model_text）和判定为本地操作的工具调用参数
  （model_tool_arguments + tool_may_egress=False），且命中来自可放宽的内置密级策略或没有任何策略命中时，
  中英文密级标记才留证（counts_as_security_finding=False、action=allow、disposition=observation）；
  收窄的细则见 test_classified_output_policy_scope_2921.py。
- 不带声明的 check_output 照 2.9.20 判。
- 输入方向（员工发出的消息、未知来源）照 2.9.20 判；客户端提供的历史助手消息（assistant_history）可以
  伪造，不享受这条留证。
- 同一回答里的其他命中（私钥、证件号等）照常处置。
"""
import pytest

from app.detectors.engine import SecurityEngine
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet
from app.principal_context import PrincipalContext

CLASSIFIED = {"classified_classified_cn", "classified_classified_en"}
REASON = "model_output_classified_marker"
BUILTIN_CODE = "builtin.data_leak.17723b156cfa7533"
PRIVATE_KEY_CODE = "builtin.data_leak.a0891acf6ebc39c0"
NATIVE_CONTEXT = {"output_projection": "model_text"}


def _gateway_principal():
    return PrincipalContext(
        schema_version=1, tenant_id="tenant_default", key_id="key-r2921", protocol="openai",
        entry_point="gateway_api", identity_source="api_key", trust_level="key_bound",
    )


def _builtin_classified_policy():
    # 与控制面内置「涉密文件标记检测」一致：high + block，中英两项能力，输入输出两侧。
    return CompiledPolicy(
        policy_code=BUILTIN_CODE, policy_id="policy-classified",
        policy_name="涉密文件标记检测", policy_type="data_leak", scene="data_security",
        severity="high", action="block", enabled=True, binding_mode="any",
        capabilities=[CompiledPolicyCapability(
            category=category, supported_stages=["input", "output"],
            allowed_actions=["audit", "block"], mask_capable=False,
        ) for category in sorted(CLASSIFIED)],
    )


def _builtin_private_key_policy():
    # 与控制面内置「证书/私钥检测」一致的能力绑定，动作取 block。
    return CompiledPolicy(
        policy_code=PRIVATE_KEY_CODE, policy_id="policy-private-key",
        policy_name="证书/私钥检测", policy_type="data_leak", scene="data_security",
        severity="critical", action="block", enabled=True, binding_mode="any",
        capabilities=[CompiledPolicyCapability(
            category="ssh_private_key", supported_stages=["input", "output"],
            allowed_actions=["audit", "block"], mask_capable=False,
        )],
    )


@pytest.fixture(scope="module")
def engine():
    eng = SecurityEngine()
    eng.load_policies(PolicySet([_builtin_classified_policy()]))
    return eng


def _native_output(eng, request_id, text):
    return eng.check_output(request_id, text, context=dict(NATIVE_CONTEXT), skip_semantic=True,
                            principal=_gateway_principal())


# 现场形态：版权头、写文件的工具参数、助手解释拦截原因、代码回答；另加强佐证和中文标记。
OUTPUT_CASES = {
    "license_header": (
        "/*\n * Copyright (c) 2026 Example Semiconductor Co., Ltd. All rights reserved.\n"
        " * CONFIDENTIAL AND PROPRIETARY. This file is for internal use only.\n */\n#include <stdio.h>\n"
    ),
    "write_tool_arguments": (
        "{\"file_path\": \"/repo/src/runner.py\", \"content\": \"# Copyright (c) 2026 Example Corp.\\n"
        "# CONFIDENTIAL AND PROPRIETARY - do not distribute this file.\\nimport os\\n\"}"
    ),
    "assistant_explains_block": (
        "两次拦截的原因是工具调用参数里的 CONFIDENTIAL 字样，它出现在我准备写入每个文件头部的专有声明里。"
    ),
    "code_answer_member_access": (
        "已修改 models.py 文件：\n```python\nif doc.level == Level.Confidential:\n    return deny()\n```"
    ),
    "strong_corroboration": "CONFIDENTIAL - Q3 Financial Reporting Package\nPrepared for the Board of Directors",
    "chinese_marker": "这是机密文件，包含客户名单和财务数据",
    "chinese_marker_level": "密级：秘密，请勿外传此报告",
}

KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\n"
    "aFDrBz9vFqU4yBHt3Qe1vI5x7xmKqXUvL9aGgVZ7MZTkGxJxY7kIaFm9yN0vC4vS\n"
    "-----END RSA PRIVATE KEY-----"
)


def _classified(result):
    return [f for f in result.findings if f.category in CLASSIFIED]


@pytest.mark.parametrize("name", sorted(OUTPUT_CASES))
def test_native_model_output_classified_marker_is_observation(engine, name):
    result = _native_output(engine, "r2921-out", OUTPUT_CASES[name])
    hits = _classified(result)
    assert hits, name
    assert result.action == "allow", [(f.category, f.action) for f in result.findings]
    for finding in hits:
        assert finding.counts_as_security_finding is False
        assert finding.action == "allow"
        assert finding.triage.get("disposition") == "observation"
        assert finding.triage.get("disposition_reason") == REASON
        assert finding.evidence_reason.startswith("留证原因：")


@pytest.mark.parametrize("name", sorted(OUTPUT_CASES))
def test_follow_policy_disposition_blocks_native_output_by_policy(monkeypatch, name):
    # 2.9.22：model_output_classified_disposition=follow_policy 时不再留证，按策略拦。
    monkeypatch.setenv("SECURITY_MODEL_OUTPUT_CLASSIFIED_DISPOSITION", "follow_policy")
    eng = SecurityEngine()
    eng.load_policies(PolicySet([_builtin_classified_policy()]))
    result = _native_output(eng, "r2922-follow", OUTPUT_CASES[name])
    hits = _classified(result)
    assert hits, name
    assert result.action == "block"
    assert all(f.counts_as_security_finding for f in hits)
    assert all(f.triage.get("disposition_reason") != REASON for f in hits)


@pytest.mark.parametrize("value", ["observe", "", "unexpected"])
def test_observe_disposition_is_default_and_fallback(monkeypatch, value):
    monkeypatch.setenv("SECURITY_MODEL_OUTPUT_CLASSIFIED_DISPOSITION", value)
    eng = SecurityEngine()
    eng.load_policies(PolicySet([_builtin_classified_policy()]))
    result = _native_output(eng, "r2922-observe", OUTPUT_CASES["license_header"])
    assert result.action == "allow"
    assert all(f.triage.get("disposition_reason") == REASON for f in _classified(result))


@pytest.mark.parametrize("name", sorted(OUTPUT_CASES))
def test_undeclared_output_still_blocked_like_2920(engine, name):
    # 不带网关原生声明（反代、正代、旧网关）：照 2.9.20 拦截并计入。
    result = engine.check_output("r2921-out-plain", OUTPUT_CASES[name], skip_semantic=True)
    hits = _classified(result)
    assert hits, name
    assert result.action == "block"
    assert all(f.counts_as_security_finding for f in hits)
    assert all(f.triage.get("disposition_reason") != REASON for f in hits)


@pytest.mark.parametrize("name", sorted(OUTPUT_CASES))
def test_same_text_from_user_still_blocked_like_2920(engine, name):
    result = engine.check_input("r2921-in", OUTPUT_CASES[name], skip_semantic=True, content_source="user")
    hits = _classified(result)
    assert hits, name
    assert result.action == "block"
    assert all(f.counts_as_security_finding for f in hits)


@pytest.mark.parametrize("source", ["assistant_history", None])
def test_client_supplied_history_and_unknown_source_not_released(engine, source):
    # 历史助手消息由客户端提供，可以伪造；未知来源照全量。两者都不享受输出方向的留证，即使带了输出声明。
    text = OUTPUT_CASES["strong_corroboration"]
    context = {"inspection_is_history": True} if source == "assistant_history" else {}
    result = engine.check_input("r2921-hist", text, context={**context, **NATIVE_CONTEXT}, skip_semantic=True,
                                content_source=source, principal=_gateway_principal())
    hits = _classified(result)
    assert hits, source
    for finding in hits:
        assert finding.triage.get("disposition_reason") != REASON
        assert finding.counts_as_security_finding is True
    assert result.action == "block"


def test_other_output_findings_keep_their_disposition():
    # 内置私钥策略照常拦，私钥命中计入；同一回答里的密级标记只留证。
    eng = SecurityEngine()
    eng.load_policies(PolicySet([_builtin_classified_policy(), _builtin_private_key_policy()]))
    mixed_text = OUTPUT_CASES["license_header"] + "\n" + KEY
    mixed = _native_output(eng, "r2921-key", mixed_text)
    assert mixed.action == "block"
    keys = [f for f in mixed.findings if f.category == "ssh_private_key"]
    assert keys
    for finding in keys:
        assert finding.policy_code == PRIVATE_KEY_CODE
        assert finding.action == "block"
        assert finding.counts_as_security_finding is True
        assert finding.triage.get("disposition_reason") != REASON
    hits = _classified(mixed)
    assert hits
    for finding in hits:
        assert finding.counts_as_security_finding is False
        assert finding.triage.get("disposition_reason") == REASON
    plain = eng.check_output("r2921-key-plain", mixed_text, skip_semantic=True)
    assert plain.action == "block"
    assert all(f.counts_as_security_finding for f in _classified(plain))


def test_output_without_policies_classified():
    # 不绑策略：带原生声明的留证；不带声明的照 2.9.20 记 audit。
    eng = SecurityEngine()
    declared = _native_output(eng, "r2921-nopol", OUTPUT_CASES["license_header"])
    hits = _classified(declared)
    assert hits
    assert all(f.counts_as_security_finding is False for f in hits)
    assert declared.action == "allow"
    plain = eng.check_output("r2921-nopol-plain", OUTPUT_CASES["license_header"], skip_semantic=True)
    assert _classified(plain)
    assert all(f.counts_as_security_finding for f in _classified(plain))
    assert plain.action == "audit"
