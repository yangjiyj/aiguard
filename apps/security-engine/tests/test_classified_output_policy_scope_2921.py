"""2.9.21：模型输出方向的密级留证，收窄到网关原生声明和可放宽的内置密级策略。

现场（2.9.20）30 天「涉密文件标记检测」真正拦下的 4 次全在网关原生路径的模型输出方向。5ae11371 曾在
engine.check_output 套策略之前，把所有密级命中一律标成留证。独立复核确认越界：
- 反代的非 chat 端点、正代的通用 JSON 兜底会把文件内容、知识库、会话历史送进 /check-output/；
- 客户 all 组合（密级 AND 身份证号）因密级不计入而凑不齐；客户自建的输出侧密级拦截被静默覆盖。

收窄后的契约（网关→引擎 context 字段，其余一律照 2.9.20）：
a. principal 存在、entry_point=gateway_api、身份来源不是反代或正代，context.source 也不是；
b. context.output_projection=model_text，或 model_tool_arguments 且 tool_may_egress 是布尔 False；
c. 只看中英文密级命中，附件正文除外；
d. 在套策略、编码画像降级、信号处置之后，按每份策略副本判断：可放宽的内置密级策略（编码就是
   builtin.data_leak.17723b156cfa7533、无匹配规则、能力只有两项密级）的副本留证；客户策略副本照常；
   没有策略命中的，当前主体可见、启用中的客户策略在输出阶段都没声明该类别时才留证（客户 all 组合没凑齐
   留下的证据照 2.9.20 记 audit）；
e. 留证写法同 5ae11371，留证原因后面不追加“策略级别/告警级别”；
f. 输入方向不变。
"""
import base64

import pytest

from app import feature_flags
from app.detectors.engine import SecurityEngine
from app.custom_rules import CompiledRule  # noqa: E402  先导入引擎，避免 custom_rules 循环导入
from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet, SubjectBinding
from app.principal_context import PrincipalContext

CN = "classified_classified_cn"
EN = "classified_classified_en"
CLASSIFIED = {CN, EN}
IDCARD = "id_card_cn"
PRIVATE_KEY = "ssh_private_key"
REASON = "model_output_classified_marker"
EVIDENCE = "留证原因：模型输出里的密级字样，内容由模型生成，不是本单位文件外发"
BUILTIN_CODE = "builtin.data_leak.17723b156cfa7533"
PRIVATE_KEY_CODE = "builtin.data_leak.a0891acf6ebc39c0"
CUSTOMER_CODE = "customer.r2921f.classified"

CONF_TEXT = "CONFIDENTIAL - Q3 board report file for the directors"
CN_TEXT = "这是机密文件，包含客户名单和财务数据"
ID_NUMBER = "11010519491231002X"
CONF_WITH_ID = CONF_TEXT + "\n负责人身份证号：" + ID_NUMBER
KEY_TEXT = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB\n"
    "aFDrBz9vFqU4yBHt3Qe1vI5x7xmKqXUvL9aGgVZ7MZTkGxJxY7kIaFm9yN0vC4vS\n"
    "-----END RSA PRIVATE KEY-----"
)

MODEL_TEXT = {"output_projection": "model_text"}
LOCAL_TOOL = {"output_projection": "model_tool_arguments", "tool_name": "Write", "tool_may_egress": False}


def _principal(**overrides):
    values = dict(
        schema_version=1, tenant_id="tenant_default", key_id="key-r2921f", protocol="openai",
        entry_point="gateway_api", identity_source="api_key", trust_level="key_bound",
    )
    values.update(overrides)
    return PrincipalContext(**values)


def _cap(category, actions, stages=("input", "output")):
    return CompiledPolicyCapability(
        category=category, supported_stages=list(stages), allowed_actions=list(actions),
        mask_capable="mask" in actions,
    )


def _policy(code, categories, *, action="block", mode="any", stages=("input", "output"),
            policy_id=None, name="r2921f 策略", subject_binding=None):
    return CompiledPolicy(
        policy_code=code, policy_id=policy_id or ("policy-" + code), policy_name=name,
        policy_type="data_leak", scene="data_security", severity="high", action=action,
        enabled=True, binding_mode=mode, subject_binding=subject_binding,
        capabilities=[_cap(category, ("audit", "block"), stages) for category in categories],
    )


def _builtin(action="block", **kwargs):
    # 与控制面内置「涉密文件标记检测」一致：high、默认 block，中英两项能力，输入输出两侧。
    return _policy(BUILTIN_CODE, [CN, EN], action=action, policy_id="policy-classified",
                   name="涉密文件标记检测", **kwargs)


def _private_key_policy():
    return _policy(PRIVATE_KEY_CODE, [PRIVATE_KEY], policy_id="policy-private-key", name="证书/私钥检测")


def _customer(categories, **kwargs):
    return _policy(CUSTOMER_CODE, categories, policy_id="policy-customer", name="客户自建密级策略", **kwargs)


def _engine(*policies, rules=None):
    eng = SecurityEngine()
    if policies:
        eng.load_policies(PolicySet(list(policies)))
    if rules:
        eng.load_custom_rules(rules)
    return eng


def _declared(eng, text, context=None, principal=None):
    ctx = dict(MODEL_TEXT) if context is None else context
    return eng.check_output("r2921f", text, context=ctx, skip_semantic=True,
                            principal=_principal() if principal is None else principal)


def _plain(eng, text, context=None, principal=None):
    return eng.check_output("r2921f", text, context=context, skip_semantic=True, principal=principal)


def _classified(result, category=None):
    wanted = {category} if category else CLASSIFIED
    return [f for f in result.findings if f.category in wanted]


def _assert_observed(finding):
    assert finding.counts_as_security_finding is False
    assert finding.action == "allow"
    assert finding.triage.get("disposition") == "observation"
    assert finding.triage.get("disposition_reason") == REASON
    assert finding.evidence_reason == EVIDENCE
    assert "severity_explanation" not in finding.triage


def _assert_counted(finding):
    assert finding.counts_as_security_finding is True
    assert finding.triage.get("disposition_reason") != REASON


def _shape(result):
    return sorted(
        (f.category, f.policy_code, f.action, f.counts_as_security_finding, f.triage.get("disposition_reason"))
        for f in result.findings
    )


# ——内置密级策略：留证，留证原因不追加“策略级别/告警级别”——


@pytest.mark.parametrize("action", ["block", "audit"])
@pytest.mark.parametrize("text", [CONF_TEXT, CN_TEXT])
def test_builtin_policy_block_or_audit_is_observed(action, text):
    result = _declared(_engine(_builtin(action)), text)
    hits = _classified(result)
    assert hits
    for finding in hits:
        assert finding.policy_code == BUILTIN_CODE
        _assert_observed(finding)
        assert "策略级别" not in finding.evidence_reason and "告警级别" not in finding.evidence_reason
    assert result.action == "allow"


def test_local_tool_arguments_are_observed():
    text = '{"file_path": "/repo/src/runner.py", "content": "# CONFIDENTIAL AND PROPRIETARY - do not distribute this file."}'
    result = _declared(_engine(_builtin()), text, context=dict(LOCAL_TOOL))
    hits = _classified(result)
    assert hits
    for finding in hits:
        _assert_observed(finding)
    assert result.action == "allow"


def test_session_identity_from_gateway_is_observed():
    principal = _principal(identity_source="session", trust_level="authenticated", actor_user_id="u-1",
                           key_id="")
    result = _declared(_engine(_builtin()), CONF_TEXT, principal=principal)
    assert _classified(result)
    assert result.action == "allow"


# ——客户策略照 2.9.20——


def test_builtin_plus_customer_all_combination_blocks():
    eng = _engine(_builtin(), _customer([EN, IDCARD], mode="all"))
    result = _declared(eng, CONF_WITH_ID)
    assert result.action == "block"
    copies = {f.policy_code: f for f in _classified(result, EN)}
    assert set(copies) == {BUILTIN_CODE, CUSTOMER_CODE}
    _assert_counted(copies[CUSTOMER_CODE])
    assert copies[CUSTOMER_CODE].action == "block"
    _assert_observed(copies[BUILTIN_CODE])
    ids = [f for f in result.findings if f.category == IDCARD]
    assert ids and all(f.counts_as_security_finding and f.policy_code == CUSTOMER_CODE for f in ids)


def test_customer_all_combination_alone_blocks():
    eng = _engine(_customer([EN, IDCARD], mode="all"))
    result = _declared(eng, CONF_WITH_ID)
    assert result.action == "block"
    hits = _classified(result, EN)
    assert hits and all(f.policy_code == CUSTOMER_CODE for f in hits)
    for finding in hits:
        _assert_counted(finding)
    assert _shape(result) == _shape(_plain(eng, CONF_WITH_ID))


def test_customer_all_combination_incomplete_stays_audit_like_2920():
    eng = _engine(_customer([EN, IDCARD], mode="all"))
    result = _declared(eng, CONF_TEXT)
    hits = _classified(result, EN)
    assert hits
    for finding in hits:
        _assert_counted(finding)
        assert finding.action == "audit"
    assert result.action == "audit"
    assert _shape(result) == _shape(_plain(eng, CONF_TEXT))


@pytest.mark.parametrize("stages", [("output",), ("input", "output")])
def test_builtin_plus_customer_any_classified_block_blocks(stages):
    eng = _engine(_builtin(), _customer([EN], stages=stages))
    result = _declared(eng, CONF_TEXT)
    assert result.action == "block"
    copies = {f.policy_code: f for f in _classified(result, EN)}
    assert set(copies) == {BUILTIN_CODE, CUSTOMER_CODE}
    _assert_counted(copies[CUSTOMER_CODE])
    assert copies[CUSTOMER_CODE].action == "block"
    _assert_observed(copies[BUILTIN_CODE])


def test_customer_audit_policy_keeps_audit():
    eng = _engine(_builtin(), _customer([EN], action="audit"))
    result = _declared(eng, CONF_TEXT)
    assert result.action == "audit"
    copies = {f.policy_code: f for f in _classified(result, EN)}
    _assert_counted(copies[CUSTOMER_CODE])
    assert copies[CUSTOMER_CODE].action == "audit"
    _assert_observed(copies[BUILTIN_CODE])


def test_builtin_rewritten_as_all_with_idcard_is_not_relaxed():
    rewritten = _policy(BUILTIN_CODE, [EN, IDCARD], mode="all", policy_id="policy-classified",
                        name="涉密文件标记检测")
    eng = _engine(rewritten)
    combined = _declared(eng, CONF_WITH_ID)
    assert combined.action == "block"
    hits = _classified(combined, EN)
    assert hits and all(f.policy_code == BUILTIN_CODE for f in hits)
    for finding in hits:
        _assert_counted(finding)
    alone = _declared(eng, CONF_TEXT)
    assert alone.action == "audit"
    for finding in _classified(alone, EN):
        _assert_counted(finding)
    assert _shape(alone) == _shape(_plain(eng, CONF_TEXT))


def test_customer_policy_bound_to_other_subject_is_not_visible():
    # 客户策略绑定到别的密钥：对当前主体不可见，照契约 d 按“没有策略命中”处理。
    other = _customer([EN], subject_binding=SubjectBinding(key_ids=["key-other"]))
    eng = _engine(other)
    result = _declared(eng, CONF_TEXT)
    hits = _classified(result, EN)
    assert hits and all(f.policy_code == "" for f in hits)
    for finding in hits:
        _assert_observed(finding)
    assert result.action == "allow"
    assert _plain(eng, CONF_TEXT, principal=_principal()).action == "audit"


# ——可放宽的只有现场那条内置密级策略：编码必须是 builtin.data_leak.17723b156cfa7533——


@pytest.mark.parametrize("category,text", [(CN, CN_TEXT), (EN, CONF_TEXT)], ids=["cn", "en"])
def test_other_builtin_policy_rewritten_to_classified_only_blocks_like_2920(category, text):
    # 停用内置密级策略，把别的内置策略（证书/私钥检测）覆写成只绑一项密级能力的 block 策略：
    # 结构和可放宽的那条一样，但编码不是，照 2.9.20 拦。
    disabled = _builtin().model_copy(update={"enabled": False})
    rewritten = _policy(PRIVATE_KEY_CODE, [category], policy_id="policy-private-key", name="证书/私钥检测")
    eng = _engine(disabled, rewritten)
    result = _declared(eng, text)
    hits = _classified(result, category)
    assert hits and all(f.policy_code == PRIVATE_KEY_CODE for f in hits)
    for finding in hits:
        _assert_counted(finding)
        assert finding.action == "block"
    assert result.action == "block"
    assert _shape(result) == _shape(_plain(eng, text))


@pytest.mark.parametrize("code", [
    "system.data_leak.17723b156cfa7533",
    "system.data_leak.classified",
    "builtin.data_leak.0000000000000000",
    BUILTIN_CODE + ".copy",
])
def test_classified_policy_with_other_code_is_not_relaxed(code):
    # 两项密级能力、无匹配规则，结构与内置密级策略相同；编码不是那一条（含 system. 开头的）：照 2.9.20 拦。
    eng = _engine(_policy(code, [CN, EN], policy_id="policy-" + code, name="涉密文件标记检测"))
    result = _declared(eng, CONF_TEXT)
    hits = _classified(result)
    assert hits and all(f.policy_code == code for f in hits)
    for finding in hits:
        _assert_counted(finding)
        assert finding.action == "block"
    assert result.action == "block"
    assert _shape(result) == _shape(_plain(eng, CONF_TEXT))


# ——不绑策略、主体绑定、其他命中——


def test_without_policies_declared_is_observed_and_plain_is_audit_like_2920():
    eng = _engine()
    declared = _declared(eng, CONF_TEXT)
    assert declared.action == "allow"
    hits = _classified(declared)
    assert hits
    for finding in hits:
        _assert_observed(finding)
    plain = _plain(eng, CONF_TEXT)
    assert plain.action == "audit"
    for finding in _classified(plain):
        _assert_counted(finding)


def test_builtin_subject_binding_mismatch():
    bound = _builtin(subject_binding=SubjectBinding(key_ids=["key-other"]))
    eng = _engine(bound)
    declared = _declared(eng, CONF_TEXT)
    hits = _classified(declared)
    assert hits and all(f.policy_code == "" for f in hits)
    for finding in hits:
        _assert_observed(finding)
    assert declared.action == "allow"
    plain = _plain(eng, CONF_TEXT, principal=_principal())
    assert plain.action == "audit"
    for finding in _classified(plain):
        _assert_counted(finding)


def test_builtin_private_key_policy_still_blocks():
    eng = _engine(_builtin(), _private_key_policy())
    result = _declared(eng, CONF_TEXT + "\n" + KEY_TEXT)
    assert result.action == "block"
    keys = [f for f in result.findings if f.category == PRIVATE_KEY]
    assert keys
    for finding in keys:
        _assert_counted(finding)
        assert finding.policy_code == PRIVATE_KEY_CODE
        assert finding.action == "block"
    hits = _classified(result)
    assert hits
    for finding in hits:
        _assert_observed(finding)


# ——编码画像降级：留证原因不被改写，不追加后缀——


@pytest.mark.parametrize("action", ["block", "audit"])
def test_coding_profile_keeps_observation_reason(monkeypatch, action):
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "true")
    eng = _engine(_builtin(action))
    result = _declared(eng, CONF_TEXT, context={**MODEL_TEXT, "agent_type": "claude-code"})
    hits = _classified(result)
    assert hits
    for finding in hits:
        _assert_observed(finding)
    assert result.action == "allow"


# ——照 2.9.20：附件正文、反代、正代、缺 principal、声明不合格——


def test_attachment_text_not_observed(monkeypatch):
    feature_flags.apply_overrides({})
    monkeypatch.setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
    eng = _engine(_builtin())
    attachment = {"attachments": [{
        "file_name": "report.txt", "content_type": "text/plain",
        "data_base64": base64.b64encode(CONF_TEXT.encode()).decode(),
    }]}
    result = _declared(eng, "File attached", context={**MODEL_TEXT, **attachment})
    hits = _classified(result)
    assert hits and all(f.content_source == "file_attachment" for f in hits)
    for finding in hits:
        _assert_counted(finding)
    assert result.action == "block"


def test_attachments_in_context_keep_answer_text_like_2920(monkeypatch):
    # 附件文字（含旧 OCR 拼接）没有可靠来源标注：上下文带附件时整条照 2.9.20。
    feature_flags.apply_overrides({})
    monkeypatch.setenv("SECURITY_FILE_CONTENT_DLP_ENABLED", "true")
    eng = _engine(_builtin())
    attachment = {"attachments": [{
        "file_name": "notes.txt", "content_type": "text/plain",
        "data_base64": base64.b64encode(b"ordinary notes").decode(),
    }]}
    result = _declared(eng, CONF_TEXT, context={**MODEL_TEXT, **attachment})
    hits = _classified(result)
    assert hits
    for finding in hits:
        _assert_counted(finding)
    assert result.action == "block"


NOT_DECLARED = {
    "reverse_proxy_source": (dict(MODEL_TEXT, source="reverse_proxy"), {}),
    "forward_proxy_source": (dict(MODEL_TEXT, source="forward_proxy"), {}),
    "reverse_proxy_principal": (dict(MODEL_TEXT), {"entry_point": "reverse_proxy", "identity_source": "reverse_proxy"}),
    "reverse_proxy_identity_gateway_entry": (dict(MODEL_TEXT), {"identity_source": "reverse_proxy"}),
    "forward_proxy_principal": (dict(MODEL_TEXT), {"entry_point": "forward_proxy", "identity_source": "forward_proxy"}),
    "forward_proxy_identity_gateway_entry": (dict(MODEL_TEXT), {"identity_source": "forward_proxy"}),
    "entry_point_missing": (dict(MODEL_TEXT), {"entry_point": ""}),
    "projection_other_value": ({"output_projection": "model_answer"}, {}),
    "projection_upper_case": ({"output_projection": "MODEL_TEXT"}, {}),
    "projection_missing": ({}, {}),
    "tool_may_egress_string_false": (dict(LOCAL_TOOL, tool_may_egress="false"), {}),
    "tool_may_egress_zero": (dict(LOCAL_TOOL, tool_may_egress=0), {}),
    "tool_may_egress_missing": ({"output_projection": "model_tool_arguments", "tool_name": "Write"}, {}),
    "tool_may_egress_true": (dict(LOCAL_TOOL, tool_may_egress=True), {}),
}


@pytest.mark.parametrize("name", sorted(NOT_DECLARED))
def test_without_native_declaration_blocks_like_2920(name):
    context, principal_overrides = NOT_DECLARED[name]
    eng = _engine(_builtin())
    result = _declared(eng, CONF_TEXT, context=context, principal=_principal(**principal_overrides))
    hits = _classified(result)
    assert hits, name
    for finding in hits:
        _assert_counted(finding)
        assert finding.action == "block"
    assert result.action == "block", name


def test_missing_principal_blocks_like_2920():
    eng = _engine(_builtin())
    result = eng.check_output("r2921f", CONF_TEXT, context=dict(MODEL_TEXT), skip_semantic=True)
    hits = _classified(result)
    assert hits
    for finding in hits:
        _assert_counted(finding)
    assert result.action == "block"


def test_principal_as_plain_dict_is_not_trusted():
    eng = _engine()
    principal = _principal().model_dump()
    result = eng.check_output("r2921f", CONF_TEXT, context=dict(MODEL_TEXT), skip_semantic=True,
                              principal=principal)
    hits = _classified(result)
    assert hits
    for finding in hits:
        _assert_counted(finding)
    assert result.action == "audit"


# ——自定义匹配规则不受影响——


def _custom_rule(category):
    return CompiledRule(
        rule_id="rule_r2921f_conf", rule_name="自定义密级词", rule_type="regex", category=category,
        severity="high", action="block", regex=r"CONFIDENTIAL",
    )


def test_custom_matcher_rule_hit_unaffected():
    matcher = CompiledPolicy(
        policy_code="customer.matcher.r2921f", policy_id="policy-matcher", policy_name="自定义密级词",
        policy_type="matcher_policy", scene="data_leak", severity="high",
        matcher_rule_id="rule_r2921f_conf", action="block", enabled=True, binding_mode="any",
    )
    eng = _engine(_builtin(), matcher, rules=[_custom_rule("custom_r2921f")])
    result = _declared(eng, CONF_TEXT)
    assert result.action == "block"
    custom = [f for f in result.findings if f.policy_code == "customer.matcher.r2921f"]
    assert custom
    for finding in custom:
        _assert_counted(finding)
        assert finding.action == "block"
    for finding in _classified(result):
        _assert_observed(finding)


def test_custom_rule_with_classified_category_not_relaxed():
    # 自定义规则自报密级类别、被内置密级策略按类别命中：不是内置检测器的命中，不留证。
    eng = _engine(_builtin(), rules=[_custom_rule(EN)])
    result = _declared(eng, "CONFIDENTIAL")
    custom = [f for f in result.findings if f.type == "custom"]
    assert custom
    for finding in custom:
        _assert_counted(finding)
    assert result.action == "block"


# ——留证原因、原始留证——


def test_explain_severity_twice_is_stable():
    eng = _engine(_builtin(), _customer([EN]))
    result = _declared(eng, CONF_TEXT)
    snapshot = [(f.policy_code, f.evidence_reason, dict(f.triage)) for f in result.findings]
    SecurityEngine._explain_severity(result.findings)
    SecurityEngine._explain_severity(result.findings)
    assert [(f.policy_code, f.evidence_reason, dict(f.triage)) for f in result.findings] == snapshot
    copies = {f.policy_code: f for f in _classified(result, EN)}
    assert copies[BUILTIN_CODE].evidence_reason == EVIDENCE
    assert copies[CUSTOMER_CODE].evidence_reason.count("策略级别") == 1


def test_raw_findings_keep_classified_counted():
    result = _declared(_engine(_builtin()), CONF_TEXT)
    raw = [f for f in result.raw_findings if f.category in CLASSIFIED]
    assert raw
    for finding in raw:
        _assert_counted(finding)


# ——输入方向不变——


@pytest.mark.parametrize("source", ["user", "tool_result", "assistant_history", None])
def test_input_side_unchanged_by_output_declaration(source):
    eng = _engine(_builtin())
    base = {"inspection_is_history": True} if source == "assistant_history" else {}
    plain = eng.check_input("r2921f-in", CONF_TEXT, context=dict(base) or None, skip_semantic=True,
                            content_source=source, principal=_principal())
    declared = eng.check_input("r2921f-in", CONF_TEXT, context={**base, **LOCAL_TOOL, **MODEL_TEXT},
                               skip_semantic=True, content_source=source, principal=_principal())
    hits = _classified(declared)
    assert hits, source
    assert all(f.triage.get("disposition_reason") != REASON for f in hits)
    assert _shape(declared) == _shape(plain)
    assert declared.action == plain.action
    if source == "user":
        assert declared.action == "block"


# ——复核收口：契约 d 的“启用中”“输出阶段”、内置检测器来源，以及集成 DLP 下的处置——


def test_disabled_visible_customer_policy_does_not_block_observation():
    # 内置密级策略绑到别的密钥（没有策略命中）；当前主体可见的客户 EN 策略已停用：只看启用中的客户策略，照样留证。
    bound = _builtin(subject_binding=SubjectBinding(key_ids=["key-other"]))
    disabled = _customer([EN]).model_copy(update={"enabled": False})
    eng = _engine(bound, disabled)
    result = _declared(eng, CONF_TEXT)
    hits = _classified(result, EN)
    assert hits and all(f.policy_code == "" for f in hits)
    for finding in hits:
        _assert_observed(finding)
    assert result.action == "allow"


def test_customer_policy_declaring_classified_only_on_input_does_not_block_observation():
    # 客户 EN 策略只在输入阶段声明：输出阶段没声明该类别，没有策略命中的密级证据照样留证；输入方向照常拦。
    bound = _builtin(subject_binding=SubjectBinding(key_ids=["key-other"]))
    eng = _engine(bound, _customer([EN], stages=("input",)))
    result = _declared(eng, CONF_TEXT)
    hits = _classified(result, EN)
    assert hits and all(f.policy_code == "" for f in hits)
    for finding in hits:
        _assert_observed(finding)
    assert result.action == "allow"
    assert eng.check_input("r2921f-in", CONF_TEXT, skip_semantic=True, content_source="user",
                           principal=_principal()).action == "block"


def test_custom_rule_named_like_builtin_detector_not_relaxed():
    # 自定义规则的 rule_id 与内置检测器同名、自报 EN 类别：不是内置检测器的命中，照 2.9.20 计入并拦截。
    rule = CompiledRule(
        rule_id="data_leak_classified_en", rule_name="自定义密级词", rule_type="regex", category=EN,
        severity="high", action="block", regex=r"CONFIDENTIAL",
    )
    eng = _engine(_builtin(), rules=[rule])
    result = _declared(eng, "CONFIDENTIAL")
    custom = [f for f in result.findings if f.type == "custom"]
    assert custom
    for finding in custom:
        _assert_counted(finding)
    assert result.action == "block"


def _integration_dlp_context():
    return {
        **MODEL_TEXT, "tenant_id": "tenant_default", "key_id": "key-r2921f", "integration_credential": True,
        "effective_dlp_enforcement": "block", "integration_dlp_block_key_ids": ["key-r2921f"],
    }


def test_audit_only_integration_dlp_block_not_disabled_by_observed_classified_copy():
    # 全局只记录 + 集成密钥 DLP 拦截：2.9.22 起全局观察留痕管全部检测类拦截（D6），集成密钥 DLP 强制档也只记录。
    # 留证的密级副本仍不计入，计入的身份证号命中照常留证。
    idcard = _policy(
        "custom.agentshield-idcard", [IDCARD], policy_id="policy-agentshield-idcard", name="身份证号",
        subject_binding=SubjectBinding(tenant_ids=["tenant_default"], key_ids=["key-r2921f"]),
    ).model_copy(update={"authoring_source": "agentshield"})
    eng = _engine(_builtin(), idcard)
    eng.audit_only = True
    declared = _declared(eng, CONF_WITH_ID, context=_integration_dlp_context())
    assert declared.action == "audit"
    hits = _classified(declared)
    assert hits
    for finding in hits:
        _assert_observed(finding)
    ids = [f for f in declared.findings if f.category == IDCARD]
    assert ids and all(f.counts_as_security_finding and not f.triage.get("integration_dlp_block") for f in ids)

    plain_context = {k: v for k, v in _integration_dlp_context().items() if k != "output_projection"}
    plain = _plain(eng, CONF_WITH_ID, context=plain_context, principal=_principal())
    assert plain.action == "audit"
    for finding in _classified(plain):
        _assert_counted(finding)
    assert eng.audit_only is True


# ——r2921g 复核（site F2）：同一次输出里还有其他计入的脱敏（mask）命中时，密级命中不放宽，照 2.9.20 拦——
# 密级放宽以后，身份证号等由各自的 mask 策略处置：回答正文里变成脱敏放行，Messages 原生 tool_use 参数脱敏
# 回写不了还会原样转发（messages_native.go 的 forwarded unmasked）。2.9.20 上这些输出被密级 block 一并挡住。
# 其他命中是 block 的（如私钥）本来就拦，密级照旧留证（test_builtin_private_key_policy_still_blocks）；
# 其他命中只是 audit 的不改处置，密级照旧留证。

IDCARD_CODE = "builtin.data_leak.ee20059e4c9fbf2f"
CN_WITH_ID = "这份机密文件里有负责人身份证号：" + ID_NUMBER
WRITE_WITH_ID = (
    '{"file_path": "/repo/src/owner.py", "content": "# CONFIDENTIAL AND PROPRIETARY\\n'
    'OWNER_ID = \\"' + ID_NUMBER + '\\"\\n"}'
)


def _idcard_policy(action="mask"):
    # 与控制面内置「身份证号检测」一致：high、默认 mask。
    return CompiledPolicy(
        policy_code=IDCARD_CODE, policy_id="policy-idcard", policy_name="身份证号检测",
        policy_type="data_leak", scene="data_security", severity="high", action=action,
        enabled=True, binding_mode="any", subject_binding=None,
        capabilities=[CompiledPolicyCapability(
            category=IDCARD, supported_stages=["input", "output"], allowed_actions=["audit", "mask", "block"],
            mask_capable=True,
        )],
    )


@pytest.mark.parametrize("context, text", [
    (MODEL_TEXT, CONF_WITH_ID),
    (MODEL_TEXT, CN_WITH_ID),
    (LOCAL_TOOL, WRITE_WITH_ID),
])
def test_classified_with_counted_mask_hit_blocks_like_2920(context, text):
    eng = _engine(_builtin(), _idcard_policy())
    declared = _declared(eng, text, context=dict(context))
    plain = _plain(eng, text, principal=_principal())
    assert plain.action == "block"
    assert declared.action == "block"
    hits = _classified(declared)
    assert hits
    for finding in hits:
        _assert_counted(finding)
        assert finding.action == "block"
    assert _shape(declared) == _shape(plain)


def test_classified_with_audit_only_other_hit_still_observed():
    eng = _engine(_builtin(), _idcard_policy("audit"))
    declared = _declared(eng, CONF_WITH_ID)
    hits = _classified(declared)
    assert hits
    for finding in hits:
        _assert_observed(finding)
    ids = [f for f in declared.findings if f.category == IDCARD]
    assert ids and all(f.counts_as_security_finding and f.action == "audit" for f in ids)
    assert declared.action == "audit"


def test_classified_alone_with_mask_policy_loaded_still_observed():
    eng = _engine(_builtin(), _idcard_policy())
    declared = _declared(eng, CONF_TEXT, context=dict(LOCAL_TOOL))
    hits = _classified(declared)
    assert hits
    for finding in hits:
        _assert_observed(finding)
    assert declared.action == "allow"


# ——r2921g 复核（site F1）：本地文件工具放行后，下一轮请求里的工具回显照 2.9.20 在输入方向拦——
# Edit、覆盖写、CodeBuddy replace_in_file 的结果会把带密级字样的行回显进下一轮的 tool_result；输入方向不放宽，
# 是否放开交用户决定。这里钉住现状。

EDIT_ECHO = (
    "The file /repo/src/runner.py has been updated. Here's the result of running `cat -n` on a snippet "
    "of the edited file:\n     1\t#!/usr/bin/env python3\n     2\t# CONFIDENTIAL AND PROPRIETARY. "
    "This file is for internal use only.\n     3\timport os\n"
)


def test_edit_echo_tool_result_next_turn_still_blocks():
    eng = _engine(_builtin())
    for context in (None, {**LOCAL_TOOL}, {**MODEL_TEXT}):
        result = eng.check_input("r2921g-in", EDIT_ECHO, context=context, skip_semantic=True,
                                 content_source="tool_result", principal=_principal())
        hits = _classified(result)
        assert hits, context
        for finding in hits:
            _assert_counted(finding)
        assert result.action == "block", context
