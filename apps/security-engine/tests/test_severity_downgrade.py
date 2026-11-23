import re

import pytest

from app.detectors.engine import SecurityEngine, SecurityFinding
from app.detectors.severity_downgrade import (
    TRIAGE_REASON, annotate_key_only_findings, apply_evidence_downgrades, match_has_real_value, match_is_key_only,
)


def _hit(content, pattern=r"(?i)(password|api_key)\s*[=:：]", severity="high", **extra):
    m = re.search(pattern, content)
    assert m, content
    return SecurityFinding(
        type="custom", category="customer_sensitive_data", severity=severity,
        matched_text_preview="x", rule_id="rule_997bd32c", rule_name="密钥相关", rule_type="regex",
        matched_location=f"content[{m.start()}:{m.end()}]", raw_evidence=content[m.start():m.end()], **extra,
    )


def _run(findings, content):
    return apply_evidence_downgrades(annotate_key_only_findings(findings, content))


@pytest.mark.parametrize("content", [
    "POSTGRES_PASSWORD=\nOTHER=1",
    "POSTGRES_PASSWORD: ${PG_PASS}",
    "password=changeme",
    "api_key: <your-api-key>",
    "DB_PASSWORD=os.environ['DB_PASSWORD']",
    "password: '***'",
])
def test_key_name_without_real_value_is_downgraded_one_level(content):
    [out] = _run([_hit(content)], content)
    assert out.severity == "medium"
    assert out.triage["severity_downgrade_reason"] == "只命中字段名，未见真实值"
    assert out.triage["severity_before_downgrade"] == "high"


@pytest.mark.parametrize("content", [
    'password="R3al!Cred9Value"',
    "PASSWORD=Zx9!mQ2#vL7p",
])
def test_real_value_is_not_downgraded(content):
    [out] = _run([_hit(content)], content)
    assert out.severity == "high"
    assert "severity_downgrade_reason" not in out.triage


def test_ai_review_false_positive_verdict_downgrades():
    content = "随便一段说明文字"
    f = SecurityFinding(type="catalog_policy", category="code_xss_generation", severity="medium",
                        matched_text_preview="x", rule_id="r", matched_location="content[0:4]",
                        raw_evidence=content[0:4],
                        triage={"verdict": "likely_false_positive", "ai_review_downgrade_eligible": True})
    [out] = _run([f], content)
    assert out.severity == "low"
    assert out.triage["severity_downgrade_reason"] == "AI 复核判定为疑似误报"


def test_low_is_the_floor():
    content = "password="
    [out] = _run([_hit(content, severity="low")], content)
    assert out.severity == "low"
    assert "severity_downgrade_reason" not in out.triage


def test_observations_and_non_downgradable_categories_are_left_alone():
    content = "password="
    observed = _hit(content, counts_as_security_finding=False)
    locked = _hit(content, triage={"cannot_downgrade": True})
    out = _run([observed, locked], content)
    assert [f.severity for f in out] == ["high", "high"]


def test_detector_downgraded_findings_are_not_downgraded_again():
    content = "password="
    already = _hit(content, triage={"severity_downgrade_reason": "安全码格式候选，缺少有效卡号佐证", "severity_before_downgrade": "critical"})
    [out] = _run([already], content)
    assert out.severity == "high"
    assert out.triage["severity_downgrade_reason"] == "安全码格式候选，缺少有效卡号佐证"


def test_location_that_does_not_match_the_content_is_ignored():
    content = "password="
    f = _hit(content)
    f.raw_evidence = "something else"
    [out] = _run([f], content)
    assert out.severity == "high"


def test_downgrade_runs_once():
    content = "password="
    once = _run([_hit(content)], content)
    twice = apply_evidence_downgrades(once)
    assert twice[0].severity == "medium"


@pytest.mark.parametrize("method", ["check_input", "check_output"])
def test_engine_applies_evidence_downgrades(monkeypatch, method):
    import app.detectors.engine as engine_module
    calls = []

    def spy(findings):
        calls.append(len(findings))
        return findings

    monkeypatch.setattr(engine_module, "apply_evidence_downgrades", spy)
    content = "我的手机号是 13812345678"
    getattr(SecurityEngine(), method)("wire", content, skip_semantic=True)
    assert len(calls) == 1


# ---- 修 1：证据降级不能改处置动作 ----

def _reply_policy():
    from app.reply_generator import ReplyPolicy
    return ReplyPolicy(enabled=True, templates={"data_leak": "不能处理该请求"})


def _code_config(triage):
    return SecurityFinding(type="code_config", category="x_cfg", severity="high", matched_text_preview="x",
                           rule_id="code_x", policy_scene="data_leak", triage=triage)


def test_should_reply_covers_evidence_downgraded_critical_finding():
    # 2.9.22（设计 5.4）：开启固定回复后所有阻断都代答，策略级别为严重也一样
    # （原断言 False 锁的是“凭据类强制硬拦”，用户 11-17 决定去掉）。
    f = _code_config({"severity_downgrade_reason": TRIAGE_REASON, "severity_before_downgrade": "critical"})
    assert SecurityEngine._should_reply([f], _reply_policy()) is True


def test_should_reply_still_honours_detector_own_downgrade():
    f = _code_config({"severity_downgrade_reason": "安全码格式候选，缺少有效卡号佐证",
                      "severity_before_downgrade": "critical"})
    assert SecurityEngine._should_reply([f], _reply_policy()) is True


@pytest.mark.parametrize("reply_enabled,expected", [(True, "reply"), (False, "block")])
def test_critical_block_stays_enforced_after_ai_review_downgrade(monkeypatch, reply_enabled, expected):
    # AI 复核把级别降到 high，动作仍是拦截；2.9.22 起开启固定回复时用固定回复拦
    # （原断言 action == "block" 锁的是“凭据类不代答”，随用户 11-17 决定改写）。
    engine = SecurityEngine()
    if reply_enabled:
        engine.load_reply_policy(_reply_policy())
    critical = SecurityFinding(type="code_config", category="x_cfg", severity="critical",
                               matched_text_preview="x", rule_id="code_x", policy_scene="data_leak",
                               action="block", policy_code="p.cfg", raw_evidence="abc", matched_location="content[0:3]")
    monkeypatch.setattr(engine, "_detect_code_config", lambda content: [critical])
    # 降级资格由 _needs_full_reinspection 决定；此处只验证“降级后动作不变”，故强制其为真。
    monkeypatch.setattr(engine, "_needs_full_reinspection", lambda runtime, finding: True)

    def review(content, findings, *a, **k):
        for f in findings:
            f.triage = {**f.triage, "verdict": "likely_false_positive"}
        return findings

    monkeypatch.setattr(engine, "_apply_finding_triage", review)
    result = engine.check_input("r1", "abc def", skip_semantic=True)
    assert result.action == expected
    assert [f.severity for f in result.findings if f.rule_id == "code_x"] == ["high"]


# ---- 修 2：非 mask 自定义正则不能被首处“只有字段名”吞掉后面的真实值 ----

def _rule(action):
    from app.custom_rules import CompiledRule
    return CompiledRule(rule_id="rule_997bd32c", rule_name="密钥相关", rule_type="regex",
                        category="customer_sensitive_data", severity="high", action=action, enabled=True,
                        regex=r"(?i)(password|api_key)\s*[=:：]")


MIXED = "POSTGRES_PASSWORD: ${PG_PASS}\nother: 1\nDB_PASSWORD: R3al!Cred9Value"


@pytest.mark.parametrize("action", ["audit", "block"])
def test_custom_rule_reports_the_first_match_that_has_a_real_value(action):
    from app.custom_rules import CustomRuleSet
    [f] = CustomRuleSet([_rule(action)]).match(MIXED)
    start = MIXED.rindex("PASSWORD")
    assert f.matched_location.startswith(f"content[{start}:")
    [out] = _run([f], MIXED)
    assert out.severity == "high"
    assert "severity_downgrade_reason" not in out.triage


@pytest.mark.parametrize("action", ["audit", "block"])
def test_custom_rule_all_key_only_matches_keep_first_and_downgrade(action):
    from app.custom_rules import CustomRuleSet
    content = "POSTGRES_PASSWORD: ${PG_PASS}\nDB_PASSWORD: ${DB_PASS}"
    [f] = CustomRuleSet([_rule(action)]).match(content)
    assert f.matched_location.startswith(f"content[{content.index('PASSWORD')}:")
    [out] = _run([f], content)
    assert out.severity == "medium"
    assert out.triage["severity_downgrade_reason"] == "只命中字段名，未见真实值"


# ---- 修 3：缓存重放与直连一致 ----

KEY_ONLY = "POSTGRES_PASSWORD: ${PG_PASS}"


def test_apply_context_replay_matches_direct_downgrade(monkeypatch):
    import anyio
    import app.api.apply_context as apply_context_module
    from app.custom_rules import CustomRuleSet
    engine = SecurityEngine()
    engine.load_custom_rules([_rule("audit")])
    monkeypatch.setattr(apply_context_module, "engine", engine)
    direct = engine.check_input("r2", KEY_ONLY, skip_semantic=True)
    request = apply_context_module.ApplyContextRequest(
        tenant_id="tenant_default", raw_findings=[f.model_dump() for f in direct.raw_findings],
        context={"content_source": "user"})
    replay = anyio.run(lambda: apply_context_module.apply_context(request))

    def view(findings):
        return sorted((f.rule_id, f.severity, f.triage.get("severity_downgrade_reason"),
                       f.triage.get("severity_before_downgrade")) for f in findings)

    assert view(replay.findings) == view(direct.findings)
    assert any(row[1] == "medium" and row[2] for row in view(direct.findings))


def _fp_runtime(engine, **overrides):
    from dataclasses import replace
    return replace(engine.snapshot_semantic_runtime(), **{
        "fp_suppression_enabled": True, "semantic_master_enabled": True, "llm_judge_mode": "off", **overrides})


def _candidate(**extra):
    return SecurityFinding(type="catalog_policy", category="prompt_leak_internal_rules", severity="high",
                           matched_text_preview="x", rule_id="r", matched_location="content[0:4]",
                           raw_evidence="abcd", **extra)


def test_ai_review_downgrade_requires_the_eligibility_mark():
    plain = _candidate(triage={"verdict": "likely_false_positive"})
    marked = _candidate(triage={"verdict": "likely_false_positive", "ai_review_downgrade_eligible": True})
    out = apply_evidence_downgrades([plain, marked])
    assert [f.severity for f in out] == ["high", "medium"]
    assert out[1].triage["severity_downgrade_reason"] == TRIAGE_REASON


def test_mark_follows_the_same_condition_as_the_replay_409():
    engine = SecurityEngine()
    on = _fp_runtime(engine)
    assert engine._needs_full_reinspection(on, _candidate()) is True
    for runtime in (_fp_runtime(engine, fp_suppression_enabled=False),
                    _fp_runtime(engine, semantic_master_enabled=False)):
        assert engine._needs_full_reinspection(runtime, _candidate()) is False
    other = SecurityFinding(type="catalog_policy", category="code_xss_generation", severity="high",
                            matched_text_preview="x", rule_id="r")
    assert engine._needs_full_reinspection(on, other) is False
    [marked] = engine._mark_ai_review_eligible([_candidate()], on)
    assert marked.triage["ai_review_downgrade_eligible"] is True
    [unmarked] = engine._mark_ai_review_eligible([_candidate()], _fp_runtime(engine, fp_suppression_enabled=False))
    assert "ai_review_downgrade_eligible" not in unmarked.triage


def test_every_ai_review_downgraded_finding_makes_the_replay_return_409(monkeypatch):
    import anyio
    import pytest as _pytest
    from fastapi import HTTPException
    import app.api.apply_context as apply_context_module
    engine = SecurityEngine()
    runtime = _fp_runtime(engine)
    [marked] = engine._mark_ai_review_eligible([_candidate(triage={"verdict": "likely_false_positive"})], runtime)
    [out] = apply_evidence_downgrades([marked])
    assert out.triage["severity_downgrade_reason"] == TRIAGE_REASON
    monkeypatch.setattr(apply_context_module, "engine", engine)
    monkeypatch.setattr(engine, "snapshot_semantic_runtime", lambda: runtime)
    raw = _candidate().model_dump()
    request = apply_context_module.ApplyContextRequest(tenant_id="tenant_default", raw_findings=[raw])
    with _pytest.raises(HTTPException) as caught:
        anyio.run(lambda: apply_context_module.apply_context(request))
    assert caught.value.status_code == 409


# ---- 修 4：复核结论的降级范围 ----

def _judge(monkeypatch, name, verdict):
    import importlib
    module = importlib.import_module("app.detectors.engine")
    monkeypatch.setattr(module, name, lambda *a, **k: {
        "verdict": verdict, "confidence": 0.95, "risk_level": "low",
        "reason": "示例", "review_state": verdict})


def test_shadow_advisory_verdict_on_non_candidate_does_not_downgrade(monkeypatch):
    _judge(monkeypatch, "llm_triage_judge", "likely_false_positive")
    engine = SecurityEngine()
    runtime = _fp_runtime(engine, llm_judge_mode="shadow")
    f = SecurityFinding(type="catalog_policy", category="code_xss_generation", severity="high",
                        matched_text_preview="x", rule_id="r", matched_location="content[0:4]", raw_evidence="abcd")
    [reviewed] = engine._apply_finding_triage("abcd", [f], "input", runtime)
    assert reviewed.counts_as_security_finding
    assert reviewed.triage["advisory_verdict"] == "likely_false_positive"
    [out] = apply_evidence_downgrades(engine._mark_ai_review_eligible([reviewed], runtime))
    assert out.severity == "high"
    assert "severity_downgrade_reason" not in out.triage


def _semantic_judge(monkeypatch, *rounds):
    """mock 底层 judge_semantic：每轮返回一条意见（verdict, category, confidence）。"""
    from app.detectors.llm_judge import SemanticOpinion
    answers = iter(rounds)
    monkeypatch.setattr("app.detectors.llm_judge.judge_semantic",
                        lambda text, **kw: SemanticOpinion(*next(answers)[:3], "这是示例说明"))


def _review_candidate(monkeypatch, *rounds):
    engine = SecurityEngine()
    runtime = _fp_runtime(engine)
    _semantic_judge(monkeypatch, *rounds)
    [reviewed] = engine._apply_finding_triage("abcd", [_candidate()], "input", runtime,
                                              content_source="tool_result")
    [out] = apply_evidence_downgrades(engine._mark_ai_review_eligible([reviewed], runtime))
    return engine, runtime, out


def test_agreeing_benign_review_below_withdraw_confidence_downgrades_one_level(monkeypatch):
    _engine, _runtime, out = _review_candidate(monkeypatch, ("benign", "none", 0.6), ("benign", "none", 0.6))
    assert out.counts_as_security_finding
    assert out.triage["verdict"] == "needs_review"
    assert out.triage["advisory_verdict"] == "likely_false_positive"
    assert out.severity == "medium"
    assert out.triage["severity_downgrade_reason"] == TRIAGE_REASON
    assert out.triage["severity_before_downgrade"] == "high"


def test_disagreeing_review_rounds_do_not_downgrade(monkeypatch):
    _engine, _runtime, out = _review_candidate(monkeypatch, ("benign", "none", 0.6), ("malicious", "prompt_injection", 0.9))
    assert out.counts_as_security_finding
    assert "advisory_verdict" not in out.triage
    assert out.severity == "high"
    assert "severity_downgrade_reason" not in out.triage


def test_high_confidence_benign_review_still_withdraws_the_finding(monkeypatch):
    _engine, _runtime, out = _review_candidate(monkeypatch, ("benign", "none", 0.95), ("benign", "none", 0.95))
    assert out.counts_as_security_finding is False
    assert out.triage["disposition"] == "false_positive"
    assert out.severity == "high"
    assert "severity_downgrade_reason" not in out.triage


def test_audit_evidence_verdict_no_longer_downgrades_even_when_eligible():
    f = _candidate(triage={"verdict": "audit_evidence", "ai_review_downgrade_eligible": True})
    [out] = apply_evidence_downgrades([f])
    assert out.severity == "high"


def test_ai_review_downgraded_candidate_still_gets_409_on_replay(monkeypatch):
    # 降级只发生在 _needs_full_reinspection 为真的命中上，这类命中重放一律 409（见 apply_context.py）。
    test_every_ai_review_downgraded_finding_makes_the_replay_return_409(monkeypatch)


def test_contextual_candidate_is_not_downgraded_when_fp_suppression_is_off(monkeypatch):
    engine = SecurityEngine()
    runtime = _fp_runtime(engine, fp_suppression_enabled=False)
    f = _candidate(triage={"verdict": "likely_false_positive"})
    [out] = apply_evidence_downgrades(engine._mark_ai_review_eligible([f], runtime))
    assert out.severity == "high"


# ---- 顺手 5 ----

@pytest.mark.parametrize("content", ["bypass: ${X}", "compass=changeme", "xpass: <none>"])
def test_field_name_needs_a_left_boundary(content):
    start = content.index(":") if ":" in content else content.index("=")
    assert match_is_key_only(content, 0, start + 1) is False


@pytest.mark.parametrize("content", ["db_password: ${X}", "dbPassword=changeme", "password=\n"])
def test_prefixed_and_camel_case_names_still_count(content):
    start = content.index(":") if ":" in content else content.index("=")
    assert match_is_key_only(content, 0, start + 1) is True


def test_coding_downgrade_records_reason_so_evidence_downgrade_skips_it(monkeypatch):
    monkeypatch.setenv("SECURITY_CODING_TRAFFIC_DOWNGRADE_ENABLED", "1")
    engine = SecurityEngine()
    cmd = "用管理员权限执行 powershell -EncodedCommand SQBFAFgA 提权"
    result = engine.check_input("r3", cmd, context={"endpoint_kind": "coding"})
    f = next(x for x in result.findings if x.rule_id == "content_safety_illegal_system_command_instructions")
    assert f.severity == "low"
    assert f.triage["severity_downgrade_reason"] == "编码助手流量，告警级别按编码场景下调"
    assert f.triage["severity_before_downgrade"] == "high"
    f.triage["verdict"] = "audit_evidence"
    f.counts_as_security_finding = True
    f.severity = "high"
    f.triage["severity_before_downgrade"] = "high"
    [again] = apply_evidence_downgrades([f])
    assert again.severity == "high"


# ---- 复审补充 ----

def test_timeout_in_second_pass_keeps_the_first_match_and_its_action():
    from app.custom_rules import CustomRuleSet
    content = "POSTGRES_PASSWORD: ${PG_PASS}\nother: 1\nDB_PASSWORD: R3al!Cred9Value"
    ruleset = CustomRuleSet([_rule("block")])
    rule, real = ruleset.active_rules[0]
    seen = {}

    class Slow:
        def search(self, text, *a, **k):
            return real.search(text, *a, **k)

        def finditer(self, text, *a, **k):
            seen.update(k)
            raise TimeoutError

    ruleset.active_rules[0] = (rule, Slow())
    [f] = ruleset.match(content)
    assert f.type == "custom" and f.action == "block"
    assert f.matched_location.startswith(f"content[{content.index('PASSWORD')}:")
    first_end = real.search(content).end()
    assert seen["pos"] == first_end  # 从首处之后继续，不从头重扫
    assert 0 < seen["timeout"] <= 3.0  # 只用本规则剩余预算


@pytest.mark.parametrize("rule_kwargs", [
    {"rule_type": "field_name", "field_names": ["password"], "regex": None},
    {"rule_type": "keyword", "keywords": ["password"], "regex": None},
])
@pytest.mark.parametrize("action", ["audit", "block"])
def test_field_name_and_keyword_rules_prefer_the_valued_match(rule_kwargs, action):
    from app.custom_rules import CompiledRule, CustomRuleSet
    rule = CompiledRule(rule_id="rule_fk", rule_name="密钥相关", category="customer_sensitive_data",
                        severity="high", action=action, enabled=True, **rule_kwargs)
    content = "password: ${X}\nuser: a\npassword: R3al!Cred9Value"
    [f] = CustomRuleSet([rule]).match(content)
    assert f.matched_location.startswith(f"content[{content.rindex('password')}:")
    [out] = _run([f], content)
    assert out.severity == "high"
    assert "severity_downgrade_reason" not in out.triage


def test_multiline_match_is_never_key_only():
    content = "api_token: R3alTok3nValue99x\npassword:"
    f = SecurityFinding(type="code_config", category="config_file", severity="medium", matched_text_preview="x",
                        rule_id="code_config_file", raw_evidence=content, matched_location=f"content[0:{len(content)}]")
    [out] = annotate_key_only_findings([f], content)
    assert "credential_key_only" not in out.triage


# ---- 第二遍扫描推迟到首遍之后，并限定区间 ----

def _audit_rule(rule_id="rule_audit2", regex=r"(?i)token\s*[=:：]"):
    from app.custom_rules import CompiledRule
    return CompiledRule(rule_id=rule_id, rule_name="令牌", rule_type="regex", category="customer_sensitive_data",
                        severity="medium", action="audit", enabled=True, regex=regex)


def test_second_pass_runs_after_every_rules_first_pass_and_loses_no_hit(monkeypatch):
    import app.custom_rules as cr
    ruleset = cr.CustomRuleSet([_rule("block"), _audit_rule()])
    events = []
    original_run = cr.CustomRuleSet._run_regex_rule
    original_find = cr._find_valued_match

    def run(self, *a, **k):
        events.append("run")
        return original_run(self, *a, **k)

    def find(*a, **k):
        events.append("find")
        return original_find(*a, **k)

    monkeypatch.setattr(cr.CustomRuleSet, "_run_regex_rule", run)
    monkeypatch.setattr(cr, "_find_valued_match", find)
    content = "POSTGRES_PASSWORD: ${PG_PASS}\n" + "x" * 300_000 + "\nDB_PASSWORD: R3al!Cred9Value\ntoken: abc"
    found = ruleset.match(content)
    assert events == ["run", "run", "find"]
    assert {f.rule_id for f in found} == {"rule_997bd32c", "rule_audit2"}
    assert all(f.type == "custom" for f in found)
    block = next(f for f in found if f.rule_id == "rule_997bd32c")
    assert block.action == "block"


def test_second_pass_is_skipped_when_the_pack_budget_is_gone_after_the_first_pass(monkeypatch):
    import types
    import time as real_time
    import app.custom_rules as cr
    ruleset = cr.CustomRuleSet([_rule("block"), _audit_rule()])
    state = {"runs": 0}
    original_run = cr.CustomRuleSet._run_regex_rule

    def run(self, *a, **k):
        result = original_run(self, *a, **k)
        state["runs"] += 1
        return result

    fake_time = types.SimpleNamespace(
        monotonic=lambda: real_time.monotonic() + (1000.0 if state["runs"] >= 2 else 0.0),
        thread_time=real_time.thread_time)
    monkeypatch.setattr(cr.CustomRuleSet, "_run_regex_rule", run)
    monkeypatch.setattr(cr, "time", fake_time)
    monkeypatch.setattr(cr, "_find_valued_match", lambda *a, **k: pytest.fail("预算用尽后不得再扫"))
    content = "POSTGRES_PASSWORD: ${PG_PASS}\nDB_PASSWORD: R3al!Cred9Value\ntoken: abc"
    found = ruleset.match(content)
    assert {f.rule_id for f in found} == {"rule_997bd32c", "rule_audit2"}
    assert all(f.type == "custom" for f in found)  # 没有 regex_budget_exhausted
    first = next(f for f in found if f.rule_id == "rule_997bd32c")
    assert first.matched_location.startswith(f"content[{content.index('PASSWORD')}:")  # 保留首处


@pytest.mark.parametrize("kind", ["regex", "field_name", "keyword"])
def test_real_value_beyond_the_scan_window_is_not_searched_so_first_match_is_kept_and_downgraded(kind):
    from app.custom_rules import CompiledRule, CustomRuleSet
    extra = {"regex": {"regex": r"(?i)password\s*[=:：]"},
             "field_name": {"field_names": ["password"]},
             "keyword": {"keywords": ["password"]}}[kind]
    rule = CompiledRule(rule_id="rule_w", rule_name="密钥相关", rule_type=kind,
                        category="customer_sensitive_data", severity="high", action="block", enabled=True, **extra)
    content = "password: ${X}\n" + "a" * (300 * 1024) + "\npassword: R3al!Cred9Value"
    [f] = CustomRuleSet([rule]).match(content)
    assert f.matched_location.startswith("content[0:")
    [out] = _run([f], content)
    assert out.severity == "medium"
    assert out.action == "block"


@pytest.mark.parametrize("kind", ["field_name", "keyword"])
def test_field_name_and_keyword_second_pass_is_deferred_too(monkeypatch, kind):
    import app.custom_rules as cr
    extra = {"field_name": {"field_names": ["password"]}, "keyword": {"keywords": ["password"]}}[kind]
    rule = cr.CompiledRule(rule_id="rule_d", rule_name="密钥相关", rule_type=kind,
                           category="customer_sensitive_data", severity="high", action="audit", enabled=True, **extra)
    ruleset = cr.CustomRuleSet([rule, _audit_rule()])
    events = []
    original_find = cr._find_valued_match
    monkeypatch.setattr(cr, "_find_valued_match", lambda *a, **k: events.append("find") or original_find(*a, **k))
    original_search = ruleset.active_rules[1][1].search

    class Spy:
        def __init__(self, inner):
            self.inner = inner

        def search(self, *a, **k):
            events.append("audit-first-pass")
            return self.inner.search(*a, **k)

        def finditer(self, *a, **k):
            return self.inner.finditer(*a, **k)

    ruleset.active_rules[1] = (ruleset.active_rules[1][0], Spy(ruleset.active_rules[1][1]))
    ruleset.match("password: ${X}\nuser: a\npassword: R3al!Cred9Value\ntoken: abc")
    assert events.index("audit-first-pass") < events.index("find")


# ---- 第四轮：正向判断“带真实值” ----

@pytest.mark.parametrize("content,expected", [
    ("password: R3al!Cred9Value", True),
    ('DB_PASSWORD="R3al!Cred9Value"', True),
    ("password: ${X}", False),
    ("password: changeme", False),
    ("password=", False),
    ("# 请定期轮换 password，不要提交到仓库", False),
    ("password", False),
])
def test_match_has_real_value_is_a_positive_judgement(content, expected):
    m = re.search(r"(?i)password\s*[=:：]?", content)
    assert match_has_real_value(content, m.start(), m.end()) is expected


COMMENT_MENTION = "password: ${X}\n# 请定期轮换 password，不要提交到仓库"


@pytest.mark.parametrize("kind", ["keyword", "regex"])
def test_a_bare_mention_is_not_chosen_as_the_valued_representative(kind):
    from app.custom_rules import CompiledRule, CustomRuleSet
    extra = {"keyword": {"keywords": ["password"]}, "regex": {"regex": r"(?i)\bpassword\b"}}[kind]
    rule = CompiledRule(rule_id="rule_m", rule_name="密钥相关", rule_type=kind,
                        category="customer_sensitive_data", severity="high", action="audit", enabled=True, **extra)
    [f] = CustomRuleSet([rule]).match(COMMENT_MENTION)
    assert f.matched_location.startswith("content[0:")
    [out] = _run([f], COMMENT_MENTION)
    assert out.severity == "medium"
    assert out.triage["severity_downgrade_reason"] == "只命中字段名，未见真实值"


# ---- 只走公开接口的端到端 ----

COMPOSE_REAL = ("services:\n  db:\n    environment:\n      POSTGRES_USER: app\n"
                "      POSTGRES_PASSWORD: ${PG_PASS}\n      REDIS_PASSWORD: R3al!Cred9Value\n")
COMPOSE_REFS = ("services:\n  db:\n    environment:\n      POSTGRES_PASSWORD: ${PG_PASS}\n"
                "      REDIS_PASSWORD: ${REDIS_PASS}\n")


@pytest.mark.parametrize("content,severity,reason,anchor", [
    (COMPOSE_REAL, "high", None, "REDIS_PASSWORD"),
    (COMPOSE_REFS, "medium", "只命中字段名，未见真实值", "POSTGRES_PASSWORD"),
    ("POSTGRES_PASSWORD: ${PG_PASS}\n# 请定期轮换 password，不要提交到仓库", "medium", "只命中字段名，未见真实值",
     "POSTGRES_PASSWORD"),
])
@pytest.mark.parametrize("action", ["audit", "block"])
def test_check_input_end_to_end_for_compose_refs_and_comments(content, severity, reason, anchor, action):
    engine = SecurityEngine()
    engine.load_custom_rules([_rule(action)])
    result = engine.check_input("e2e", content, skip_semantic=True)
    [f] = [x for x in result.findings if x.rule_id == "rule_997bd32c"]
    assert f.severity == severity
    assert f.triage.get("severity_downgrade_reason") == reason
    start = content.index(anchor) + anchor.index("PASSWORD")
    assert f.matched_location.startswith(f"content[{start}:")
    assert f.action == action
    assert result.action == action
