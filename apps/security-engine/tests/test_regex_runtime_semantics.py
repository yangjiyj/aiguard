import logging
import time

import pytest

from app.detectors.engine import SecurityEngine
from app import custom_rules
from app.custom_rules import (
    CompiledException,
    CompiledRule,
    CustomRuleSet,
    ExceptionSet,
)
from app.policy_bindings import CompiledPolicy, PolicySet
from app.principal_context import PrincipalContext


class TimeoutPattern:
    def search(self, _content: str, *, timeout: float):
        raise TimeoutError("simulated regex timeout")

    def finditer(self, _content: str, *, timeout: float):
        raise TimeoutError("simulated regex timeout")


def make_rule(
    action: str,
    *,
    rule_id: str | None = None,
    pattern: str = r"ZZHIT\d+",
) -> CompiledRule:
    return CompiledRule(
        rule_id=rule_id or f"rule_{action}",
        rule_name=f"runtime {action}",
        rule_type="regex",
        category="custom_runtime_action",
        severity="high",
        action=action,
        regex=pattern,
    )


@pytest.mark.parametrize("action", ["mask", "block", "audit", "allow"])
def test_regex_action_matrix_normal_hit(action):
    finding = CustomRuleSet([make_rule(action)]).match("before ZZHIT123 after")[0]

    assert finding.type == "custom"
    assert finding.category == "custom_runtime_action"
    assert finding.severity == "high"
    assert finding.action == action
    assert finding.counts_as_security_finding is True


@pytest.mark.parametrize("action", ["mask", "block", "audit", "allow"])
def test_regex_action_matrix_timeout_has_action_specific_semantics(monkeypatch, action):
    monkeypatch.setattr(
        custom_rules,
        "validate_and_compile_regex",
        lambda _pattern: (TimeoutPattern(), None),
    )

    finding = CustomRuleSet([make_rule(action)]).match("attacker-controlled")[0]

    if action == "mask":
        # A mask scan that timed out cannot guarantee masking: recorded as an
        # alert and marked mask_unavailable, never escalated to block.
        assert finding.type == "regex_timeout"
        assert finding.category == "custom_regex_timeout"
        assert finding.severity == "medium"
        assert finding.action == "audit"
        assert finding.triage.get("mask_unavailable") is True
        assert finding.evidence_kind == "runtime"
        assert finding.counts_as_security_finding is False
    else:
        assert finding.type == "engine_runtime"
        assert finding.category == "engine_scan_incomplete"
        assert finding.severity == "low"
        assert finding.action == "audit"
        assert not finding.cannot_downgrade()
        assert finding.counts_as_security_finding is False


def test_detection_timeout_is_auditable_but_does_not_block_pentagi_like_request(
    monkeypatch,
):
    monkeypatch.setattr(
        custom_rules,
        "validate_and_compile_regex",
        lambda _pattern: (TimeoutPattern(), None),
    )
    engine = SecurityEngine()
    engine.load_custom_rules([make_rule("block", rule_id="rule_g_email")])
    payload = (
        "POST /exploit?q=%27OR%201=1-- shell=${jndi:ldap://127.0.0.1/a} "
        + " user"
        + "a" * 48
        + "@"
        + "subdomain-" * 8
        + "invalid"
    ) * 700

    result = engine.check_input("pentagi-regex-timeout", payload)

    incomplete = [f for f in result.findings if f.category == "engine_scan_incomplete"]
    assert result.action == "audit"
    assert len(incomplete) == 1
    assert incomplete[0].rule_id == "rule_g_email"
    assert incomplete[0].counts_as_security_finding is False


def test_detection_timeout_can_be_downgraded_by_approved_compiled_exception(monkeypatch):
    monkeypatch.setattr(
        custom_rules,
        "validate_and_compile_regex",
        lambda _pattern: (TimeoutPattern(), None),
    )
    finding = CustomRuleSet([make_rule("block")]).match("payload")[0]
    exception = CompiledException(
        exception_id="exc-approved-runtime-timeout",
        scope_type="rule",
        rule_id="rule_block",
        decision="allow",
        reason="approved operational exception",
    )

    downgraded = ExceptionSet([exception]).apply([finding])[0]

    assert downgraded.action == "allow"
    assert downgraded.exception_id == exception.exception_id


@pytest.mark.parametrize("direction", ["input", "output"])
def test_engine_passes_principal_to_key_scoped_content_exceptions(direction):
    engine = SecurityEngine()
    engine.load_custom_rules([make_rule("block", rule_id="rule_key_scope")])
    engine.load_content_audit_exceptions(ExceptionSet([
        CompiledException(
            exception_id="exc-key-scope",
            scope_type="key_v1",
            scope_ref="key-a",
            rule_id="rule_key_scope",
            decision="audit",
            reason="key-specific false positive",
        ),
    ]))
    principal = PrincipalContext(
        schema_version=1,
        tenant_id="tenant-a",
        key_id="key-a",
        identity_source="api_key",
        trust_level="key_bound",
    )

    if direction == "input":
        result = engine.check_input(
            "req-key-input",
            "before ZZHIT123 after",
            context={"tenant_id": "tenant-a"},
            skip_semantic=True,
            principal=principal,
        )
    else:
        result = engine.check_output(
            "req-key-output",
            "before ZZHIT123 after",
            context={"tenant_id": "tenant-a"},
            skip_semantic=True,
            principal=principal,
        )

    scoped = [
        finding for finding in result.findings
        if finding.rule_id == "rule_key_scope"
    ]
    assert len(scoped) == 1
    assert scoped[0].exception_id == "exc-key-scope"
    assert scoped[0].action == "audit"


@pytest.mark.parametrize("direction", ["input", "output"])
def test_engine_rejects_cross_tenant_principal_for_key_exception(direction):
    engine = SecurityEngine()
    engine.load_custom_rules([make_rule("block", rule_id="rule_key_scope")])
    engine.load_content_audit_exceptions(ExceptionSet([
        CompiledException(
            exception_id="exc-key-scope",
            scope_type="key_v1",
            scope_ref="key-a",
            rule_id="rule_key_scope",
            decision="audit",
        ),
    ]))
    principal = PrincipalContext(
        schema_version=1,
        tenant_id="tenant-other",
        key_id="key-a",
        identity_source="api_key",
        trust_level="key_bound",
    )
    kwargs = {
        "request_id": f"req-cross-tenant-{direction}",
        "content": "before ZZHIT123 after",
        "context": {"tenant_id": "tenant-a"},
        "skip_semantic": True,
        "principal": principal,
    }

    if direction == "input":
        result = engine.check_input(**kwargs)
    else:
        result = engine.check_output(**kwargs)

    scoped = [
        finding for finding in result.findings
        if finding.rule_id == "rule_key_scope"
    ]
    assert len(scoped) == 1
    assert scoped[0].exception_id == ""
    assert scoped[0].action == "block"


def test_timeout_and_budget_exhaustion_are_counted_by_rule_id(monkeypatch, caplog):
    monkeypatch.setattr(
        custom_rules,
        "validate_and_compile_regex",
        lambda _pattern: (TimeoutPattern(), None),
    )
    ruleset = CustomRuleSet([make_rule("audit", rule_id="slow-rule")])
    with caplog.at_level(logging.WARNING, logger="app.custom_rules"):
        ruleset.match("payload")
        ruleset.match("payload")

    assert ruleset.runtime_failure_counts[("slow-rule", "regex_timeout")] == 2
    assert "rule_id=slow-rule" in caplog.text
    assert "count=2" in caplog.text

    monkeypatch.setattr(custom_rules, "MAX_REGEX_RULESET_SECONDS", 0.0)
    budget_ruleset = CustomRuleSet([make_rule("allow", rule_id="budget-rule")])
    budget_ruleset.match("payload")
    assert budget_ruleset.runtime_failure_counts[
        ("budget-rule", "regex_budget_exhausted")
    ] == 1


def test_rule_g_email_hardened_regex_p99_under_five_ms_on_100k_pentagi_text():
    pattern, error = custom_rules.validate_and_compile_regex(
        custom_rules.RULE_G_EMAIL_REGEX
    )
    assert error is None
    assert pattern is not None
    payload = ((
        "POST /api exploit payload=%27OR%201=1-- contact user"
        + "a" * 48
        + "@"
        + "subdomain-" * 8
        + "invalid "
    ) * 900)[:100_000]
    assert len(payload) == 100_000

    samples_ms = []
    for _ in range(1000):
        started = time.perf_counter()
        assert pattern.search(
            payload,
            timeout=custom_rules.MAX_REGEX_MATCH_SECONDS,
        ) is None
        samples_ms.append((time.perf_counter() - started) * 1000)

    p99_ms = sorted(samples_ms)[989]
    assert p99_ms < 5.0, f"rule_g_email p99={p99_ms:.3f}ms"


def test_rule_g_email_uses_hardened_runtime_pattern_even_for_stale_rule_pack():
    stale = make_rule(
        "audit",
        rule_id="rule_g_email",
        pattern=r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    )

    ruleset = CustomRuleSet([stale])

    assert ruleset.active_rules[0][1].pattern == custom_rules.RULE_G_EMAIL_REGEX
    assert "email_local" in ruleset.active_rules[0][1].groupindex
    finding = ruleset.match("contact alice.long+tag@sub.example-security.com")[0]
    assert finding.rule_id == "rule_g_email"
    assert finding.matched_location == "content[8:47]"
    assert "alice.long+tag@sub.example-security.com" not in finding.redacted_evidence


def test_detection_timeout_stays_audit_after_block_matcher_policy(monkeypatch):
    monkeypatch.setattr(
        custom_rules,
        "validate_and_compile_regex",
        lambda _pattern: (TimeoutPattern(), None),
    )
    engine = SecurityEngine()
    engine.load_custom_rules([make_rule("block", rule_id="rule_g_email")])
    engine.load_policies(PolicySet([
        CompiledPolicy(
            policy_code="builtin.data.email",
            policy_id="policy.data.email",
            policy_name="邮箱检测",
            policy_type="matcher_policy",
            scene="data_leak",
            matcher_rule_id="rule_g_email",
            action="block",
            enabled=True,
            binding_mode="any",
            capabilities=[],
        )
    ]))

    result = engine.check_input("policy-timeout", "attacker-controlled")

    assert result.action == "audit"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.type == "engine_runtime"
    assert finding.action == "audit"
    assert finding.rule_id == "policy.data.email"
    assert finding.source_rule_id == "rule_g_email"
    assert finding.counts_as_security_finding is False


def test_content_over_scan_limit_records_mask_rule_gap_without_blocking():
    audit_rule = make_rule("audit", rule_id="first-audit")
    mask_rule = make_rule("mask", rule_id="later-mask")
    content = "x" * (custom_rules.MAX_SCAN_LEN + 1)

    findings = CustomRuleSet([audit_rule, mask_rule]).match(content)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "later-mask"
    assert finding.type == "custom_scan_incomplete"
    assert finding.action == "audit"
    assert finding.triage.get("mask_unavailable") is True
    assert finding.evidence_kind == "runtime"
    assert finding.counts_as_security_finding is False
