import re
from dataclasses import replace

import anyio
import httpx
import pytest

import app.main as main_module
import app.custom_rules as custom_rules
import app.detectors.engine as engine_module
from app.custom_rules import CompiledRule, CustomRuleSet, validate_and_compile_regex
from app.detectors.engine import SecurityEngine, SecurityFinding
from app.detectors.triage import build_triage_payload
from app.reply_generator import DEFAULT_REPLIES, normalize_reply_policy


INTERNAL_HEADER = "X-JJDGuard-Internal-Token"


def test_custom_scan_limit_covers_the_gateway_request_limit():
    assert custom_rules.MAX_SCAN_LEN == 10 * 1024 * 1024


def _post(pattern: str, token: str | None = None) -> httpx.Response:
    async def run() -> httpx.Response:
        headers = {INTERNAL_HEADER: token} if token is not None else {}
        transport = httpx.ASGITransport(app=main_module.app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://security-engine",
        ) as client:
            return await client.post(
                "/admin/v1/internal/regex/validate",
                headers=headers,
                json={"pattern": pattern},
            )

    return anyio.run(run)


@pytest.mark.parametrize(
    ("pattern", "want_error"),
    [
        ("(?=secret)secret", None),
        ("(", "invalid_syntax"),
        ("(a+)+$", "unsafe_regex"),
        ("(a|aa)+$", "unsafe_regex"),
        ("a" * 1001, "unsafe_regex"),
    ],
)
def test_validate_and_compile_regex_matches_runtime_contract(
    pattern: str,
    want_error: str | None,
):
    compiled, error_code = validate_and_compile_regex(pattern)

    assert error_code == want_error
    assert (compiled is None) == (want_error is not None)


def test_custom_rule_set_regex_path_uses_shared_validation_helper(monkeypatch):
    sentinel = re.compile("shared-helper")
    calls: list[str] = []

    def fake_validate(pattern: str):
        calls.append(pattern)
        return sentinel, None

    monkeypatch.setattr(
        custom_rules,
        "validate_and_compile_regex",
        fake_validate,
    )
    rule = CompiledRule(
        rule_id="rule_shared_helper",
        rule_name="共享编译 helper",
        rule_type="regex",
        category="custom",
        severity="medium",
        action="audit",
        regex="source-pattern",
    )

    rules = CustomRuleSet([rule])

    assert calls == ["source-pattern"]
    assert rules.active_rules == [(rule, sentinel)]


def test_custom_rule_match_bounds_each_regex_execution(monkeypatch):
    class TimeoutPattern:
        def __init__(self):
            self.timeouts: list[float] = []

        def search(self, _content: str, *, timeout: float):
            self.timeouts.append(timeout)
            raise TimeoutError("simulated regex timeout")

    pattern = TimeoutPattern()
    monkeypatch.setattr(
        custom_rules,
        "validate_and_compile_regex",
        lambda _pattern: (pattern, None),
    )
    rule = CompiledRule(
        rule_id="rule_timeout_guard",
        rule_name="运行时超时保护",
        rule_type="regex",
        category="custom",
        severity="high",
        action="block",
        regex="accepted-at-admission",
    )

    findings = CustomRuleSet([rule]).match("a" * 200_000)

    assert len(findings) == 1
    assert findings[0].type == "engine_runtime"
    assert findings[0].category == "engine_scan_incomplete"
    assert findings[0].rule_id == rule.rule_id
    assert findings[0].action == "audit"
    assert not findings[0].cannot_downgrade()
    assert findings[0].counts_as_security_finding is False
    assert "a" * 32 not in findings[0].matched_text_preview
    assert "a" * 32 not in findings[0].redacted_evidence
    # 瞬时超时且几乎没耗 CPU（模拟等锁）：按 CPU 预算重试一次，重试仍失败才记 regex_timeout。
    assert len(pattern.timeouts) == 2
    # 单条正则的执行时间必须有硬上限。这份夹具是 200 KiB，按体量因子（每 64 KiB 一档、
    # 封顶 20 档）放宽到 4 倍，所以不能再拿 MAX_REGEX_MATCH_SECONDS 当绝对天花板：
    # 它现在是"普通大小 prompt 的严格预算"，由 test_customer_detection_performance.py 守护。
    assert pattern.timeouts[0] > 0
    assert pattern.timeouts[0] <= 0.2, "单条正则的执行时间不得超过 0.2s"
    assert pattern.timeouts[0] <= 0.5, "整组正则预算不得超过 0.5s"
    assert 0 < pattern.timeouts[1] <= 2.0, "重试的墙钟上限受 SECURITY_REGEX_WALL_MAX_SECONDS 约束"


def test_mask_regex_redacts_every_match_before_returning_content():
    engine = SecurityEngine()
    engine.audit_only = False
    engine.load_custom_rules([
        CompiledRule(
            rule_id="rule_mask_all",
            rule_name="完整脱敏",
            rule_type="regex",
            category="custom_mask_all",
            severity="high",
            action="mask",
            regex=r"SENSITIVE-\d+",
        )
    ])

    result = engine.check_input(
        "request-mask-all",
        "SENSITIVE-111 and SENSITIVE-222",
    )

    assert result.action == "mask"
    assert result.masked_content == "<MASKED> and <MASKED>"
    assert len([item for item in result.findings if item.rule_id == "rule_mask_all"]) == 2


def test_mask_regex_redacts_repeated_identical_values_at_every_span():
    engine = SecurityEngine()
    engine.audit_only = False
    engine.load_custom_rules([
        CompiledRule(
            rule_id="rule_mask_repeated",
            rule_name="重复值完整脱敏",
            rule_type="regex",
            category="custom_mask_repeated",
            severity="high",
            action="mask",
            regex=r"SENSITIVE-\d+",
        )
    ])

    result = engine.check_input(
        "request-mask-repeated",
        "SENSITIVE-111 and SENSITIVE-111",
    )

    assert result.action == "mask"
    assert result.masked_content == "<MASKED> and <MASKED>"
    assert [
        item.matched_location
        for item in result.findings
        if item.rule_id == "rule_mask_repeated"
    ] == ["content[0:13]", "content[18:31]"]


def test_mask_regex_match_limit_forwards_with_alert_instead_of_partial_mask(monkeypatch):
    # Too many matches to mask them all: never return a partial mask, and
    # never escalate the configured "mask" to "block" either.
    monkeypatch.setattr(custom_rules, "MAX_REGEX_MASK_MATCHES", 3)
    engine = SecurityEngine()
    engine.audit_only = False
    engine.load_custom_rules([
        CompiledRule(
            rule_id="rule_mask_limit",
            rule_name="脱敏数量上限",
            rule_type="regex",
            category="custom_mask_limit",
            severity="high",
            action="mask",
            regex=r"SENSITIVE-\d+",
        )
    ])
    content = " ".join(
        f"SENSITIVE-{index}"
        for index in range(custom_rules.MAX_REGEX_MASK_MATCHES + 1)
    )

    result = engine.check_input("request-mask-limit", content)

    assert result.action == "audit"
    assert result.masked_content is None
    assert len(result.findings) == 1
    assert result.findings[0].type == "regex_timeout"
    assert result.findings[0].triage["reason"] == "regex_match_limit"


def test_content_beyond_custom_scan_limit_records_gap_without_partial_mask():
    rule = CompiledRule(
        rule_id="rule_scan_limit",
        rule_name="超长内容完整性保护",
        rule_type="regex",
        category="custom_scan_limit",
        severity="high",
        action="mask",
        regex=r"SENSITIVE-\d+",
    )
    content = "x" * custom_rules.MAX_SCAN_LEN + "SENSITIVE-999"

    guard_findings = CustomRuleSet([rule]).match(content)

    assert len(guard_findings) == 1
    assert guard_findings[0].type == "custom_scan_incomplete"
    assert guard_findings[0].action == "audit"
    assert guard_findings[0].triage["mask_unavailable"] is True
    assert guard_findings[0].triage["reason"] == "custom_scan_limit"
    assert "SENSITIVE-999" not in guard_findings[0].matched_text_preview
    assert "SENSITIVE-999" not in guard_findings[0].redacted_evidence


def test_regex_timeout_skips_shadow_triage_and_never_uses_fixed_reply(monkeypatch):
    class TimeoutPattern:
        def search(self, _content: str, *, timeout: float):
            raise TimeoutError("simulated regex timeout")

    monkeypatch.setattr(
        custom_rules,
        "validate_and_compile_regex",
        lambda _pattern: (TimeoutPattern(), None),
    )
    judge_calls: list[dict] = []
    monkeypatch.setattr(
        engine_module,
        "llm_triage_judge",
        lambda payload, **_kwargs: judge_calls.append(payload)
        or {"verdict": "likely_false_positive"},
    )
    engine = SecurityEngine()
    engine.audit_only = False
    with engine._semantic_config_lock:
        engine._semantic_runtime = replace(
            engine.snapshot_semantic_runtime(),
            llm_judge_mode="shadow",
        )
    engine.load_custom_rules([
        CompiledRule(
            rule_id="rule_timeout_e2e",
            rule_name="超时整链保护",
            rule_type="regex",
            category="custom_timeout_e2e",
            severity="high",
            action="block",
            regex="accepted-at-admission",
        )
    ])
    engine.load_reply_policy(normalize_reply_policy({
        "schema_version": 1,
        "enabled": True,
        "templates": {
            key: DEFAULT_REPLIES[key]
            for key in (
                "default",
                "prompt_injection",
                "content_safety",
                "data_leak",
            )
        },
    }))

    result = engine.check_input("request-timeout-e2e", "attacker-controlled")

    assert result.action == "audit"
    assert result.masked_content is None
    assert judge_calls == []
    timeout_findings = [
        item for item in result.findings if item.type == "engine_runtime"
    ]
    assert len(timeout_findings) == 1
    assert not timeout_findings[0].cannot_downgrade()
    assert timeout_findings[0].counts_as_security_finding is False
    assert timeout_findings[0].triage == {"reason": "regex_timeout"}


def test_triage_payload_evaluates_cannot_downgrade_method_instead_of_bound_method():
    finding = SecurityFinding(
        type="custom",
        category="ordinary",
        severity="medium",
        matched_text_preview="<REDACTED>",
        rule_id="rule_ordinary",
        action="audit",
    )

    payload = build_triage_payload("ordinary content", finding, "input")

    assert payload["finding"]["cannot_downgrade"] is False


def test_regex_validation_endpoint_requires_internal_token(monkeypatch):
    pattern = "auth-canary-pattern"
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "internal-secret")

    response = _post(pattern)

    assert response.status_code == 401
    assert pattern not in response.text


def test_regex_validation_endpoint_fails_closed_when_internal_secret_is_unset(monkeypatch):
    pattern = "unset-secret-canary-pattern"
    monkeypatch.delenv("JJD_INTERNAL_API_SECRET", raising=False)

    response = _post(pattern)

    assert response.status_code == 503
    assert response.json() == {"detail": {"code": "internal_auth_unavailable"}}
    assert pattern not in response.text


def test_regex_validation_endpoint_accepts_python_lookahead(monkeypatch):
    pattern = "(?=secret)secret"
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "internal-secret")

    response = _post(pattern, "internal-secret")

    assert response.status_code == 200
    assert response.json() == {"valid": True, "error_code": None}
    assert pattern not in response.text


@pytest.mark.parametrize(
    ("pattern", "error_code"),
    [
        ("(", "invalid_syntax"),
        ("(a+)+$", "unsafe_regex"),
        ("(a|aa)+$", "unsafe_regex"),
        ("a" * 1001, "unsafe_regex"),
    ],
)
def test_regex_validation_endpoint_returns_only_stable_error_code(
    monkeypatch,
    pattern: str,
    error_code: str,
):
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "internal-secret")

    response = _post(pattern, "internal-secret")

    assert response.status_code == 200
    assert response.json() == {"valid": False, "error_code": error_code}
    assert pattern not in response.text
    assert "unterminated" not in response.text.lower()
    assert "position" not in response.text.lower()


def test_regex_validation_endpoint_bounds_request_without_echo(monkeypatch):
    pattern = "request-limit-canary-" + "x" * 5000
    monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "internal-secret")

    response = _post(pattern, "internal-secret")

    assert response.status_code == 413
    assert pattern not in response.text
    assert response.json() == {"detail": {"code": "request_too_large"}}
