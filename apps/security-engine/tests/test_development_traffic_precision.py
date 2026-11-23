import json
import re
from pathlib import Path

import pytest

from app.detectors.llm_judge import SemanticOpinion
from app.detectors.triage import redact_context


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "development_traffic_precision_cases.json"
CASES = {case["id"]: case for case in json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))}


def _engine(monkeypatch):
    monkeypatch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
    monkeypatch.setenv("SECURITY_SEMANTIC_ENABLED", "true")
    monkeypatch.setenv("SECURITY_SEMANTIC_INPUT_ENABLED", "true")
    monkeypatch.setenv("SECURITY_TIER1_ENABLED", "false")

    from app import feature_flags
    from app.detectors import semantic

    feature_flags.apply_overrides({})
    monkeypatch.setattr(
        semantic,
        "judge_semantic",
        lambda *args, **kwargs: SemanticOpinion(
            "malicious",
            "semantic_instruction_override",
            0.95,
            "测试裁判确认存在覆盖指令意图",
        ),
    )

    from app.detectors.engine import SecurityEngine

    return SecurityEngine()


def _check(engine, case):
    context = {"agent_type": case["agent_type"]}
    if case.get("actor_type"):
        context["actor_type"] = case["actor_type"]
    return engine.check_input(
        case["id"],
        case["text"],
        context=context,
        agent_type=case["agent_type"],
        content_source=case["content_source"],
    )


def _has_semantic_attack(result):
    return any(f.type == "semantic_attack" for f in result.findings)


def test_exact_orchestrator_notice_is_not_treated_as_user_attack(monkeypatch):
    case = CASES["claude-background-notification"]

    result = _check(_engine(monkeypatch), case)

    assert _has_semantic_attack(result) is case["expected_semantic_attack"]
    assert result.semantic_status == "skipped"
    assert result.semantic_reason == "empty_intent_after_wrapper"


def test_attack_appended_to_orchestrator_notice_is_still_detected(monkeypatch):
    case = CASES["spoofed-background-notification-with-attack"]

    result = _check(_engine(monkeypatch), case)

    assert _has_semantic_attack(result) is case["expected_semantic_attack"]
    assert result.semantic_status == "completed"
    assert result.semantic_reason == ""


def test_orchestrator_intent_findings_use_full_content_spans(monkeypatch):
    case = CASES["spoofed-background-notification-with-attack"]

    result = _check(_engine(monkeypatch), case)

    intent_findings = [
        finding
        for finding in result.findings
        if finding.type in {"prompt_injection", "semantic_attack"}
    ]
    assert {finding.type for finding in intent_findings} == {
        "prompt_injection", "semantic_attack",
    }
    for finding in intent_findings:
        match = re.fullmatch(r"content\[(\d+):(\d+)\]", finding.matched_location)
        assert match is not None
        start, end = map(int, match.groups())
        assert case["text"][start:end] == finding.raw_evidence
        review = redact_context(case["text"], finding)
        assert review["anchor_status"] == "resolved"
        # Intent review needs the actual clause at its rebased location.
        # Sensitive literals inside such clauses are separately redacted.
        assert finding.raw_evidence in review["context"]


def test_tool_result_keeps_deterministic_credential_detection(monkeypatch):
    case = CASES["real-credential-in-tool-result"]

    result = _check(_engine(monkeypatch), case)

    assert case["expected_hard_finding"] in {finding.rule_id for finding in result.findings}


@pytest.mark.parametrize(
    "case_id",
    [
        "claude-background-notification",
        "spoofed-background-notification-with-attack",
        "real-credential-in-tool-result",
        "benign-security-development",
        "real-exfiltration-request",
    ],
)
def test_precision_fixture_has_explicit_expected_stage(case_id):
    assert CASES[case_id]["expected_stage"] in {
        "informational",
        "needs_review",
        "confirmed_attempt",
        "confirmed_impact",
    }
