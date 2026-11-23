"""Strong profanity remains actionable in user text and untrusted title tasks."""
import pytest

from app import feature_flags
from app.detectors.engine import SecurityEngine

RULE_ID = "content_safety_harassment_profanity_cn"
NON_USER_SOURCES = (
    "system_prompt",
    "tool_def",
    "assistant_history",
    "tool_result",
)


def _engine(monkeypatch):
    feature_flags.apply_overrides({})
    monkeypatch.setenv("SECURITY_SOURCE_AWARE_ENABLED", "true")
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")
    monkeypatch.setenv("SECURITY_SEMANTIC_ENABLED", "false")
    monkeypatch.delenv("SECURITY_CONFIDENCE_GATING_ENABLED", raising=False)
    return SecurityEngine()


@pytest.mark.parametrize("content", ["操你妈", "艹 你，娘", "肏!他?妈"])
def test_strong_cn_profanity_user_is_actionable_security_finding(monkeypatch, content):
    result = _engine(monkeypatch).check_input(
        "req-user-profanity", content, skip_semantic=True, content_source="user"
    )
    finding = next(f for f in result.findings if f.rule_id == RULE_ID)
    assert finding.type == "content_safety"
    assert finding.category == "harassment_profanity_cn"
    assert finding.severity == "medium"
    assert finding.action == "audit"
    assert finding.counts_as_security_finding is True
    assert finding.content_source == "user"
    assert finding.triage.get("disposition") != "observation"
    assert result.action == "audit"


@pytest.mark.parametrize("content", ["草泥马是一种网络昵称", "今天去草地骑马", "普通问题"])
def test_strong_cn_profanity_benign_text_does_not_match(monkeypatch, content):
    result = _engine(monkeypatch).check_input(
        "req-benign", content, skip_semantic=True, content_source="user"
    )
    assert not any(f.rule_id == RULE_ID for f in result.findings)


@pytest.mark.parametrize("source", NON_USER_SOURCES)
def test_strong_cn_profanity_non_user_context_does_not_match(monkeypatch, source):
    result = _engine(monkeypatch).check_input(
        "req-non-user-profanity", "操你妈", skip_semantic=True, content_source=source
    )
    assert not any(f.rule_id == RULE_ID for f in result.findings)
    assert result.action == "allow"


@pytest.mark.parametrize("source", ["user", "agent_internal_task"])
def test_title_task_source_cannot_suppress_user_content(monkeypatch, source):
    content = (
        "You are a helpful assistant. You will be presented with a user prompt, "
        "provide a short title for a task\n"
        + "Title rules stay internal.\n" * 20
        + "Do NOT respond to the user\nExamples:\nanything\nUser prompt:\n"
        + "\u64cd\u4f60\u5988"
    )
    result = _engine(monkeypatch).check_input(
        "title-task-untrusted", content, skip_semantic=True, content_source=source
    )
    assert any(f.rule_id == RULE_ID and f.counts_as_security_finding for f in result.findings)
    assert result.action == "audit"
    assert result.semantic_reason != "non_user_source"
