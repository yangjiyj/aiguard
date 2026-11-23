"""Scope excludes a target, never grants trust based on words inside it."""
import pytest

from app import feature_flags as ff
from app.detectors.engine import SecurityEngine


@pytest.fixture
def scoped_engine(monkeypatch):
    ff.apply_overrides({})
    for key, value in {
        "SECURITY_INSPECT_USER_INPUT": "true",
        "SECURITY_INSPECT_MODEL_OUTPUT": "true",
        "SECURITY_INSPECT_BUILTIN_CONTEXT": "false",
        "SECURITY_INSPECT_HISTORY": "false",
        "SECURITY_INSPECT_TOOL_RESULTS": "true",
        "SECURITY_PII_CHECKSUM_ENABLED": "true",
    }.items():
        monkeypatch.setenv(key, value)
    return SecurityEngine()


@pytest.mark.parametrize("source", ["system_prompt", "developer", "tool_def", "assistant_history", "user_history"])
def test_excluded_sources_skip_all_detection(scoped_engine, source):
    result = scoped_engine.check_input("scope", "身份证11010519491231002X", content_source=source)
    assert result.findings == []
    assert result.semantic_status == "skipped"
    assert result.semantic_reason == "inspection_scope_excluded"


@pytest.mark.parametrize("source", ["user", "tool_result", "rag", "", "unknown"])
def test_current_and_untrusted_sources_keep_real_pii(scoped_engine, source):
    result = scoped_engine.check_input("scope", "[system_prompt] 身份证11010519491231002X", content_source=source)
    assert any(f.category == "id_card_cn" for f in result.findings)


def test_history_metadata_must_be_boolean(scoped_engine):
    content = "身份证11010519491231002X"
    skipped = scoped_engine.check_input("scope", content, content_source="user", context={"inspection_is_history": True})
    assert skipped.findings == []
    checked = scoped_engine.check_input("scope", content, content_source="user", context={"inspection_is_history": "true"})
    assert any(f.category == "id_card_cn" for f in checked.findings)
    unknown = scoped_engine.check_input("scope", content, content_source="unknown", context={"inspection_is_history": True})
    assert any(f.category == "id_card_cn" for f in unknown.findings)


def test_output_scope_changes_atomically(scoped_engine):
    content = "身份证11010519491231002X"
    assert scoped_engine.check_output("output", content).findings
    ff.apply_overrides({"SECURITY_INSPECT_MODEL_OUTPUT": "false"})
    try:
        scoped_engine.reconfigure_semantic()
        result = scoped_engine.check_output("output", content)
        assert result.findings == []
        assert result.semantic_reason == "inspection_scope_excluded"
    finally:
        ff.apply_overrides({})


def test_native_scanner_ignores_telemetry_id_and_service_mailbox(scoped_engine):
    result = scoped_engine.check_input("actual-false-alert", '"sum":789739705449372800, noreply@anthropic.com')
    assert not any(f.category in {"id_card_cn", "email"} for f in result.findings)
    result = scoped_engine.check_input("real-pii", "身份证11010519491231002X; customer@example.org")
    assert any(f.category == "id_card_cn" for f in result.findings)
    assert any(f.category == "email" for f in result.findings)
