import pytest

from app import feature_flags as ff
from app.detectors.engine import SecurityEngine


@pytest.fixture(autouse=True)
def _clear_managed_overrides():
    ff.apply_overrides({})
    yield
    ff.apply_overrides({})


def test_startup_selfcheck_passes_when_audit_only_paths_audit(monkeypatch):
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")

    from app.startup_selfcheck import assert_production_audit_only

    assert_production_audit_only(SecurityEngine())


def test_startup_selfcheck_accepts_missing_env_as_legacy_strict_fallback(monkeypatch):
    monkeypatch.delenv("SECURITY_AUDIT_ONLY", raising=False)

    from app.startup_selfcheck import assert_production_audit_only

    engine = SecurityEngine()

    assert engine.audit_only is False
    assert_production_audit_only(engine)


def test_startup_selfcheck_accepts_strict_runtime_when_env_default_is_strict(monkeypatch):
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "false")
    monkeypatch.setenv("SECURITY_CONFIDENCE_GATING_ENABLED", "true")
    engine = SecurityEngine()

    from app.startup_selfcheck import assert_production_audit_only

    assert engine.audit_only is False
    assert_production_audit_only(engine)


def test_startup_selfcheck_uses_managed_runtime_not_environment(monkeypatch):
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")
    ff.apply_overrides({"SECURITY_AUDIT_ONLY": "false"})
    engine = SecurityEngine()

    from app.startup_selfcheck import assert_production_audit_only

    assert engine.audit_only is False
    assert_production_audit_only(engine)


def test_startup_selfcheck_reports_blocking_path(monkeypatch):
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")
    engine = SecurityEngine()

    def _blocking_check_output(request_id, content, context=None):
        result = SecurityEngine().check_output(request_id, content, context)
        result.action = "block"
        return result

    engine.check_output = _blocking_check_output

    from app.startup_selfcheck import (
        StartupSelfCheckError,
        assert_production_audit_only,
    )

    with pytest.raises(StartupSelfCheckError) as exc:
        assert_production_audit_only(engine)

    assert "check_output" in str(exc.value)
    assert "block" in str(exc.value)


def test_startup_selfcheck_holds_one_runtime_snapshot_during_managed_reload(monkeypatch):
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "false")
    engine = SecurityEngine()
    original_check_input = engine.check_input

    def _check_then_reload(*args, **kwargs):
        result = original_check_input(*args, **kwargs)
        ff.apply_overrides({"SECURITY_AUDIT_ONLY": "true"})
        return result

    engine.check_input = _check_then_reload

    from app.startup_selfcheck import assert_runtime_policy_consistency

    assert_runtime_policy_consistency(engine)
