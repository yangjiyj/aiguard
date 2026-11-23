import importlib

from app import feature_flags as ff


def test_is_enabled_truthy_values(monkeypatch):
    for v in ("1", "true", "True", "yes", "on", "ON"):
        monkeypatch.setenv("X_FLAG", v)
        assert ff.is_enabled("X_FLAG") is True


def test_is_enabled_falsy_and_unset(monkeypatch):
    monkeypatch.delenv("X_FLAG", raising=False)
    assert ff.is_enabled("X_FLAG") is False
    for v in ("0", "false", "no", "off", ""):
        monkeypatch.setenv("X_FLAG", v)
        assert ff.is_enabled("X_FLAG") is False


def test_get_float_parses_and_defaults(monkeypatch):
    monkeypatch.setenv("X_NUM", "0.7")
    assert ff.get_float("X_NUM", 0.1) == 0.7
    monkeypatch.setenv("X_NUM", "not-a-number")
    assert ff.get_float("X_NUM", 0.1) == 0.1
    monkeypatch.delenv("X_NUM", raising=False)
    assert ff.get_float("X_NUM", 0.1) == 0.1


def test_llm_judge_mode_only_off_or_shadow(monkeypatch):
    monkeypatch.delenv(ff.ENV_LLM_JUDGE_MODE, raising=False)
    assert ff.llm_judge_mode() == "off"
    monkeypatch.setenv(ff.ENV_LLM_JUDGE_MODE, "shadow")
    assert ff.llm_judge_mode() == "shadow"
    monkeypatch.setenv(ff.ENV_LLM_JUDGE_MODE, "enforce")
    assert ff.llm_judge_mode() == "off"


def test_default_constants_present():
    assert ff.DEFAULT_LLM_JUDGE_URL.startswith("http://127.0.0.1:8091")
    assert ff.DEFAULT_LLM_JUDGE_MODEL == "qwen2.5-7b-instruct-local"
    assert 0.0 < ff.CONFIDENCE_DOWNGRADE_THRESHOLD < 1.0


def test_semantic_flags_default_off(monkeypatch):
    import app.feature_flags as ff
    monkeypatch.delenv(ff.ENV_SEMANTIC_ENABLED, raising=False)
    monkeypatch.delenv(ff.ENV_SEMANTIC_INPUT_ENABLED, raising=False)
    assert ff.is_enabled(ff.ENV_SEMANTIC_ENABLED) is False
    assert ff.is_enabled(ff.ENV_SEMANTIC_INPUT_ENABLED) is False


def test_semantic_total_timeout_default(monkeypatch):
    import app.feature_flags as ff
    monkeypatch.delenv(ff.ENV_SEMANTIC_TOTAL_TIMEOUT, raising=False)
    assert ff.get_float(ff.ENV_SEMANTIC_TOTAL_TIMEOUT, ff.DEFAULT_SEMANTIC_TOTAL_TIMEOUT) == 8.0


def test_tier1_env_names_and_defaults():
    from app import feature_flags as ff
    assert ff.ENV_TIER1_ENABLED == "SECURITY_TIER1_ENABLED"
    assert ff.ENV_TIER1_URL == "SECURITY_TIER1_URL"
    assert ff.ENV_TIER1_TIMEOUT == "SECURITY_TIER1_TIMEOUT"
    assert ff.ENV_TIER1_LOW_THRESHOLD == "SECURITY_TIER1_LOW_THRESHOLD"
    assert ff.ENV_TIER1_HIGH_THRESHOLD == "SECURITY_TIER1_HIGH_THRESHOLD"
    assert ff.ENV_FP_SUPPRESSION_ENABLED == "SECURITY_FP_SUPPRESSION_ENABLED"
    assert ff.DEFAULT_TIER1_URL == "http://tier1-classifier:8000/classify"
    assert ff.DEFAULT_TIER1_TIMEOUT == 1.0
    assert ff.DEFAULT_TIER1_LOW_THRESHOLD == 0.2
    assert ff.DEFAULT_TIER1_HIGH_THRESHOLD == 0.8


def test_tier1_enabled_default_false(monkeypatch):
    from app import feature_flags as ff
    ff.apply_overrides({})
    monkeypatch.delenv("SECURITY_TIER1_ENABLED", raising=False)
    monkeypatch.delenv("SECURITY_FP_SUPPRESSION_ENABLED", raising=False)
    assert ff.is_enabled(ff.ENV_TIER1_ENABLED) is False
    assert ff.is_enabled(ff.ENV_FP_SUPPRESSION_ENABLED) is False


def test_tier1_thresholds_read_via_get_float(monkeypatch):
    from app import feature_flags as ff
    ff.apply_overrides({})
    monkeypatch.setenv("SECURITY_TIER1_LOW_THRESHOLD", "0.15")
    monkeypatch.setenv("SECURITY_TIER1_HIGH_THRESHOLD", "0.85")
    assert ff.get_float(ff.ENV_TIER1_LOW_THRESHOLD, ff.DEFAULT_TIER1_LOW_THRESHOLD) == 0.15
    assert ff.get_float(ff.ENV_TIER1_HIGH_THRESHOLD, ff.DEFAULT_TIER1_HIGH_THRESHOLD) == 0.85
