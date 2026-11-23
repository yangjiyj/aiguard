import app.feature_flags as ff


def test_override_takes_precedence_then_falls_back_to_env(monkeypatch):
    ff.apply_overrides({})  # 清空
    monkeypatch.setenv("SECURITY_SEMANTIC_ENABLED", "false")
    assert ff.is_enabled("SECURITY_SEMANTIC_ENABLED") is False  # 无 override → 回退 env
    ff.apply_overrides({"SECURITY_SEMANTIC_ENABLED": "true"})
    assert ff.is_enabled("SECURITY_SEMANTIC_ENABLED") is True   # override 覆盖 env
    ff.apply_overrides({})  # 复位
    assert ff.is_enabled("SECURITY_SEMANTIC_ENABLED") is False


def test_get_str_override(monkeypatch):
    ff.apply_overrides({})
    monkeypatch.setenv("SECURITY_LLM_JUDGE_MODEL", "env-model")
    assert ff.get_str("SECURITY_LLM_JUDGE_MODEL", "d") == "env-model"
    ff.apply_overrides({"SECURITY_LLM_JUDGE_MODEL": "db-model"})
    assert ff.get_str("SECURITY_LLM_JUDGE_MODEL", "d") == "db-model"
    ff.apply_overrides({})


def test_tier1_enabled_override_over_env(monkeypatch):
    ff.apply_overrides({})
    monkeypatch.setenv(ff.ENV_TIER1_ENABLED, "false")
    assert ff.is_enabled(ff.ENV_TIER1_ENABLED) is False        # 无 override → env
    ff.apply_overrides({ff.ENV_TIER1_ENABLED: "true"})
    assert ff.is_enabled(ff.ENV_TIER1_ENABLED) is True         # override 覆盖 env
    ff.apply_overrides({})
    assert ff.is_enabled(ff.ENV_TIER1_ENABLED) is False        # 复位回退 env


def test_tier1_thresholds_override_and_fallback(monkeypatch):
    ff.apply_overrides({})
    monkeypatch.setenv(ff.ENV_TIER1_LOW_THRESHOLD, "0.2")
    monkeypatch.setenv(ff.ENV_TIER1_HIGH_THRESHOLD, "0.8")
    assert ff.get_float(ff.ENV_TIER1_LOW_THRESHOLD, 0.0) == 0.2
    assert ff.get_float(ff.ENV_TIER1_HIGH_THRESHOLD, 0.0) == 0.8
    ff.apply_overrides({
        ff.ENV_TIER1_LOW_THRESHOLD: "0.15",
        ff.ENV_TIER1_HIGH_THRESHOLD: "0.85",
    })
    assert ff.get_float(ff.ENV_TIER1_LOW_THRESHOLD, 0.0) == 0.15
    assert ff.get_float(ff.ENV_TIER1_HIGH_THRESHOLD, 0.0) == 0.85
    ff.apply_overrides({})                                      # 复位


def test_fp_suppression_override_over_env(monkeypatch):
    ff.apply_overrides({})
    monkeypatch.setenv(ff.ENV_FP_SUPPRESSION_ENABLED, "false")
    assert ff.is_enabled(ff.ENV_FP_SUPPRESSION_ENABLED) is False
    ff.apply_overrides({ff.ENV_FP_SUPPRESSION_ENABLED: "true"})
    assert ff.is_enabled(ff.ENV_FP_SUPPRESSION_ENABLED) is True
    ff.apply_overrides({})


def test_empty_override_value_does_not_mask_env(monkeypatch):
    # 空 override 值不算设置(apply_overrides 过滤空)→ 仍回退 env,不误清
    monkeypatch.setenv(ff.ENV_TIER1_ENABLED, "true")
    ff.apply_overrides({ff.ENV_TIER1_ENABLED: ""})
    assert ff.is_enabled(ff.ENV_TIER1_ENABLED) is True
    ff.apply_overrides({})
