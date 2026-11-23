from app.semantic_config_loader import map_config_to_overrides


def test_map_config_to_env_names():
    cfg = {
        "semantic_enabled": True, "semantic_input_enabled": True,
        "judge_url": "http://llm-judge:8080/v1/chat/completions",
        "judge_model": "bundled-judge", "judge_api_key": "bundled-judge",
        "semantic_total_timeout": 8,
    }
    ov = map_config_to_overrides(cfg)
    assert ov["SECURITY_SEMANTIC_ENABLED"] == "true"
    assert ov["SECURITY_LLM_JUDGE_URL"] == "http://llm-judge:8080/v1/chat/completions"
    assert ov["SECURITY_LLM_JUDGE_MODEL"] == "bundled-judge"
    assert ov["SECURITY_SEMANTIC_TOTAL_TIMEOUT"] == "8"


def test_map_ignores_empty_judge_fields():
    ov = map_config_to_overrides({"semantic_enabled": True, "judge_url": ""})
    assert "SECURITY_LLM_JUDGE_URL" not in ov  # 空不下发,留给 env 兜底


def test_map_tier1_and_fp_config_keys():
    cfg = {
        "tier1_enabled": True,
        "tier1_low_threshold": 0.15,
        "tier1_high_threshold": 0.85,
        "fp_suppression_enabled": False,
    }
    ov = map_config_to_overrides(cfg)
    assert ov["SECURITY_TIER1_ENABLED"] == "true"
    assert ov["SECURITY_TIER1_LOW_THRESHOLD"] == "0.15"
    assert ov["SECURITY_TIER1_HIGH_THRESHOLD"] == "0.85"
    assert ov["SECURITY_FP_SUPPRESSION_ENABLED"] == "false"


def test_map_tier1_bool_variants_string_form():
    ov = map_config_to_overrides({"tier1_enabled": "on", "fp_suppression_enabled": 1})
    assert ov["SECURITY_TIER1_ENABLED"] == "true"
    assert ov["SECURITY_FP_SUPPRESSION_ENABLED"] == "true"


def test_map_omits_absent_and_none_tier1_keys():
    ov = map_config_to_overrides({"tier1_enabled": None})
    assert "SECURITY_TIER1_ENABLED" not in ov       # None 不下发,留 env 兜底
    ov2 = map_config_to_overrides({})
    for env in ("SECURITY_TIER1_ENABLED", "SECURITY_TIER1_LOW_THRESHOLD",
                "SECURITY_TIER1_HIGH_THRESHOLD", "SECURITY_FP_SUPPRESSION_ENABLED"):
        assert env not in ov2                        # 缺键不下发


def test_map_config_includes_flip_flags():
    from app.semantic_config_loader import map_config_to_overrides
    from app import feature_flags as ff
    ov = map_config_to_overrides({
        "source_aware_enabled": True,
        "confidence_gating_enabled": True,
        "coding_traffic_downgrade_enabled": False,
    })
    assert ov[ff.ENV_SOURCE_AWARE] == "true"
    assert ov[ff.ENV_CONFIDENCE_GATING] == "true"
    assert ov[ff.ENV_CODING_TRAFFIC_DOWNGRADE] == "false"


def test_managed_custom_judge_accepts_plain_http_only_with_private_egress():
    import json
    import pathlib

    import pytest

    from app.semantic_config_loader import _validate_managed_config

    fixture = pathlib.Path(__file__).parent / "fixtures" / "internal_semantic_config.json"
    base = json.loads(fixture.read_text(encoding="utf-8"))
    base.update({
        "judge_backend": "custom",
        "judge_url": "http://172.16.20.10:8000/v1/chat/completions",
        "judge_model": "qwen-judge",
        "judge_api_key": "k",
    })

    base["judge_allow_private_egress"] = True
    _validate_managed_config(base)

    base["judge_allow_private_egress"] = False
    with pytest.raises(ValueError):
        _validate_managed_config(base)

    base["judge_url"] = "https://judge.example/v1/chat/completions"
    _validate_managed_config(base)


def test_unchanged_heartbeat_preserves_completed_windows_but_changed_config_reloads(monkeypatch):
    import json
    from pathlib import Path
    from types import SimpleNamespace
    from app import semantic_config_loader as loader, feature_flags as ff
    cfg = json.loads((Path(__file__).parent / "fixtures" / "internal_semantic_config.json").read_text())
    held = [""]
    reloads, reports, completed = [], [], {}
    monkeypatch.setattr(ff, "_OVERRIDES", {})
    monkeypatch.setattr(loader.httpx, "get", lambda *a, **k: SimpleNamespace(raise_for_status=lambda:None, json=lambda:dict(cfg)))
    monkeypatch.setattr(loader, "_auth_headers", lambda token:{})
    monkeypatch.setattr(loader, "_verify_managed_config_attestation", lambda c:None)
    monkeypatch.setattr(loader, "_held_revision", lambda:held[0])
    monkeypatch.setattr(loader, "_judge_required", lambda c:False)
    monkeypatch.setattr(loader, "_report_runtime", lambda *a, **k:reports.append(k))
    def reconfigure(revision):
        held[0] = revision
        reloads.append(revision)
        completed.clear()
    monkeypatch.setattr(loader, "_reconfigure_live_engine", reconfigure)
    loader._fetch_once("http://control-plane", "", 1)
    completed["window"] = "benign"
    loader._fetch_once("http://control-plane", "", 1)
    assert len(reloads) == 1 and completed == {"window":"benign"}
    assert len(reports) == 2 and all(r["config_loaded"] for r in reports)
    cfg["semantic_input_enabled"] = not cfg["semantic_input_enabled"]
    loader._fetch_once("http://control-plane", "", 1)
    assert len(reloads) == 2 and not completed


def test_semantic_block_min_confidence_is_optional_and_range_checked():
    import json
    import pathlib

    import pytest

    from app import feature_flags as ff
    from app.semantic_config_loader import _validate_managed_config

    fixture = pathlib.Path(__file__).parent / "fixtures" / "internal_semantic_config.json"
    base = json.loads(fixture.read_text(encoding="utf-8"))
    legacy = dict(base)
    legacy.pop("semantic_block_min_confidence", None)
    _validate_managed_config(legacy)  # 旧 control-plane 不下发：引擎取默认 0.85
    assert ff.ENV_SEMANTIC_BLOCK_MIN_CONFIDENCE not in map_config_to_overrides(legacy)

    for good in ("0.5", "0.85", "1"):
        _validate_managed_config({**base, "semantic_block_min_confidence": good})
    for bad in ("0.49", "1.01", "nan", "abc", 0.9):
        with pytest.raises(ValueError):
            _validate_managed_config({**base, "semantic_block_min_confidence": bad})
    overrides = map_config_to_overrides({**base, "semantic_block_min_confidence": "0.9"})
    assert overrides[ff.ENV_SEMANTIC_BLOCK_MIN_CONFIDENCE] == "0.9"


def test_runtime_disposition_and_block_stage_keys_are_optional_and_validated():
    # 2.9.22：三个新键旧控制面不下发时取引擎缺省。
    # 复审第四轮改动：原断言“非法值整份拒绝”。与网关一致后，取值是字符串但不认识时只把该键当未下发
    # （见 test_unknown_engine_option_value_only_drops_that_key），取值不是字符串仍整份拒绝。
    import json
    import pathlib

    import pytest

    from app import feature_flags as ff
    from app.semantic_config_loader import _validate_managed_config

    fixture = pathlib.Path(__file__).parent / "fixtures" / "internal_semantic_config.json"
    base = json.loads(fixture.read_text(encoding="utf-8"))
    legacy = {k: v for k, v in base.items() if k not in {
        "agent_security_monitor_disposition", "model_output_classified_disposition", "semantic_block_stages"}}
    _validate_managed_config(legacy)
    overrides = map_config_to_overrides(legacy)
    assert ff.ENV_AGENT_SECURITY_MONITOR_DISPOSITION not in overrides
    assert ff.ENV_MODEL_OUTPUT_CLASSIFIED_DISPOSITION not in overrides
    assert ff.ENV_SEMANTIC_BLOCK_STAGES not in overrides

    good = {
        **legacy,
        "agent_security_monitor_disposition": "follow_policy",
        "model_output_classified_disposition": "observe",
        "semantic_block_stages": '["agent","input"]',
    }
    _validate_managed_config(good)
    overrides = map_config_to_overrides(good)
    assert overrides[ff.ENV_AGENT_SECURITY_MONITOR_DISPOSITION] == "follow_policy"
    assert overrides[ff.ENV_MODEL_OUTPUT_CLASSIFIED_DISPOSITION] == "observe"
    assert json.loads(overrides[ff.ENV_SEMANTIC_BLOCK_STAGES]) == ["agent", "input"]
    for key, bad in (
        ("model_output_classified_disposition", True),
        ("semantic_block_stages", ["input"]),
        ("agent_security_monitor_disposition", 1),
    ):
        with pytest.raises(ValueError):
            _validate_managed_config({**legacy, key: bad})



def test_unknown_engine_option_value_only_drops_that_key(caplog):
    # 复审第四轮：签名里引擎键的取值不认识时只忽略该键（与网关一致），其余照常生效；日志只在值变化时打。
    import json
    import logging
    import pathlib

    from app import feature_flags as ff
    from app import semantic_config_loader as loader

    fixture = pathlib.Path(__file__).parent / "fixtures" / "internal_semantic_config.json"
    base = json.loads(fixture.read_text(encoding="utf-8"))
    loader._IGNORED_ENGINE_OPTION_VALUES.clear()
    for key, bad in (
        ("agent_security_monitor_disposition", "block"),
        ("semantic_block_stages", '["input","bogus"]'),
        ("semantic_block_stages", "[]"),
        ("semantic_block_stages", "input"),
    ):
        config = {**base, "model_output_classified_disposition": "follow_policy", key: bad}
        loader._validate_managed_config(config)
        kept = loader._drop_unknown_engine_options(config)
        assert key not in kept
        overrides = map_config_to_overrides(kept)
        env = loader._OPTIONAL_CHOICE_KEYS[key]
        assert env not in overrides, (key, overrides)
        assert overrides[ff.ENV_MODEL_OUTPUT_CLASSIFIED_DISPOSITION] == "follow_policy"
    loader._IGNORED_ENGINE_OPTION_VALUES.clear()
    caplog.clear()
    config = {**base, "agent_security_monitor_disposition": "block"}
    with caplog.at_level(logging.WARNING, logger=loader.logger.name):
        loader._drop_unknown_engine_options(config)
        loader._drop_unknown_engine_options(config)
        loader._drop_unknown_engine_options({**base, "agent_security_monitor_disposition": "deny"})
    ignored = [r for r in caplog.records if "agent_security_monitor_disposition" in r.getMessage()]
    assert len(ignored) == 2, [r.getMessage() for r in ignored]
