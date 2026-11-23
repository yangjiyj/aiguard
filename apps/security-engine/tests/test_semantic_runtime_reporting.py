from __future__ import annotations

import hashlib
import hmac
import httpx
import pytest

from app import feature_flags as ff
from app.detectors.semantic import SemanticDetector, SemanticOpinion
from app.semantic_config_loader import (
    _effective_managed_config,
    _enter_safe_record_mode_without_last_good,
    _fetch_once,
    _probe_managed_judge,
    _verify_managed_config_attestation,
    map_config_to_overrides,
)
from app.startup_selfcheck import assert_runtime_policy_consistency


@pytest.fixture(autouse=True)
def _engine_attestation(monkeypatch):
    monkeypatch.setenv("SECURITY_RULE_PACK_ATTESTATION_TOKEN", "test-attestation")
    monkeypatch.setattr(
        "app.detectors.llm_judge._post_chat",
        lambda *a, **k: '{"verdict":"benign","category":"none","confidence":0.99,"reason":"health"}',
    )
    from app.detectors import llm_judge
    llm_judge._reset_breakers()
    ff.apply_overrides({})
    yield
    ff.apply_overrides({})


def test_semantic_config_maps_global_audit_ceiling():
    overrides = map_config_to_overrides({"security_audit_only": False})
    assert overrides["SECURITY_AUDIT_ONLY"] == "false"



def test_first_refresh_failure_enters_safe_record_without_last_good(monkeypatch):
    applied = []
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "false")
    monkeypatch.setattr("app.semantic_config_loader._held_revision", lambda: "")
    monkeypatch.setattr(
        "app.semantic_config_loader._reconfigure_live_engine",
        lambda revision=None: applied.append(revision),
    )
    _enter_safe_record_mode_without_last_good()
    assert ff.is_enabled(ff.ENV_AUDIT_ONLY) is True
    assert applied == [None]


def test_deployment_audit_only_does_not_override_signed_protect(monkeypatch):
    # 2.9.22（设计 D7）：控制台显式选了防护阻断（投影带 security_execution_mode_managed）时，
    # 引擎容器的 SECURITY_AUDIT_ONLY 不再把它改回只审计。原断言（强制 record、改签名）随之改写。
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")
    config = _complete_managed_config()
    config["security_audit_only"] = False
    config["security_execution_mode_managed"] = True
    config = _sign_managed_config(config)
    effective = _effective_managed_config(config)
    assert effective["security_audit_only"] is False
    assert effective == config



@pytest.mark.parametrize("audit_only", [False, True], ids=["protect", "record"])
@pytest.mark.parametrize("managed", [True, False, None], ids=["managed", "legacy-false", "legacy-absent"])
def test_deployment_audit_only_is_only_an_initial_value(
    monkeypatch, audit_only, managed
):
    # 2.9.22（设计 D7，与网关同口径）：投影带 security_execution_mode_managed=true（控制台
    # 显式选过）时按投影执行；没有显式模式时，引擎容器的 SECURITY_AUDIT_ONLY=true 作初值。
    # 原测试（P0 2026-09-27“部署锁是硬上限”）断言 effective 恒为 True，随用户 11-17 决定改写。
    monkeypatch.setenv(ff.ENV_AUDIT_ONLY, "true")
    config = _complete_managed_config()
    config["security_audit_only"] = audit_only
    if managed is not None:
        config["security_execution_mode_managed"] = managed
    config = _sign_managed_config(config)

    effective = _effective_managed_config(config)

    expected = audit_only if managed is True else True
    assert effective["security_audit_only"] is expected
    if expected == audit_only:
        assert effective == config
    _verify_managed_config_attestation(effective)


@pytest.mark.parametrize("audit_only", [False, True], ids=["protect", "record"])
def test_effective_managed_mode_applies_without_deployment_lock(monkeypatch, audit_only):
    monkeypatch.setenv(ff.ENV_AUDIT_ONLY, "")
    config = _complete_managed_config()
    config["security_audit_only"] = audit_only
    config["security_execution_mode_managed"] = True
    config = _sign_managed_config(config)

    effective = _effective_managed_config(config)

    assert effective["security_audit_only"] is audit_only
    assert effective == config


@pytest.mark.parametrize("audit_only,expected_action", [(False, "block"), (True, "audit")])
def test_fetch_managed_mode_controls_real_policy_decisions_and_reports_revision(
    monkeypatch, audit_only, expected_action
):
    import importlib
    from app.policy_bindings import CompiledPolicy, CompiledPolicyCapability, PolicySet

    engine_module = importlib.import_module("app.detectors.engine")
    # 客户部署不设部署锁：控制台 managed 模式决定真实策略动作。
    monkeypatch.setenv(ff.ENV_AUDIT_ONLY, "")
    managed_engine = engine_module.SecurityEngine()
    managed_engine.load_policies(PolicySet([CompiledPolicy(
        policy_code="managed.secret.block",
        policy_id="policy.managed.secret.block",
        policy_name="Managed secret blocking",
        policy_type="scene_policy",
        scene="data_leak",
        action="block",
        enabled=True,
        binding_mode="any",
        capabilities=[CompiledPolicyCapability(
            category="generic_api_key",
            supported_stages=["input", "output"],
            allowed_actions=["audit", "block"],
            mask_capable=False,
        )],
    )]))
    monkeypatch.setattr(engine_module, "engine", managed_engine)
    config = _complete_managed_config()
    config.update({
        "security_audit_only": audit_only,
        "security_execution_mode_managed": True,
        "semantic_enabled": False,
    })
    config = _sign_managed_config(config)
    reports = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return config

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(
        httpx, "post",
        lambda url, *, headers, json, timeout: reports.append(json) or Response(),
    )

    revision = _fetch_once("http://control-plane:8081", "internal-token", 5.0)

    assert managed_engine.audit_only is audit_only
    assert ff.is_enabled(ff.ENV_AUDIT_ONLY) is audit_only
    assert revision == config["revision"] == managed_engine.semantic_config_revision
    assert reports[0]["applied_revision"] == revision
    for stage in ("input", "output"):
        result = getattr(managed_engine, f"check_{stage}")(
            f"managed-mode-{stage}", "api_key=ordinaryvalue123456",
        )
        assert result.action == expected_action
        assert any(f.policy_code == "managed.secret.block" for f in result.findings)


@pytest.mark.parametrize("marker", ["true", "false", 1, 0, None, [], {}])
def test_fetch_rejects_non_boolean_managed_mode_marker_before_apply(monkeypatch, marker):
    config = _complete_managed_config()
    config["security_execution_mode_managed"] = marker
    # Strings can have a valid attestation and must still fail the JSON boolean contract.
    if isinstance(marker, str):
        config = _sign_managed_config(config)

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return config

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(
        "app.semantic_config_loader._reconfigure_live_engine",
        lambda revision: pytest.fail("invalid marker must not reach the live engine"),
    )
    monkeypatch.setattr(
        httpx, "post", lambda *args, **kwargs: pytest.fail("invalid marker must not be reported applied"),
    )
    previous = {ff.ENV_AUDIT_ONLY: "true"}
    ff.apply_overrides(previous)

    with pytest.raises(ValueError, match="security_execution_mode_managed must be boolean"):
        _fetch_once("http://control-plane:8081", "internal-token", 5.0)

    assert ff.snapshot_overrides() == previous


@pytest.mark.parametrize("tamper", ["insert", "change", "remove"])
def test_fetch_rejects_managed_marker_tampering_and_preserves_last_good(monkeypatch, tamper):
    config = _complete_managed_config()
    config["security_audit_only"] = False
    if tamper != "insert":
        config["security_execution_mode_managed"] = False
    config = _sign_managed_config(config)
    if tamper == "remove":
        del config["security_execution_mode_managed"]
    else:
        config["security_execution_mode_managed"] = True

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return config

    monkeypatch.setenv(ff.ENV_AUDIT_ONLY, "true")
    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(
        "app.semantic_config_loader._reconfigure_live_engine",
        lambda revision: pytest.fail("tampered marker must not reach the live engine"),
    )
    monkeypatch.setattr(
        httpx, "post", lambda *args, **kwargs: pytest.fail("tampered marker must not be reported applied"),
    )
    previous = {ff.ENV_AUDIT_ONLY: "true"}
    ff.apply_overrides(previous)

    with pytest.raises(ValueError, match="attestation"):
        _fetch_once("http://control-plane:8081", "internal-token", 5.0)

    assert ff.snapshot_overrides() == previous


def test_semantic_config_maps_file_content_dlp_boolean():
    """全局文件 DLP 开关必须以 JSON boolean 流过托管配置键映射。"""
    overrides = map_config_to_overrides({"file_content_dlp_enabled": True})
    assert overrides[ff.ENV_FILE_CONTENT_DLP] == "true"
    overrides_off = map_config_to_overrides({"file_content_dlp_enabled": False})
    assert overrides_off[ff.ENV_FILE_CONTENT_DLP] == "false"


def test_fetch_once_applies_revision_then_reports(monkeypatch):
    calls: list[tuple[str, dict]] = []

    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return _complete_managed_config()

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())

    class PostResponse:
        status_code = 200

        def raise_for_status(self):
            return None

    def fake_post(url, *, headers, json, timeout):
        calls.append((url, {"headers": headers, "json": json, "timeout": timeout}))
        return PostResponse()

    monkeypatch.setattr(httpx, "post", fake_post)
    monkeypatch.setattr("app.semantic_config_loader._reconfigure_live_engine", lambda revision: None)
    ff.apply_overrides({})

    revision = _fetch_once("http://control-plane:8081", "internal-token", 5.0)

    assert revision == _complete_managed_config()["revision"]
    assert calls[0][0].endswith("/admin/v1/internal/security/semantic-runtime-report/engine")
    assert calls[0][1]["json"]["component"] == "security-engine"
    assert calls[0][1]["json"]["applied_revision"] == revision
    assert "internal-token" not in repr(calls[0][1]["json"])
    assert ff.is_enabled("SECURITY_AUDIT_ONLY") is True
    ff.apply_overrides({})


def test_fetch_once_applies_strict_db_runtime_and_attests_revision(monkeypatch):
    import importlib

    engine_module = importlib.import_module("app.detectors.engine")
    monkeypatch.setenv("SECURITY_AUDIT_ONLY", "true")
    managed_engine = engine_module.SecurityEngine()
    monkeypatch.setattr(engine_module, "engine", managed_engine)
    reports = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            config = _complete_managed_config()
            config["security_audit_only"] = False
            config["security_execution_mode_managed"] = True
            return _sign_managed_config(config)

    class PostResponse:
        def raise_for_status(self):
            return None

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())

    def fake_post(url, *, headers, json, timeout):
        reports.append((url, json))
        return PostResponse()

    monkeypatch.setattr(httpx, "post", fake_post)

    revision = _fetch_once("http://control-plane:8081", "internal-token", 5.0)

    # 2.9.22（设计 D7）：部署变量 SECURITY_AUDIT_ONLY=true 只作初值，签名下发的防护模式生效。
    # 原断言 audit_only is True（部署锁压过控制台）随用户 11-17 决定改写。
    assert managed_engine.audit_only is False
    assert managed_engine.semantic_config_revision == revision
    assert len(reports) == 1
    report_url, report = reports[0]
    assert report_url.endswith("/semantic-runtime-report/engine")
    assert report["component"] == "security-engine"
    assert report["applied_revision"] == revision
    assert report["node_id"]
    assert_runtime_policy_consistency(managed_engine)


def test_fetch_once_rejects_missing_or_invalid_revision_before_apply(monkeypatch):
    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            config = _complete_managed_config()
            config["revision"] = "bad"
            return config

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: pytest.fail("invalid config must not be reported as applied"))
    ff.apply_overrides({"SECURITY_SEMANTIC_ENABLED": "false"})

    with pytest.raises(ValueError, match="revision"):
        _fetch_once("http://control-plane:8081", "token", 5.0)

    assert ff.is_enabled("SECURITY_SEMANTIC_ENABLED") is False
    ff.apply_overrides({})


def test_fetch_once_rejects_tampered_body_before_apply_and_preserves_last_good(monkeypatch):
    config = _complete_managed_config()
    config["semantic_agent_enabled"] = True

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return config

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(
        "app.semantic_config_loader._reconfigure_live_engine",
        lambda revision: pytest.fail("tampered config must not reach live engine"),
    )
    monkeypatch.setattr(httpx, "post", lambda *a, **k: pytest.fail("tampered config must not be reported applied"))
    ff.apply_overrides({"SECURITY_SEMANTIC_ENABLED": "false"})

    with pytest.raises(ValueError, match="attestation"):
        _fetch_once("http://control-plane:8081", "token", 5.0)

    assert ff.is_enabled("SECURITY_SEMANTIC_ENABLED") is False


def test_probe_managed_judge_uses_configured_timeout(monkeypatch):
    calls = []

    def fake_judge(content, **kwargs):
        calls.append((content, kwargs))
        return SemanticOpinion("benign", "none", 0.99, "healthy")

    monkeypatch.setattr("app.detectors.llm_judge.judge_semantic", fake_judge)
    monkeypatch.setattr(
        "app.detectors.llm_judge.get_semantic_judge_health",
        lambda url, **scope: {"operational": True, "url": url},
    )
    config = _complete_managed_config()
    config["judge_timeout"] = 14

    health = _probe_managed_judge(config)

    assert health["operational"] is True
    assert len(calls) == 2
    assert all(call[1]["timeout"] == 14.0 for call in calls)
    assert calls[0][1]["judge_backend"] == config["judge_backend"]
    assert calls[0][1]["allow_private_egress"] is config["judge_allow_private_egress"]


def test_fetch_once_reports_loaded_config_but_unavailable_judge(monkeypatch):
    reports = []

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return _complete_managed_config()

    class PostResponse:
        def raise_for_status(self):
            return None

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(httpx, "post", lambda url, *, headers, json, timeout: reports.append(json) or PostResponse())
    monkeypatch.setattr("app.semantic_config_loader._reconfigure_live_engine", lambda revision: None)
    monkeypatch.setattr("app.detectors.llm_judge._post_chat", lambda *a, **k: None)

    _fetch_once("http://control-plane:8081", "token", 5.0)

    assert len(reports) == 1
    report = reports[0]
    assert report["config_loaded"] is True
    assert report["judge_required"] is True
    assert report["judge_operational"] is False
    assert report["judge_consecutive_failures"] >= 1
    assert report["error_code"] == "judge_unavailable"


def test_semantic_sampling_applies_only_to_output(monkeypatch):
    detector = SemanticDetector(
        url="http://judge.invalid",
        model="judge",
        api_key="key",
        op_timeout=1,
        total_timeout=1,
        sample_rate=0,
    )
    monkeypatch.setattr(
        detector,
        "_judge_with_deadline",
        lambda content, deadline=None, **kwargs: SemanticOpinion("malicious", "semantic_jailbreak", 0.9, ""),
    )

    assert detector.detect("ignore previous instructions", "input")
    assert detector.detect("model output", "output") == []

def test_reconfigure_semantic_updates_audit_only_from_runtime_override():
    from app.detectors.engine import SecurityEngine

    ff.apply_overrides({"SECURITY_AUDIT_ONLY": "false"})
    engine = SecurityEngine()
    assert engine.audit_only is False

    ff.apply_overrides({"SECURITY_AUDIT_ONLY": "true"})
    engine.reconfigure_semantic()
    assert engine.audit_only is True
    ff.apply_overrides({})


def test_reconfigure_semantic_failure_preserves_complete_previous_state(monkeypatch):
    import app.detectors.engine as engine_module

    ff.apply_overrides({
        "SECURITY_AUDIT_ONLY": "true",
        "SECURITY_SEMANTIC_ENABLED": "false",
        "SECURITY_SEMANTIC_INPUT_ENABLED": "false",
        "SECURITY_LLM_JUDGE_MODEL": "old-model",
    })
    engine = engine_module.SecurityEngine()
    before = (
        engine.audit_only,
        engine.semantic_enabled,
        engine.semantic_output_enabled,
        engine._judge_model,
        engine.semantic,
    )

    ff.apply_overrides({
        "SECURITY_AUDIT_ONLY": "false",
        "SECURITY_SEMANTIC_ENABLED": "true",
        "SECURITY_SEMANTIC_INPUT_ENABLED": "true",
        "SECURITY_LLM_JUDGE_MODEL": "new-model",
    })
    monkeypatch.setattr(
        engine_module,
        "SemanticDetector",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("constructor failed")),
    )
    with pytest.raises(RuntimeError, match="constructor failed"):
        engine.reconfigure_semantic()

    after = (
        engine.audit_only,
        engine.semantic_enabled,
        engine.semantic_output_enabled,
        engine._judge_model,
        engine.semantic,
    )
    assert after == before
    ff.apply_overrides({})

def test_fetch_reconfigure_failure_restores_previous_feature_overrides(monkeypatch):
    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return _complete_managed_config()

    monkeypatch.setattr(httpx, "get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(
        "app.semantic_config_loader._reconfigure_live_engine",
        lambda revision: (_ for _ in ()).throw(RuntimeError("apply failed")),
    )
    monkeypatch.setattr(httpx, "post", lambda *args, **kwargs: pytest.fail("failed config must not be reported"))
    ff.apply_overrides({
        "SECURITY_SEMANTIC_ENABLED": "false",
        "SECURITY_AUDIT_ONLY": "false",
    })

    with pytest.raises(RuntimeError, match="apply failed"):
        _fetch_once("http://control-plane:8081", "token", 5.0)

    assert ff.is_enabled("SECURITY_SEMANTIC_ENABLED") is False
    assert ff.is_enabled("SECURITY_AUDIT_ONLY") is False
    ff.apply_overrides({})


def _complete_managed_config() -> dict:
    return _sign_managed_config({
        "inspect_user_input": True,
        "inspect_model_output": True,
        "inspect_builtin_context": False,
        "inspect_history": False,
        "inspect_tool_results": True,
        "security_audit_only": True,
        "semantic_enabled": True,
        "semantic_input_enabled": True,
        "semantic_agent_enabled": False,
        "semantic_output_enabled": False,
        "judge_allow_private_egress": False,
        "tier1_enabled": False,
        "fp_suppression_enabled": False,
        "source_aware_enabled": False,
        "confidence_gating_enabled": False,
        "coding_traffic_downgrade_enabled": False,
        "file_content_dlp_enabled": False,
        "judge_backend": "bundled",
        "judge_url": "http://llm-judge:8080/v1/chat/completions",
        "judge_model": "judge",
        "judge_api_key": "secret",
        "judge_timeout": "6",
        "semantic_total_timeout": "6",
        "semantic_sample_rate": "1",
        "tier1_url": "http://tier1-classifier:8000/classify",
        "tier1_timeout": "1",
        "tier1_low_threshold": "0.2",
        "tier1_high_threshold": "0.8",
        "confidence_threshold": "0.55",
        "triage_total_budget": "8",
    })


def _sign_managed_config(config: dict, key: str = "test-attestation") -> dict:
    signed = dict(config)
    signed.pop("revision", None)
    chunks = []
    for name in sorted(signed):
        value = signed[name]
        chunks.append(f"{len(name.encode())}:{name}=".encode())
        if type(value) is bool:
            chunks.append(b"b:1;" if value else b"b:0;")
        elif isinstance(value, str):
            raw = value.encode()
            chunks.extend((f"s:{len(raw)}:".encode(), raw, b";"))
        else:
            raise TypeError(f"unsupported test config type for {name}")
    mac = hmac.new(
        key.encode(),
        b"jjdguard:semantic-config:security-engine\n" + b"".join(chunks),
        hashlib.sha256,
    ).hexdigest()[:32]
    signed["revision"] = mac
    return signed


def test_fetch_uses_engine_endpoint_and_attestation_headers(monkeypatch):
    captured = {}

    class Response:
        def raise_for_status(self):
            return None
        def json(self):
            return _sign_managed_config(
                _complete_managed_config(), key="engine-attestation"
            )

    def fake_get(url, *, headers, timeout):
        captured["url"] = url
        captured["headers"] = headers
        return Response()

    class PostResponse:
        def raise_for_status(self):
            return None

    monkeypatch.setenv("SECURITY_RULE_PACK_ATTESTATION_TOKEN", "engine-attestation")
    monkeypatch.setattr(httpx, "get", fake_get)
    monkeypatch.setattr(httpx, "post", lambda *a, **k: PostResponse())
    monkeypatch.setattr(
        "app.semantic_config_loader._reconfigure_live_engine",
        lambda revision: None,
    )

    _fetch_once("http://control-plane:8081", "internal-token", 5.0)

    assert captured["url"].endswith("/admin/v1/internal/security/semantic-config/engine")
    assert captured["headers"]["X-JJDGuard-Internal-Token"] == "internal-token"
    assert captured["headers"]["X-Rule-Pack-Attestation"] == "engine-attestation"
    assert captured["headers"]["X-Tenant-ID"] == "tenant_default"


def test_incomplete_managed_config_never_falls_back_to_env_or_reports_applied(monkeypatch):
    config = _complete_managed_config()
    del config["judge_api_key"]

    class Response:
        def raise_for_status(self):
            return None
        def json(self):
            return config

    monkeypatch.setenv(ff.ENV_LLM_JUDGE_API_KEY, "env-secret-must-not-fill-hole")
    monkeypatch.setattr(httpx, "get", lambda *a, **k: Response())
    monkeypatch.setattr(
        "app.semantic_config_loader._reconfigure_live_engine",
        lambda revision: pytest.fail("incomplete config must not reach live engine"),
    )
    monkeypatch.setattr(
        httpx, "post",
        lambda *a, **k: pytest.fail("incomplete config must not be reported as applied"),
    )

    with pytest.raises(ValueError, match="incomplete"):
        _fetch_once("http://control-plane:8081", "token", 5.0)


def test_runtime_node_id_unchanged_for_single_process(monkeypatch):
    import os
    from app.semantic_config_loader import _runtime_node_id
    monkeypatch.delenv("SEMANTIC_RUNTIME_NODE_ID", raising=False)
    monkeypatch.setenv("HOSTNAME", "engine-a")
    for value in (None, "", "1", "0", "abc", " 1 "):
        if value is None:
            monkeypatch.delenv("WEB_CONCURRENCY", raising=False)
        else:
            monkeypatch.setenv("WEB_CONCURRENCY", value)
        assert _runtime_node_id() == "engine-a", value


def test_runtime_node_id_gets_pid_suffix_when_multi_worker(monkeypatch):
    import os
    from app.semantic_config_loader import _runtime_node_id
    monkeypatch.setenv("SEMANTIC_RUNTIME_NODE_ID", "engine-a")
    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    assert _runtime_node_id() == "engine-a#%d" % os.getpid()


def test_runtime_node_id_multi_worker_suffix_survives_truncation(monkeypatch):
    import os
    from app.semantic_config_loader import _runtime_node_id
    monkeypatch.setenv("SEMANTIC_RUNTIME_NODE_ID", "n" * 300)
    monkeypatch.setenv("WEB_CONCURRENCY", "2")
    value = _runtime_node_id()
    assert len(value) <= 128 and value.endswith("#%d" % os.getpid())


def test_engine_aligns_with_gateway_on_unmanaged_projection(monkeypatch):
    # 代码质量审查（重要 1）：与网关 semantic_runtime_client 同口径——投影没有显式模式时，
    # 看引擎自己容器的 SECURITY_AUDIT_ONLY；环境变量不为 true 时按投影原样。
    config = _complete_managed_config()
    config["security_audit_only"] = False
    config = _sign_managed_config(config)
    monkeypatch.setenv(ff.ENV_AUDIT_ONLY, "true")
    forced = _effective_managed_config(config)
    assert forced["security_audit_only"] is True and forced["revision"] != config["revision"]
    _verify_managed_config_attestation(forced)
    monkeypatch.setenv(ff.ENV_AUDIT_ONLY, "false")
    assert _effective_managed_config(config) == config
