"""引擎侧版本握手、运行回执与回滚安全的热更新。

引擎每次拉规则包时上报自身身份（X-Node-ID）与当前持有版本（X-RulePack-Version）；
当下发版本与持有版本一致时跳过重载（幂等），不一致（含回滚）时重载并记下新版本。

本测试自包含：自带 versioned pack、捕获引擎和 MockTransport，锁定节点身份、
专用 attestation、持有版本、实际计数与刷新周期头的跨服务契约。
"""

import logging
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import httpx
import pytest

from app import rule_pack_loader as rule_pack_loader_module
from app.rule_pack_loader import (
    DEFAULT_REFRESH_SECONDS,
    NODE_HEADER,
    RULEPACK_ACTIVE_COUNT_HEADER,
    RULEPACK_POLICY_COUNT_HEADER,
    RULEPACK_REFRESH_SECONDS_HEADER,
    RULEPACK_SKIPPED_COUNT_HEADER,
    RULEPACK_VERSION_HEADER,
    RulePackConfig,
    RulePackLoader,
)
from app.detectors.engine import SecurityEngine


def _versioned_pack(version: str) -> dict:
    return {
        "tenant_id": "tenant_default",
        "generated_at": "2026-06-09T00:00:00Z",
        "version": version,
        "rules": [
            {
                "rule_id": "rule_med001",
                "rule_name": "medical record",
                "rule_type": "regex",
                "category": "medical",
                "severity": "high",
                "action": "block",
                "enabled": True,
                "regex": r"病案号[:：]\s*\d{6,}",
            }
        ],
        "policies": [],
        "exceptions": [],
        "skipped": [],
    }


def _config(node_id: str = "engine-1") -> RulePackConfig:
    return RulePackConfig(
        base_url="http://control-plane.local",
        token="secret",
        tenant_id="tenant_default",
        node_id=node_id,
        refresh_seconds=60,
        timeout=5.0,
    )


class _CapturingEngine:
    """记录 load 调用次数，镜像真实引擎热更新入口（load_custom_rules）。

    实现完整三段 apply 契约；加载器缺任一段都必须拒绝候选并回滚。
    """

    def __init__(self) -> None:
        self.load_calls = 0
        self.loaded_rules = None
        self.exc_load_calls = 0
        self.file_policy = None
        self.reply_policy = None

    def load_custom_rules(self, rules) -> None:
        self.loaded_rules = rules
        self.load_calls += 1

    def load_policies(self, policies) -> None:
        self.policies = policies

    def load_reply_policy(self, policy) -> None:
        self.reply_policy = policy
    def load_content_audit_exceptions(self, exceptions) -> None:
        self.exc_load_calls += 1

    def load_file_policy(self, policy) -> None:
        self.file_policy = policy


def _loader(handler, config: RulePackConfig) -> RulePackLoader:
    def factory(timeout):
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout)

    return RulePackLoader(config, client_factory=factory)


class TestNodeIdentityFromEnv:
    def test_from_env_preserves_safe_dedicated_attestation_token(self, monkeypatch):
        monkeypatch.setenv("CONTROL_PLANE_URL", "http://cp.local")
        monkeypatch.setenv("SECURITY_RULE_PACK_ATTESTATION_TOKEN", "attest-only-secret")

        cfg = RulePackConfig.from_env()

        assert cfg.attestation_token == "attest-only-secret"
        assert "attest-only-secret" not in repr(cfg)

    @pytest.mark.parametrize(
        "unsafe_token",
        [
            " leading-space",
            "trailing-space ",
            "contains space",
            "line\r\nbreak",
            "x" * 257,
        ],
    )
    def test_rejects_attestation_token_unsafe_for_http_headers(
        self, monkeypatch, unsafe_token
    ):
        monkeypatch.setenv("CONTROL_PLANE_URL", "http://cp.local")
        monkeypatch.setenv("SECURITY_RULE_PACK_ATTESTATION_TOKEN", unsafe_token)

        with pytest.raises(ValueError) as exc_info:
            RulePackConfig.from_env()

        assert unsafe_token not in str(exc_info.value)

    def test_from_env_prefers_trimmed_explicit_node_id(self, monkeypatch):
        monkeypatch.setenv("CONTROL_PLANE_URL", "http://cp.local")
        monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "secret")
        monkeypatch.setenv("SECURITY_NODE_ID", "  engine-7  ")
        cfg = RulePackConfig.from_env()
        assert cfg.node_id == "engine-7"

    @pytest.mark.parametrize("configured", [None, "", "   \t\n"])
    def test_missing_or_blank_node_id_falls_back_to_hostname(
        self, monkeypatch, configured
    ):
        monkeypatch.setenv("CONTROL_PLANE_URL", "http://cp.local")
        monkeypatch.setenv("JJD_INTERNAL_API_SECRET", "secret")
        monkeypatch.setattr("socket.gethostname", lambda: "  worker-host  ")
        if configured is None:
            monkeypatch.delenv("SECURITY_NODE_ID", raising=False)
        else:
            monkeypatch.setenv("SECURITY_NODE_ID", configured)
        cfg = RulePackConfig.from_env()
        # WEB_CONCURRENCY>1 means one row per worker, never one row per host.
        assert cfg.node_id.startswith("worker-host#")
        assert cfg.node_id.split("#")[-1].isdigit()

    def test_direct_construction_trims_and_limits_node_id(self):
        cfg = _config(node_id="  " + "n" * 200 + "  ")
        assert cfg.node_id == "n" * 128

    def test_blank_hostname_still_produces_nonempty_node_id(self, monkeypatch):
        monkeypatch.setattr("socket.gethostname", lambda: "  ")
        cfg = _config(node_id="  ")
        assert cfg.node_id
        assert len(cfg.node_id) <= 128

    def test_hostname_lookup_failure_still_produces_nonempty_node_id(
        self, monkeypatch
    ):
        def fail_hostname_lookup():
            raise OSError("hostname unavailable")

        monkeypatch.setattr("socket.gethostname", fail_hostname_lookup)
        cfg = _config(node_id="  ")
        assert cfg.node_id.startswith("unknown-host#")
        assert cfg.node_id.split("#")[-1].isdigit()


def test_real_http_failure_log_redacts_all_auth_tokens(caplog):
    attestation_token = "attestation-secret-never-log"
    internal_token = "internal-secret-never-log"

    class RejectingHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(500, attestation_token)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, _format, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), RejectingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        loader = RulePackLoader(
            RulePackConfig(
                base_url=f"http://127.0.0.1:{server.server_port}",
                token=internal_token,
                attestation_token=attestation_token,
                tenant_id="tenant_default",
                node_id="real-http-log-node",
            )
        )
        caplog.set_level(logging.WARNING)

        assert loader.refresh_once(_CapturingEngine()) is False
        assert attestation_token not in caplog.text
        assert internal_token not in caplog.text
        assert "<redacted>" in caplog.text
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

class TestVersionHandshakeHeaders:
    def test_default_refresh_interval_is_bounded_for_interactive_policy_updates(self):
        assert DEFAULT_REFRESH_SECONDS == 15

    def test_refresh_and_acknowledge_reports_new_receipt_immediately(self):
        seen = []
        pack = _versioned_pack("ver-ack000000001")

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(
                (
                    request.headers.get(RULEPACK_VERSION_HEADER),
                    request.headers.get(RULEPACK_ACTIVE_COUNT_HEADER),
                    request.headers.get(RULEPACK_SKIPPED_COUNT_HEADER),
                    request.headers.get(RULEPACK_POLICY_COUNT_HEADER),
                )
            )
            return httpx.Response(200, json=pack)

        loader = _loader(handler, _config())
        engine = _CapturingEngine()

        assert loader.refresh_and_acknowledge(engine) is True
        assert engine.load_calls == 1
        assert seen == [
            ("", None, None, None),
            ("ver-ack000000001", "1", "0", "0"),
        ]

    def test_acknowledgment_failure_does_not_rollback_applied_pack(self, caplog):
        requests = 0

        def handler(_request: httpx.Request) -> httpx.Response:
            nonlocal requests
            requests += 1
            if requests == 1:
                return httpx.Response(200, json=_versioned_pack("ver-ack000000002"))
            return httpx.Response(503, text="receipt unavailable")

        loader = _loader(handler, _config())
        engine = _CapturingEngine()
        caplog.set_level(logging.WARNING)

        assert loader.refresh_and_acknowledge(engine) is True
        assert engine.load_calls == 1
        assert loader._receipt[0] == "ver-ack000000002"
        assert "receipt acknowledgment failed" in caplog.text

    def test_sends_stable_dedicated_attestation_header_on_every_request(self):
        seen = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get("X-Rule-Pack-Attestation"))
            version = f"ver-attest-{len(seen)}"
            return httpx.Response(200, json=_versioned_pack(version))

        config = _config()
        config.attestation_token = "dedicated-attestation-secret"
        loader = _loader(handler, config)
        engine = _CapturingEngine()

        assert loader.refresh_once(engine) is True
        assert loader.refresh_once(engine) is True

        assert rule_pack_loader_module.RULEPACK_ATTESTATION_HEADER == (
            "X-Rule-Pack-Attestation"
        )
        assert seen == [
            "dedicated-attestation-secret",
            "dedicated-attestation-secret",
        ]

    def test_sends_node_id_and_held_version(self):
        seen = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(
                (
                    request.headers.get(NODE_HEADER),
                    request.headers.get(RULEPACK_VERSION_HEADER),
                )
            )
            # 每次回不同版本，强制第二次也真正发起请求并重载
            version = f"ver-{len(seen):012d}"
            return httpx.Response(200, json=_versioned_pack(version))

        loader = _loader(handler, _config(node_id="engine-9"))
        engine = _CapturingEngine()

        assert loader.refresh_once(engine) is True
        assert loader.refresh_once(engine) is True

        assert seen[0] == ("engine-9", "")  # 首拉：持有版本为空
        assert seen[1] == ("engine-9", "ver-000000000001")  # 复拉：带上已持有版本

    def test_declares_engine_capabilities_on_every_request(self):
        # 控制面据此决定是否下发新字段（如 semantic_action）；旧引擎不带此头，
        # 控制面不下发新字段，避免严格 DTO 拒收整个规则包（混跑升级）。
        seen = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get("X-Engine-Capabilities"))
            return httpx.Response(200, json=_versioned_pack(f"ver-cap-{len(seen):08d}"))

        loader = _loader(handler, _config())
        engine = _CapturingEngine()

        assert loader.refresh_once(engine) is True
        assert loader.refresh_once(engine) is True
        assert rule_pack_loader_module.ENGINE_CAPABILITIES_HEADER == "X-Engine-Capabilities"
        assert seen and all(value is not None for value in seen)
        assert all("semantic_action" in value.split(",") for value in seen)

    def test_sends_effective_refresh_seconds_on_every_request(self):
        seen = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get(RULEPACK_REFRESH_SECONDS_HEADER))
            return httpx.Response(200, json=_versioned_pack("ver-refresh0001"))

        loader = _loader(handler, _config())
        loader.config.refresh_seconds = -9
        engine = _CapturingEngine()

        assert loader.refresh_once(engine) is True
        assert loader.refresh_once(engine) is True
        assert seen == ["1", "1"]

    @pytest.mark.parametrize(
        ("configured", "expected"),
        [(-9, 1), (0, 1), (1, 1), (3600, 3600), (3601, 3600), (999999, 3600)],
    )
    def test_refresh_interval_is_clamped_to_supported_range(
        self, configured, expected
    ):
        config = _config()
        config.refresh_seconds = configured

        assert config.effective_refresh_seconds == expected

    def test_reports_actual_active_and_skipped_counts_on_next_fetch(self):
        seen = []
        pack = {
            "tenant_id": "tenant_default",
            "version": "ver-counts000001",
            "rules": [
                {
                    "rule_id": "rule_valid",
                    "rule_name": "valid regex",
                    "rule_type": "regex",
                    "category": "custom",
                    "severity": "high",
                    "action": "block",
                    "enabled": True,
                    "regex": r"secret-[0-9]+",
                },
                {
                    "rule_id": "rule_bad_python_regex",
                    "rule_name": "bad regex",
                    "rule_type": "regex",
                    "category": "custom",
                    "severity": "high",
                    "action": "block",
                    "enabled": True,
                    "regex": "(",
                },
            ],
            "policies": [
                {
                    "policy_code": "tenant.scene.custom",
                    "policy_id": "policy_scene_custom",
                    "policy_name": "custom scene",
                    "policy_type": "scene_policy",
                    "scene": "content_safety",
                    "action": "audit",
                    "enabled": True,
                    "binding_mode": "any",
                    "capabilities": [
                        {
                            "category": "custom",
                            "supported_stages": ["input"],
                            "allowed_actions": ["audit", "block"],
                            "mask_capable": False,
                        }
                    ],
                }
            ],
            "exceptions": [],
            "skipped": [],
        }

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(
                (
                    request.headers.get(RULEPACK_ACTIVE_COUNT_HEADER),
                    request.headers.get(RULEPACK_SKIPPED_COUNT_HEADER),
                    request.headers.get(RULEPACK_POLICY_COUNT_HEADER),
                )
            )
            return httpx.Response(200, json=pack)

        loader = _loader(handler, _config())
        engine = SecurityEngine()

        assert loader.refresh_once(engine) is True
        assert len(engine.custom_rules.active_rules) == 1
        assert loader.refresh_once(engine) is True

        assert seen[0] == (None, None, None)
        # Python 不可编译的正则是可观测降级，不拒绝其余有效规则。
        assert seen[1] == ("1", "1", "1")


class TestVersionSkipReload:
    def test_skips_reload_when_version_unchanged(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_versioned_pack("ver-stable0001"))

        loader = _loader(handler, _config())
        engine = _CapturingEngine()

        assert loader.refresh_once(engine) is True
        assert engine.load_calls == 1
        # 版本未变：仍算成功，但不应再次 load（幂等，避免无谓热更新）
        assert loader.refresh_once(engine) is True
        assert engine.load_calls == 1

    def test_reloads_when_version_changes(self):
        versions = iter(["ver-aaaa00000001", "ver-bbbb00000002"])

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_versioned_pack(next(versions)))

        loader = _loader(handler, _config())
        engine = _CapturingEngine()

        assert loader.refresh_once(engine) is True
        assert engine.load_calls == 1
        assert loader.refresh_once(engine) is True
        assert engine.load_calls == 2

    def test_rollback_to_previous_version_reloads(self):
        # A → B → A：基于内容哈希的版本号没有单调序，回滚也会改变版本，
        # 因此必须按“是否相等”判断，回滚同样触发重载（回滚安全）。
        versions = iter(["ver-A00000000001", "ver-B00000000002", "ver-A00000000001"])

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_versioned_pack(next(versions)))

        loader = _loader(handler, _config())
        engine = _CapturingEngine()

        assert loader.refresh_once(engine) is True  # A
        assert loader.refresh_once(engine) is True  # B
        assert loader.refresh_once(engine) is True  # 回滚到 A
        assert engine.load_calls == 3
