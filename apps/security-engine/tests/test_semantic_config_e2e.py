"""SFIX-1(d): 真端到端断言——Tier-1/FP 四键从 control-plane 内部供给端点
GetInternalSemanticConfig 的**真实响应**，经真 loader HTTP 路径（httpx GET →
map_config_to_overrides → ff.apply_overrides），流进 feature_flags override 层并被
is_enabled/get_float 读回。

单一事实源，非手喂 dict：本测试消费的 server 响应体是 fixtures/internal_semantic_config.json，
由 control-plane 的 Go 测试 TestGetInternalSemanticConfigWritesE2EFixture 用**真** Go handler
（DB 配置态 tier1_enabled=true / fp_suppression_enabled=false / 阈值 0.15/0.85）产出。这里起一个
真 HTTP server 回放该字节，loader 的 _fetch_once 对它发真请求、走真解析、真 apply_overrides。

锁死 SFIX-1(a) 修的断链：Go 端点若回归不 emit 这四键，先让 Go 侧夹具断言炸，夹具内容也随之
变化 → 下游本测试断言 is_enabled/get_float 回退默认而非 DB 值 → 一并失败。
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

import app.feature_flags as ff
from app import semantic_config_loader as loader

_FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "internal_semantic_config.json")


def _load_endpoint_fixture() -> dict:
    if not os.path.exists(_FIXTURE):
        pytest.skip(
            "缺 fixtures/internal_semantic_config.json——先跑 control-plane 的 "
            "go test -run TestGetInternalSemanticConfigWritesE2EFixture 生成（由真 Go 端点产出）"
        )
    with open(_FIXTURE, "rb") as fh:
        return json.loads(fh.read())


class _EndpointServer:
    """起真 HTTP server，在 SEMANTIC_CONFIG_PATH 上回放真 Go 端点产出的响应体。"""

    def __init__(self, response_body: dict):
        self._body = json.dumps(response_body).encode()
        body = self._body
        path = loader.SEMANTIC_CONFIG_PATH

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path != path:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):  # noqa: N802
                if self.path != loader.SEMANTIC_REPORT_PATH:
                    self.send_response(404)
                    self.end_headers()
                    return
                length = int(self.headers.get("Content-Length", "0"))
                if length:
                    self.rfile.read(length)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *a):  # 静音
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address
        return f"http://{host}:{port}"

    def __enter__(self):
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture(autouse=True)
def _reset_overrides(monkeypatch):
    monkeypatch.setenv("SECURITY_RULE_PACK_ATTESTATION_TOKEN", "semantic-component-test-attestation")
    monkeypatch.setenv("SECURITY_TIER1_API_TOKEN", "e2e-tier1-token")
    ff.apply_overrides({})
    yield
    ff.apply_overrides({})


def test_four_keys_flow_endpoint_to_feature_flags(monkeypatch):
    endpoint_body = _load_endpoint_fixture()
    # 自证：真 Go 端点的响应确实带这四键（否则 (a) 断链未修）。
    assert endpoint_body.get("tier1_enabled") is True
    assert endpoint_body.get("fp_suppression_enabled") is False
    assert endpoint_body.get("tier1_low_threshold") == "0.15"
    assert endpoint_body.get("tier1_high_threshold") == "0.85"

    # env 兜底刻意=「关 + 默认阈值」，与 DB 配置态不同——证明生效的是端点(DB)值而非 env。
    monkeypatch.setenv(ff.ENV_TIER1_ENABLED, "false")
    monkeypatch.setenv(ff.ENV_FP_SUPPRESSION_ENABLED, "false")
    monkeypatch.setenv(ff.ENV_TIER1_LOW_THRESHOLD, "0.2")
    monkeypatch.setenv(ff.ENV_TIER1_HIGH_THRESHOLD, "0.8")

    with _EndpointServer(endpoint_body) as srv:
        # 真 loader HTTP 路径：httpx GET 端点 → map_config_to_overrides → ff.apply_overrides
        # （_reconfigure_live_engine 内部 try/except，引擎缺失只告警不崩）。
        loader._fetch_once(srv.base_url, token="internal-token", timeout=5.0)

    # 四键 override 已从端点响应流进 feature_flags，压过 env 兜底：
    assert ff.is_enabled(ff.ENV_TIER1_ENABLED) is True, "tier1_enabled 未从端点流到 override（断链回归）"
    assert ff.is_enabled(ff.ENV_FP_SUPPRESSION_ENABLED) is False
    assert ff.get_float(ff.ENV_TIER1_LOW_THRESHOLD, 0.0) == 0.15, "阈值 low 未从端点流到 override"
    assert ff.get_float(ff.ENV_TIER1_HIGH_THRESHOLD, 0.0) == 0.85, "阈值 high 未从端点流到 override"


def test_incomplete_endpoint_is_rejected_without_env_fallback(monkeypatch):
    # engine 专属托管投影必须完整；缺键不得偷偷回退 env 后仍回报 applied。
    monkeypatch.setenv(ff.ENV_TIER1_ENABLED, "true")
    monkeypatch.setenv(ff.ENV_TIER1_LOW_THRESHOLD, "0.2")
    with _EndpointServer({
        "revision": "0123456789abcdef0123456789abcdef",
        "semantic_enabled": True,
    }) as srv:
        with pytest.raises(ValueError, match="incomplete"):
            loader._fetch_once(
                srv.base_url, token="internal-token", timeout=5.0
            )

    assert ff.snapshot_overrides() == {}


def test_runtime_disposition_keys_flow_endpoint_to_engine_runtime(monkeypatch):
    # 2.9.22 端到端：控制台设置 → 控制面签名投影（真 Go 端点产出的夹具）→ 引擎 loader → 运行快照。
    import importlib

    endpoint_body = _load_endpoint_fixture()
    assert endpoint_body.get("semantic_block_stages") == '["input","agent"]'
    assert "output_security_mode" not in endpoint_body
    engine_module = importlib.import_module("app.detectors.engine")
    live = engine_module.SecurityEngine()
    monkeypatch.setattr(engine_module, "engine", live)
    before = live.snapshot_semantic_runtime()
    assert before.semantic_block_stages == frozenset({"input"})
    assert before.agent_security_monitor_disposition == "observe"
    with _EndpointServer(endpoint_body) as srv:
        loader._fetch_once(srv.base_url, token="internal-token", timeout=5.0)
    after = live.snapshot_semantic_runtime()
    assert after.semantic_block_stages == frozenset({"input", "agent"})
    assert after.agent_security_monitor_disposition == "follow_policy"
    assert after.model_output_classified_disposition == "follow_policy"
