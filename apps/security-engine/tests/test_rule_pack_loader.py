"""
P2-1 Layer 4：引擎侧规则包加载器测试（方案A：规则编译下发 —— 引擎拉取侧）。

验证：
  1) parse_rule_pack 正确反序列化 control-plane 下发的 snake_case 规则包
     （Go 编译器输出 ↔ Python CompiledRule 契约）
  2) 坏规则被逐条跳过，不拖垮整包（防一条坏规则导致全量失效）
  3) refresh_once 发送鉴权头 X-JJDGuard-Internal-Token + 租户头 X-Tenant-ID
  4) 网络/HTTP 故障不崩溃、不清空既有规则（保持当前规则，返回 False）
  5) 未配置 CONTROL_PLANE_URL 时加载器禁用（向后兼容：无自定义规则）
  6) 端到端：拉取病案号规则 → 加载进真实引擎 → 命中内容被 block
"""
import httpx
import pytest

from app.rule_pack_loader import (
    RulePackConfig,
    RulePackLoader,
    parse_rule_pack,
    parse_exceptions,
    parse_reply_policy,
    INTERNAL_TOKEN_HEADER,
    TENANT_HEADER,
    RULE_PACK_PATH,
    run_refresh_loop,
)
from app.detectors.engine import SecurityEngine


@pytest.fixture
def anyio_backend():
    return "asyncio"


def _medical_pack() -> dict:
    return {
        "tenant_id": "tenant_default",
        "generated_at": "2026-06-06T00:00:00Z",
        "version": "medical-pack-v1",
        "rules": [
            {
                "rule_id": "rule_med001",
                "rule_name": "病案号正则",
                "rule_type": "regex",
                "category": "custom_medical_record",
                "severity": "high",
                "action": "block",
                "enabled": True,
                "regex": r"病案号[:：]?\s*([A-Za-z]{0,3}\d{6,12})",
            }
        ],
        "policies": [],
        "exceptions": [],
        "skipped": [],
    }


def _config(base_url: str = "http://control-plane:8080") -> RulePackConfig:
    return RulePackConfig(
        base_url=base_url,
        token="s3cr3t-internal-token",
        tenant_id="tenant_default",
        refresh_seconds=60,
        timeout=5.0,
    )


class _CapturingEngine:
    """记录 load_custom_rules 调用的假引擎（隔离加载器单元测试）。"""

    def __init__(self):
        self.loaded = None
        self.load_calls = 0
        self.loaded_exceptions = None
        self.exc_load_calls = 0
        self.file_policy = None
        self.loaded_reply_policy = None
        self.loaded_policies = None

    def load_custom_rules(self, rules):
        self.custom_rules = rules
        self.loaded = [rule for rule, _pattern in rules.active_rules] + list(
            rules.skipped
        )
        self.load_calls += 1

    def load_policies(self, policies):
        self.policies = policies
        self.loaded_policies = list(policies.policies)

    def load_content_audit_exceptions(self, exceptions):
        self.content_exceptions = exceptions
        self.loaded_exceptions = list(exceptions.exceptions)
        self.exc_load_calls += 1

    def load_file_policy(self, policy):
        self.file_policy = policy

    def load_reply_policy(self, policy):
        self.loaded_reply_policy = policy


def _loader_with_handler(handler, config=None):
    cfg = config or _config()

    def factory(timeout):
        return httpx.Client(transport=httpx.MockTransport(handler), timeout=timeout)

    return RulePackLoader(cfg, client_factory=factory)


class TestParseRulePack:
    def test_maps_compiled_rules_from_control_plane_json(self):
        rules = parse_rule_pack(_medical_pack())
        assert len(rules) == 1
        r = rules[0]
        assert r.rule_id == "rule_med001"
        assert r.rule_name == "病案号正则"
        assert r.rule_type == "regex"
        assert r.category == "custom_medical_record"
        assert r.severity == "high"
        assert r.action == "block"
        assert r.enabled is True
        assert r.regex == r"病案号[:：]?\s*([A-Za-z]{0,3}\d{6,12})"

    def test_rejects_entire_pack_when_any_rule_is_malformed(self):
        pack = _medical_pack()
        pack["rules"].append({"rule_id": "bad"})  # 缺必填字段
        with pytest.raises(ValueError, match="malformed rule"):
            parse_rule_pack(pack)

    def test_empty_pack_yields_empty_list(self):
        rules = parse_rule_pack({"tenant_id": "t", "rules": [], "skipped": []})
        assert rules == []

    def test_missing_rules_key_rejects_pack(self):
        with pytest.raises(ValueError, match="rules"):
            parse_rule_pack({"tenant_id": "t"})


class TestRefreshOnce:
    def test_sends_auth_and_tenant_headers_to_correct_path(self):
        seen = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["path"] = request.url.path
            seen["token"] = request.headers.get(INTERNAL_TOKEN_HEADER)
            seen["legacy_token"] = request.headers.get("X-NewAPI-Internal-Token")
            seen["tenant"] = request.headers.get(TENANT_HEADER)
            return httpx.Response(200, json=_medical_pack())

        engine = _CapturingEngine()
        loader = _loader_with_handler(handler)
        ok = loader.refresh_once(engine)

        assert ok is True
        assert seen["path"] == RULE_PACK_PATH
        assert INTERNAL_TOKEN_HEADER == "X-JJDGuard-Internal-Token"
        assert seen["token"] == "s3cr3t-internal-token"
        assert seen["legacy_token"] is None
        assert seen["tenant"] == "tenant_default"
        assert engine.load_calls == 1
        assert [r.rule_id for r in engine.loaded] == ["rule_med001"]

    def test_network_failure_keeps_current_rules(self):
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused")

        engine = _CapturingEngine()
        loader = _loader_with_handler(handler)
        ok = loader.refresh_once(engine)

        assert ok is False
        assert engine.load_calls == 0  # 未触碰引擎，保持既有规则

    def test_http_error_keeps_current_rules(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"error": "boom"})

        engine = _CapturingEngine()
        loader = _loader_with_handler(handler)
        ok = loader.refresh_once(engine)

        assert ok is False
        assert engine.load_calls == 0

    def test_disabled_when_no_control_plane_url(self):
        engine = _CapturingEngine()

        def handler(request: httpx.Request) -> httpx.Response:  # 不应被调用
            raise AssertionError("HTTP should not be attempted when disabled")

        loader = _loader_with_handler(handler, config=_config(base_url=""))
        assert loader.enabled is False
        ok = loader.refresh_once(engine)
        assert ok is False
        assert engine.load_calls == 0


class TestEndToEndIntoRealEngine:
    def test_fetch_then_real_engine_blocks_hit(self):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=_medical_pack())

        engine = SecurityEngine()
        loader = _loader_with_handler(handler)
        assert loader.refresh_once(engine) is True

        result = engine.check_input("req-e2e", "患者病案号：BA00123456 已归档")
        assert result.action == "block"
        hits = [f for f in result.findings if f.rule_id == "rule_med001"]
        assert len(hits) == 1
        assert "BA00123456" not in hits[0].matched_text_preview  # 红线：旧打码预览不含原文  # pragma: allowlist secret nosemgrep
        assert hits[0].redacted_evidence == "BA00123456"  # 2.9.19：短取值按“自动”方式原样显示，不带 sha256 后缀


class TestParseExceptions:
    def test_maps_exceptions_from_control_plane_json(self):
        payload = {
            "exceptions": [
                {
                    "exception_id": "exc1",
                    "scope_type": "rule",
                    "scope_ref": "",
                    "include_children": False,
                    "rule_id": "rule_med001",
                    "decision": "audit",
                    "reason": "复核确认误报",
                    "expires_at": "2099-01-01T00:00:00Z",
                }
            ]
        }
        excs = parse_exceptions(payload)
        assert len(excs) == 1
        assert excs[0].exception_id == "exc1"
        assert excs[0].rule_id == "rule_med001"
        assert excs[0].decision == "audit"
        assert excs[0].expires_at == "2099-01-01T00:00:00Z"
        assert excs[0].include_children is False

    def test_maps_actor_department_include_children_from_control_plane_json(self):
        excs = parse_exceptions({
            "exceptions": [{
                "exception_id": "exc-dept",
                "scope_type": "actor_department_v1",
                "scope_ref": "dept-parent",
                "include_children": True,
                "decision": "audit",
            }],
        })

        assert len(excs) == 1
        assert excs[0].scope_ref == "dept-parent"
        assert excs[0].include_children is True

    def test_rejects_include_children_on_non_department_scope(self):
        with pytest.raises(ValueError, match="malformed exception"):
            parse_exceptions({
                "exceptions": [{
                    "exception_id": "exc-key",
                    "scope_type": "key_v1",
                    "scope_ref": "key-a",
                    "include_children": True,
                    "decision": "audit",
                }],
            })

    def test_rejects_malformed_exception_expiry(self):
        with pytest.raises(ValueError, match="malformed exception"):
            parse_exceptions({"exceptions": [{
                "exception_id": "bad-expiry",
                "scope_type": "tenant",
                "decision": "audit",
                "expires_at": "tomorrow-ish",
            }]})

    def test_rejects_entire_pack_when_any_exception_is_malformed(self):
        payload = {
            "exceptions": [
                {"scope_type": "tenant"},  # 缺 exception_id（必填）
                {"exception_id": "exc_ok", "decision": "allow"},
            ]
        }
        with pytest.raises(ValueError, match="malformed exception"):
            parse_exceptions(payload)

    def test_missing_exceptions_key_rejects_pack(self):
        with pytest.raises(ValueError, match="exceptions"):
            parse_exceptions({"tenant_id": "t", "rules": []})

    def test_non_dict_payload_rejects_pack(self):
        with pytest.raises(ValueError, match="object"):
            parse_exceptions(None)
        with pytest.raises(ValueError, match="object"):
            parse_exceptions([])


class TestRefreshOnceLoadsExceptions:
    def test_refresh_loads_both_rules_and_exceptions(self):
        pack = _medical_pack()
        pack["exceptions"] = [
            {"exception_id": "exc1", "rule_id": "rule_med001", "decision": "audit"}
        ]

        def handler(request):
            return httpx.Response(200, json=pack)

        engine = _CapturingEngine()
        loader = _loader_with_handler(handler)
        assert loader.refresh_once(engine) is True
        assert engine.load_calls == 1
        assert engine.exc_load_calls == 1
        assert [e.exception_id for e in engine.loaded_exceptions] == ["exc1"]


def _ok_handler(pack=None):
    payload = pack if pack is not None else _medical_pack()

    def handler(request):
        return httpx.Response(200, json=payload)


    return handler

class TestReplyPolicyLoading:
    def test_parse_and_load_configured_reply_policy(self):
        pack = _medical_pack()
        pack["reply_policy"] = {
            "schema_version": 1,
            "enabled": True,
            "templates": {
                "default": "默认拒答",
                "prompt_injection": "注入拒答",
                "content_safety": "内容拒答",
                "data_leak": "数据拒答",
            },
        }

        parsed = parse_reply_policy(pack)
        assert parsed.enabled is True
        assert parsed.templates["prompt_injection"] == "注入拒答"

        engine = _CapturingEngine()
        loader = _loader_with_handler(_ok_handler(pack))
        assert loader.refresh_once(engine) is True
        assert engine.loaded_reply_policy.enabled is True
        assert engine.loaded_reply_policy.templates["data_leak"] == "数据拒答"

    def test_invalid_present_reply_policy_rejects_pack_without_live_change(self):
        pack = _medical_pack()
        pack["reply_policy"] = {"schema_version": 1, "enabled": True, "templates": {}}
        engine = _CapturingEngine()
        loader = _loader_with_handler(_ok_handler(pack))

        assert loader.refresh_once(engine) is False
        assert engine.load_calls == 0
        assert engine.loaded_reply_policy is None


class TestRunRefreshLoop:
    """后台热更新循环：周期性 refresh、被取消时干净退出、单次失败不中断。"""

    async def _run_inline(self, func, *args):
        return func(*args)

    @pytest.mark.anyio
    async def test_loop_refreshes_each_interval_until_stopped(self):
        engine = _CapturingEngine()
        loader = _loader_with_handler(_ok_handler(), _config())
        calls = {"n": 0}

        class _Stop(Exception):
            pass

        async def fake_sleep(_seconds):
            calls["n"] += 1
            if calls["n"] >= 3:
                raise _Stop()

        with pytest.raises(_Stop):
            await run_refresh_loop(loader, engine, sleep=fake_sleep, run_sync=self._run_inline)

        # 两次都发起 refresh；同版本第二次通过离线校验后幂等跳过 live 替换。
        assert engine.load_calls == 1

    @pytest.mark.anyio
    async def test_loop_propagates_cancellation_without_swallowing(self):
        import asyncio

        engine = _CapturingEngine()
        loader = _loader_with_handler(_ok_handler(), _config())

        async def cancel_sleep(_seconds):
            raise asyncio.CancelledError()

        # CancelledError 必须向上传播，否则优雅关闭会卡死
        with pytest.raises(asyncio.CancelledError):
            await run_refresh_loop(loader, engine, sleep=cancel_sleep, run_sync=self._run_inline)
        assert engine.load_calls == 0

    @pytest.mark.anyio
    async def test_loop_continues_after_a_failed_refresh(self):
        engine = _CapturingEngine()

        def err_handler(request):
            return httpx.Response(500, json={"error": "boom"})

        loader = _loader_with_handler(err_handler, _config())
        calls = {"n": 0}

        class _Stop(Exception):
            pass

        async def fake_sleep(_seconds):
            calls["n"] += 1
            if calls["n"] >= 3:
                raise _Stop()

        # control-plane 持续 500：refresh_once 吞错返回 False，循环不应中断
        with pytest.raises(_Stop):
            await run_refresh_loop(loader, engine, sleep=fake_sleep, run_sync=self._run_inline)

        assert engine.load_calls == 0
        assert calls["n"] == 3
